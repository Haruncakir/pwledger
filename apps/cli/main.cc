/* Copyright (c) 2026 Harun
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <pwledger/Clipboard.h>
#include <pwledger/PrimaryTable.h>
#include <pwledger/ProcessHardening.h>
#include <pwledger/Secret.h>
#include <pwledger/TerminalManager.h>
#include <pwledger/VaultIO.h>
#include <pwledger/VaultPath.h>
#include <pwledger/uuid.h>

#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This file is the application entry point for pwledger, a CLI password
// manager. It owns the interactive command loop and all I/O that touches
// sensitive material.
//
// The data model (EntryMetadata, EntrySecurityPolicy, SecretEntry,
// PrimaryTable) lives in include/pwledger/ so it can be shared with the
// native messaging host (apps/native_host/main.cc).
//
// PERSISTENCE & ENCRYPTION
// ------------------------
// The PrimaryTable is persisted to disk using Argon2id for KDF and 
// XChaCha20-Poly1305 for AEAD. The file is saved atomically.
//
// THREAD SAFETY
// -------------
// The application is single-threaded. PrimaryTable and all Secret instances
// are accessed from the main thread only.
//
// ============================================================================

// Convenience alias used throughout this file.
using Uuid = pwledger::Uuid;

namespace pwledger {

// State passed to all commands.
struct AppState {
  pwledger::PrimaryTable table;
  pwledger::Secret master_password{1}; // placeholder until initialized
  std::filesystem::path vault_path;
};

// ============================================================================
// I/O helpers
// ============================================================================

// ----------------------------------------------------------------------------
// read_secret_from_stdin
// ----------------------------------------------------------------------------
// Reads a secret from stdin with echo disabled. TerminalManager_v suppresses
// echo and canonical mode for the duration of the read and restores terminal
// settings on return or exception (RAII, via TCSAFLUSH which discards any
// buffered keystrokes entered under echo suppression).
//
// The secret is read into `out`, which must have been allocated with at least
// `max_bytes` bytes. Excess input beyond max_bytes - 1 is silently truncated.
// A null terminator is written at buf[written] so the buffer can be passed to
// crypto functions that require a C-string.
//
// Returns the number of bytes written (excluding the null terminator).
std::size_t read_secret_from_stdin(Secret& out, std::size_t max_bytes) {
  if (max_bytes < 2) {
    throw std::invalid_argument("max_bytes must be at least 2");
  }

  TerminalManager_v terminal_guard;

  std::size_t written = 0;
  out.with_write_access([&](std::span<char> buf) {
    sodium_memzero(buf.data(), buf.size());
    // std::cin.get() returns int (to distinguish EOF from valid bytes).
    // The cast to char is intentionally ASCII-only: passwords are sequences
    // of printable ASCII characters for interoperability with the widest
    // set of services. A UTF-8 migration would require:
    //   - reading multi-byte sequences (std::codecvt or ICU)
    //   - NFC normalization (to ensure consistent byte representation)
    //   - updating Secret buffer sizing (multi-byte characters need more space)
    // Until then, the supported input range is [0x20, 0x7E] plus control keys.
    int ch = 0;
    while (written < max_bytes - 1) {
      ch = std::cin.get();
      if (ch == EOF || ch == '\n' || ch == '\r') {
        break;
      }
      buf[written++] = static_cast<char>(ch);
    }
    buf[written] = '\0';
  });

  std::cout << '\n';  // advance past the suppressed newline the user typed
  return written;
}

// ----------------------------------------------------------------------------
// prompt_secret
// ----------------------------------------------------------------------------
// Prints a prompt to stdout, reads a secret from stdin with echo suppressed,
// and optionally asks the user to confirm by entering it a second time.
// Returns the number of bytes written into `out`.
//
// On a confirmation mismatch, throws std::runtime_error. The caller is
// responsible for handling the error and re-prompting if desired.
//
// Comparison is performed with sodium_memcmp (constant-time) to avoid timing
// side-channels on the confirmation check.
std::size_t prompt_secret(std::string_view prompt, Secret& out, std::size_t max_bytes, bool confirm = false) {
  std::cout << prompt << ": ";
  std::cout.flush();
  std::size_t n = read_secret_from_stdin(out, max_bytes);

  if (!confirm) {
    return n;
  }

  Secret confirm_buf(max_bytes);
  std::cout << "Confirm " << prompt << ": ";
  std::cout.flush();
  std::size_t n2 = read_secret_from_stdin(confirm_buf, max_bytes);

  // The nested with_read_access calls below operate on two *different* Secret
  // objects (out and confirm_buf), so there is no overlapping-guard UB.
  // The ACCESS GUARD RULES in Secret.h prohibit overlapping guards on the
  // *same* Secret; distinct Secrets may be opened concurrently.
  bool match = false;
  out.with_read_access([&](std::span<const char> a) {
    confirm_buf.with_read_access(
        [&](std::span<const char> b) { match = (n == n2) && (sodium_memcmp(a.data(), b.data(), n) == 0); });
  });
  // confirm_buf is destroyed here; sodium_free zeroes its allocation.

  if (!match) {
    throw std::runtime_error("Entries do not match");
  }
  return n;
}

// ----------------------------------------------------------------------------
// save_vault_safe
// ----------------------------------------------------------------------------
// Attempts to save the vault. If it fails, prints the error but does not
// throw, so the command loop can continue.
void save_vault_safe(const AppState& state) {
  try {
    state.master_password.with_read_access([&](std::span<const char> buf) {
      std::size_t len = ::strnlen(buf.data(), buf.size());
      VaultIO::save_vault(state.vault_path, state.table, std::string_view(buf.data(), len));
    });
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to save vault: " << e.what() << '\n';
  }
}

// ----------------------------------------------------------------------------
// format_timepoint
// ----------------------------------------------------------------------------
// Formats a system_clock time_point as "YYYY-MM-DD HH:MM:SS UTC".
std::string format_timepoint(std::chrono::system_clock::time_point tp) {
  std::time_t t = std::chrono::system_clock::to_time_t(tp);
  std::tm tm = {};
#ifdef _WIN32
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S UTC");
  return oss.str();
}

// ============================================================================
// CRUD operations
// ============================================================================
//
// All operations take PrimaryTable by reference and operate on it in place.
// Return values follow a consistent pattern:
//   - create / update: bool (true on success, false on conflict or not-found)
//   - read:            const SecretEntry* (nullptr if not found)
//   - delete:          bool (true if removed, false if not found)
//
// Programmer misuse (empty UUID) throws std::invalid_argument.
// Expected runtime conditions (duplicate key, not found) return bool.

// ----------------------------------------------------------------------------
// entry_create
// ----------------------------------------------------------------------------
// Inserts a new entry and prompts interactively for the secret. The salt is
// generated randomly via libsodium and stored alongside the entry for future
// use by the KDF layer. Returns false if the UUID already exists.
//
// TODO(#issue-N): pass the salt to Argon2id and store the derived key, not
// the plaintext, once the encryption layer is in place.
bool entry_create(PrimaryTable& table, const Uuid& uuid, std::string primary_key, std::string username_or_email) {
  if (uuid.empty()) {
    throw std::invalid_argument("UUID must not be empty");
  }
  if (table.contains(uuid)) {
    return false;
  }

  // 256 bytes provides 255 usable characters (the last byte holds '\0').
  // This is sufficient for the vast majority of passwords and passphrases.
  // It is intentionally *not* sized for SSH private keys or TLS certificates;
  // those require a different storage model (file-backed, streaming) rather
  // than a single contiguous sodium_malloc buffer.
  constexpr std::size_t kMaxSecretBytes = 256;
  constexpr std::size_t kSaltBytes = crypto_pwhash_SALTBYTES;

  SecretEntry entry(std::move(primary_key), std::move(username_or_email), kMaxSecretBytes, kSaltBytes);

  entry.salt.with_write_access([](std::span<char> buf) { randombytes_buf(buf.data(), buf.size()); });

  prompt_secret("New secret for '" + entry.primary_key + "'",
                entry.plaintext_secret,
                kMaxSecretBytes,
                /*confirm=*/true);

  table.emplace(uuid, std::move(entry));
  return true;
}

// ----------------------------------------------------------------------------
// entry_read
// ----------------------------------------------------------------------------
// Returns a pointer to the entry for the given UUID, or nullptr if not found.
// The pointer is valid until the next modification of the table.
const SecretEntry* entry_read(const PrimaryTable& table, const Uuid& uuid) {
  if (uuid.empty()) {
    throw std::invalid_argument("UUID must not be empty");
  }
  auto it = table.find(uuid);
  return (it != table.end()) ? &it->second : nullptr;
}

// ----------------------------------------------------------------------------
// entry_update_secret
// ----------------------------------------------------------------------------
// Replaces the secret for an existing entry. zeroize() wipes the old bytes
// before the new secret is written into the same buffer. Returns false if
// the UUID does not exist.
bool entry_update_secret(PrimaryTable& table, const Uuid& uuid) {
  if (uuid.empty()) {
    throw std::invalid_argument("UUID must not be empty");
  }
  auto it = table.find(uuid);
  if (it == table.end()) {
    return false;
  }

  SecretEntry& entry = it->second;
  entry.plaintext_secret.zeroize();

  prompt_secret("New secret for '" + entry.primary_key + "'",
                entry.plaintext_secret,
                entry.plaintext_secret.size(),
                /*confirm=*/true);

  entry.metadata.last_modified_at = std::chrono::system_clock::now();
  return true;
}

// ----------------------------------------------------------------------------
// entry_delete
// ----------------------------------------------------------------------------
// Removes the entry for the given UUID. Secret and salt are zeroed and freed
// by SecretEntry's destructor (via Secret::~Secret -> sodium_free).
// Returns false if the UUID does not exist.
bool entry_delete(PrimaryTable& table, const Uuid& uuid) {
  if (uuid.empty()) {
    throw std::invalid_argument("UUID must not be empty");
  }
  return table.erase(uuid) > 0;
}

// ============================================================================
// Metadata helpers
// ============================================================================

// ----------------------------------------------------------------------------
// touch_last_used
// ----------------------------------------------------------------------------
// Updates the last_used_at timestamp for the entry with the given UUID.
// Returns false if the UUID does not exist. This centralizes the "touch"
// pattern used by cmd_get and cmd_copy so the mutation is not duplicated
// across command handlers.
bool touch_last_used(PrimaryTable& table, const Uuid& uuid) {
  auto it = table.find(uuid);
  if (it == table.end()) {
    return false;
  }
  it->second.metadata.last_used_at = std::chrono::system_clock::now();
  return true;
}

// ============================================================================
// Display helpers
// ============================================================================

// ----------------------------------------------------------------------------
// print_entry
// ----------------------------------------------------------------------------
// Prints a human-readable summary of an entry. The secret value is never
// printed; only its byte length is shown so the user can verify it is
// non-empty without exposing the content.
void print_entry(const Uuid& uuid, const SecretEntry& entry) {
  std::size_t secret_len = 0;
  entry.plaintext_secret.with_read_access(
      [&](std::span<const char> buf) { secret_len = ::strnlen(buf.data(), buf.size()); });

  std::cout << "UUID            : " << uuid << '\n'
            << "Primary key     : " << entry.primary_key << '\n'
            << "Username/email  : " << entry.username_or_email << '\n'
            << "Secret length   : " << secret_len << " characters" << '\n'
            << "2FA enabled     : " << (entry.security_policy.two_fa_enabled ? "yes" : "no") << '\n'
            << "Strength score  : " << entry.security_policy.strength_score << '\n'
            << "Expires         : "
            << (entry.security_policy.expires_at.has_value() ? format_timepoint(*entry.security_policy.expires_at)
                                                             : "never")
            << '\n'
            << "Created         : " << format_timepoint(entry.metadata.created_at) << '\n'
            << "Last modified   : " << format_timepoint(entry.metadata.last_modified_at) << '\n'
            << "Last used       : " << format_timepoint(entry.metadata.last_used_at) << '\n';

  if (!entry.security_policy.note.empty()) {
    std::cout << "Note            : " << entry.security_policy.note << '\n';
  }
}

// ----------------------------------------------------------------------------
// print_table
// ----------------------------------------------------------------------------
// Lists all entries. Only non-sensitive fields are shown.
void print_table(const PrimaryTable& table) {
  if (table.empty()) {
    std::cout << "(no entries)\n";
    return;
  }
  for (const auto& [uuid, entry] : table) {
    std::cout << "----\n";
    print_entry(uuid, entry);
  }
  std::cout << "----\n";
}

// ============================================================================
// Command loop
// ============================================================================
//
// Each command is a free function that reads its arguments from stdin
// interactively and delegates to the appropriate CRUD or clipboard function.
// All command functions share the signature  void (*)(PrimaryTable&)  so they
// can be stored uniformly in the dispatch table.
//
// Exceptions thrown by CRUD operations are caught in run_command_loop and
// reported to the user without terminating the session.

// ----------------------------------------------------------------------------
// parse_uuid_input
// ----------------------------------------------------------------------------
// Reads a UUID string from stdin and parses it into a Uuid. Returns
// std::nullopt and prints an error if the input is not a valid UUID.
std::optional<Uuid> parse_uuid_input() {
  std::string input;
  std::cout << "UUID: ";
  std::getline(std::cin, input);

  auto uuid = Uuid::from_string(input);
  if (!uuid) {
    std::cout << "Error: '" << input << "' is not a valid UUID.\n";
  }
  return uuid;
}

void cmd_add(AppState& state) {
  std::string key, user;
  std::cout << "Primary key   : ";
  std::getline(std::cin, key);
  std::cout << "Username/email: ";
  std::getline(std::cin, user);

  // Auto-generate a UUID-v4 for the new entry.
  Uuid uuid = Uuid::generate();

  if (entry_create(state.table, uuid, std::move(key), std::move(user))) {
    std::cout << "Entry added (UUID: " << uuid << ").\n";
    save_vault_safe(state);
  } else {
    std::cout << "Error: UUID collision (astronomically unlikely).\n";
  }
}

void cmd_get(AppState& state) {
  auto uuid = parse_uuid_input();
  if (!uuid) {
    return;
  }

  const SecretEntry* entry = entry_read(state.table, *uuid);
  if (!entry) {
    std::cout << "Error: no entry found for UUID '" << *uuid << "'.\n";
    return;
  }
  if (touch_last_used(state.table, *uuid)) {
    save_vault_safe(state);
  }
  print_entry(*uuid, *entry);
}

void cmd_update(AppState& state) {
  auto uuid = parse_uuid_input();
  if (!uuid) {
    return;
  }

  if (entry_update_secret(state.table, *uuid)) {
    std::cout << "Secret updated.\n";
    save_vault_safe(state);
  } else {
    std::cout << "Error: no entry found for UUID '" << *uuid << "'.\n";
  }
}

void cmd_delete(AppState& state) {
  auto uuid = parse_uuid_input();
  if (!uuid) {
    return;
  }

  std::cout << "Delete entry '" << *uuid << "'? [y/N]: ";
  std::string confirm;
  std::getline(std::cin, confirm);
  if (confirm != "y" && confirm != "Y") {
    std::cout << "Cancelled.\n";
    return;
  }

  if (entry_delete(state.table, *uuid)) {
    std::cout << "Entry deleted.\n";
    save_vault_safe(state);
  } else {
    std::cout << "Error: no entry found for UUID '" << *uuid << "'.\n";
  }
}

void cmd_list(AppState& state) {
  print_table(state.table);
}

void cmd_copy(AppState& state) {
  auto uuid = parse_uuid_input();
  if (!uuid) {
    return;
  }

  const SecretEntry* entry = entry_read(state.table, *uuid);
  if (!entry) {
    std::cout << "Error: no entry found for UUID '" << *uuid << "'.\n";
    return;
  }
  if (touch_last_used(state.table, *uuid)) {
    save_vault_safe(state);
  }
  clipboard_copy_secret(*entry);
}

void cmd_clip_clear(AppState& /*state*/) {
  clipboard_clear_secret();
}

void cmd_save(AppState& state) {
  save_vault_safe(state);
  std::cout << "Vault saved to " << state.vault_path << ".\n";
}

void cmd_change_master(AppState& state) {
  Secret new_password(256);
  prompt_secret("Enter new master password", new_password, 256, /*confirm=*/true);
  state.master_password = std::move(new_password);
  save_vault_safe(state);
  std::cout << "Master password changed and vault re-encrypted.\n";
}

void cmd_help(AppState& /*state*/) {
  std::cout << "Commands:\n"
            << "  add            Add a new entry\n"
            << "  get            Show an entry\n"
            << "  update         Update the secret for an entry\n"
            << "  delete         Delete an entry\n"
            << "  list           List all entries\n"
            << "  copy           Copy an entry's secret to the clipboard\n"
            << "  clip-clear     Clear the clipboard\n"
            << "  save           Force save the vault to disk\n"
            << "  change-master  Change the vault master password\n"
            << "  help           Show this message\n"
            << "  quit           Exit\n";
}

// ----------------------------------------------------------------------------
// run_command_loop
// ----------------------------------------------------------------------------
// Reads command names from stdin and dispatches to the appropriate handler
// until the user types "quit" or stdin is exhausted (EOF). Exceptions from
// command handlers are caught and reported without terminating the session.
// Commands taking AppState can mutate the table and auto-save.
void run_command_loop(AppState& state) {
  using CommandFn = void (*)(AppState&);

  const std::unordered_map<std::string, CommandFn> dispatch{
      {"add", cmd_add},
      {"get", cmd_get},
      {"update", cmd_update},
      {"delete", cmd_delete},
      {"list", cmd_list},
      {"copy", cmd_copy},
      {"clip-clear", cmd_clip_clear},
      {"save", cmd_save},
      {"change-master", cmd_change_master},
      {"help", cmd_help},
  };

  std::cout << "pwledger — type 'help' for available commands.\n";

  std::string line;
  for (;;) {
    std::cout << "\npwledger> ";
    std::cout.flush();

    if (!std::getline(std::cin, line)) {
      break;  // EOF (Ctrl-D / Ctrl-Z)
    }

    // Trim leading and trailing whitespace.
    const auto first = line.find_first_not_of(" \t\r\n");
    const auto last = line.find_last_not_of(" \t\r\n");
    if (first == std::string::npos) {
      continue;
    }
    const std::string cmd = line.substr(first, last - first + 1);

    if (cmd == "quit" || cmd == "exit") {
      break;
    }

    const auto it = dispatch.find(cmd);
    if (it == dispatch.end()) {
      std::cout << "Unknown command '" << cmd << "'. Type 'help'.\n";
      continue;
    }

    try {
      it->second(state);
    } catch (const std::exception& e) {
      std::cout << "Error: " << e.what() << '\n';
    }
  }

  std::cout << "\nGoodbye.\n";
}

}  // namespace pwledger

// ============================================================================
// Entry point
// ============================================================================

int main() {
  // Process hardening must happen before any Secret is constructed.
  // See harden_process() and "KNOWN LIMITATIONS" in Secret.h.
  pwledger::harden_process();

  // sodium_init must be called once before any Secret is constructed.
  // Returns 0 on success, 1 if already initialized, -1 on failure.
  if (sodium_init() < 0) {
    std::cerr << "Fatal: libsodium initialization failed.\n";
    return 1;
  }

  pwledger::AppState state;
  try {
    pwledger::ensure_vault_dir_exists();
    state.vault_path = pwledger::default_vault_path();
  } catch (const std::exception& e) {
    std::cerr << "Fatal: Failed to create vault directory: " << e.what() << '\n';
    return 1;
  }

  if (pwledger::VaultIO::vault_exists(state.vault_path)) {
    std::cout << "Found existing vault at " << state.vault_path << "\n";
    bool loaded = false;
    // Allow up to 3 attempts
    for (int attempts = 0; attempts < 3; ++attempts) {
      pwledger::Secret pwd(256);
      pwledger::prompt_secret("Master password", pwd, 256);
      try {
        pwd.with_read_access([&](std::span<const char> buf) {
          std::size_t len = ::strnlen(buf.data(), buf.size());
          pwledger::PrimaryTable t = pwledger::VaultIO::load_vault(state.vault_path, std::string_view(buf.data(), len));
          state.table = std::move(t);
        });
        state.master_password = std::move(pwd);
        loaded = true;
        std::cout << "Vault loaded successfully (" << state.table.size() << " entries).\n";
        break;
      } catch (const std::exception& e) {
        std::cout << "Failed to decrypt vault: " << e.what() << "\n";
      }
    }
    if (!loaded) {
      std::cerr << "Fatal: Too many failed decryption attempts.\n";
      return 1;
    }
  } else {
    std::cout << "No existing vault found at " << state.vault_path << ".\n";
    std::cout << "Creating a new vault.\n";
    pwledger::Secret pwd(256);
    pwledger::prompt_secret("Set master password", pwd, 256, /*confirm=*/true);
    state.master_password = std::move(pwd);
    pwledger::save_vault_safe(state);
    std::cout << "Vault created.\n";
  }

  pwledger::run_command_loop(state);

  // Final save on graceful exit
  pwledger::save_vault_safe(state);
  // Secret::~Secret, which calls sodium_free, zeroing and releasing every
  // sodium-hardened allocation before the process exits.
  return 0;
}
