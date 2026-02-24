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

#include <pwledger/Secret.h>
#include <pwledger/TerminalManager.h>

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

#ifdef __linux__
#  include <sys/prctl.h>
#  include <sys/resource.h>
#endif

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This file is the application entry point for pwledger, a CLI password
// manager. It owns the top-level data model, the interactive command loop,
// and all I/O that touches sensitive material.
//
// PERSISTENCE
// -----------
// The PrimaryTable is currently in-memory only. Persistence (encrypted
// serialization to disk) is deferred.
// TODO(#issue-N): implement encrypted persistence layer (e.g., serialize
// PrimaryTable to a file encrypted with a master key derived from the
// master password via Argon2id).
//
// CLIPBOARD
// ---------
// Clipboard write is implemented as a best-effort clear-after-use strategy.
// The secret is written to the clipboard and the user is prompted to run
// 'clip-clear' when done.
// TODO(#issue-N): enforce a configurable auto-clear timeout via a background
// thread or platform-specific timer once the threading model is established.
//
// MASTER PASSWORD & ENCRYPTION
// -----------------------------
// The current implementation stores secrets in plaintext sodium-hardened
// memory for the duration of the session. Encryption at rest (master password
// → Argon2id KDF → XChaCha20-Poly1305) is deferred pending the persistence
// layer. The field is named `plaintext_secret` in SecretEntry to make the
// unencrypted state explicit at every read site.
// TODO(#issue-N): integrate encryption before any persistence is added.
//
// THREAD SAFETY
// -------------
// The application is single-threaded. PrimaryTable and all Secret instances
// are accessed from the main thread only.
//
// ============================================================================

// ----------------------------------------------------------------------------
// Uuid
// ----------------------------------------------------------------------------
// TODO(#issue-N): replace with a proper fixed-width UUID type (e.g., a
// 16-byte array wrapper with formatted output) once the identity layer is
// defined. A heap-allocated string is used as a placeholder; UUIDs must not
// be heap-allocated strings in the hot path of an unordered_map lookup in
// the final implementation.
using Uuid = std::string;

namespace pwledger {

// ============================================================================
// Data model
// ============================================================================

// ----------------------------------------------------------------------------
// EntryMetadata
// ----------------------------------------------------------------------------
// Lifecycle timestamps for a stored credential. All fields use system_clock
// so that timestamps are comparable and serializable to wall-clock time.
struct EntryMetadata {
  std::chrono::system_clock::time_point created_at;
  std::chrono::system_clock::time_point last_modified_at;
  std::chrono::system_clock::time_point last_used_at;
};

// ----------------------------------------------------------------------------
// EntrySecurityPolicy
// ----------------------------------------------------------------------------
// Security attributes and policy constraints for a stored credential.
//
// strength_score:  Estimated bit-strength of the plaintext secret (e.g.,
//                  from zxcvbn or a similar estimator). 0 means not yet
//                  evaluated. Consider a newtype wrapper if invariants
//                  (non-negative, bounded range) need enforcement.
// reuse_count:     Number of other entries sharing an identical secret.
//                  Populated by a background audit pass; used to surface
//                  reuse warnings in the UI.
// two_fa_enabled:  Whether a second factor is associated with this entry.
// expires_at:      Optional expiry deadline. nullopt means no expiry policy.
// note:            Free-form user annotation. Stored in plaintext; treat as
//                  non-sensitive. If notes may contain sensitive content,
//                  migrate this field to a Secret.
struct EntrySecurityPolicy {
  int                                                  strength_score = 0;
  int                                                  reuse_count    = 0;
  bool                                                 two_fa_enabled = false;
  std::optional<std::chrono::system_clock::time_point> expires_at;
  std::string                                          note;
};

// ----------------------------------------------------------------------------
// SecretEntry
// ----------------------------------------------------------------------------
// A single stored credential. The plaintext secret and its derivation salt
// are held in sodium-hardened memory via Secret, which zeroes and frees them
// on destruction. All other fields are non-sensitive metadata and may live
// in ordinary heap memory.
//
// SecretEntry is move-only because Secret is move-only. The destructor is
// compiler-generated: Secret::~Secret() already calls sodium_free, which
// zeroes and releases the hardened allocation.
struct SecretEntry {
  std::string         primary_key;
  std::string         username_or_email;
  Secret              plaintext_secret;
  Secret              salt;
  EntryMetadata       metadata;
  EntrySecurityPolicy security_policy;

  // Explicit constructor required because Secret has no default constructor.
  // secret_size and salt_size are the byte lengths of the respective buffers.
  SecretEntry(std::string  pk,
              std::string  user,
              std::size_t  secret_size,
              std::size_t  salt_size)
    : primary_key(std::move(pk)),
      username_or_email(std::move(user)),
      plaintext_secret(secret_size),
      salt(salt_size),
      metadata{
        std::chrono::system_clock::now(),
        std::chrono::system_clock::now(),
        std::chrono::system_clock::now()
      }
  {}

  ~SecretEntry()                             = default;
  SecretEntry(SecretEntry&&)                 = default;
  SecretEntry& operator=(SecretEntry&&)      = default;
  SecretEntry(const SecretEntry&)            = delete;
  SecretEntry& operator=(const SecretEntry&) = delete;
};

// ----------------------------------------------------------------------------
// PrimaryTable
// ----------------------------------------------------------------------------
// The top-level credential store: a map from UUID to SecretEntry.
// unordered_map provides O(1) average lookup by UUID. If ordered iteration
// or range queries are needed, std::map<Uuid, SecretEntry> is the alternative.
//
// SecretEntry is move-only; insertions use std::move or emplace.
using PrimaryTable = std::unordered_map<Uuid, SecretEntry>;

// ============================================================================
// Platform utilities
// ============================================================================

// ----------------------------------------------------------------------------
// harden_process
// ----------------------------------------------------------------------------
// Best-effort process hardening applied once at startup, before any Secret
// is constructed. These mitigations reduce the risk of sensitive data leaking
// through core dumps or debugger attachment. They are not a substitute for
// OS-level hardening (seccomp, AppArmor, SELinux) but serve as a first layer
// for a CLI application.
//
// None of these calls are fatal on failure; a system that disallows them
// (e.g., a container with limited capabilities) should still run normally.
void harden_process() noexcept {
#ifdef __linux__
  // Prevent core dumps from capturing in-memory secrets.
  // Must be called before any Secret is constructed (see Secret.h).
  prctl(PR_SET_DUMPABLE, 0);

  // Belt-and-suspenders: also set the core dump size limit to zero via
  // setrlimit, which applies even if prctl is overridden by a child process.
  const struct rlimit no_core{0, 0};
  setrlimit(RLIMIT_CORE, &no_core);
#endif
  // TODO(#issue-N): add macOS Hardened Runtime check and Windows
  // IsDebuggerPresent mitigation once those platforms are targeted.
}

// ============================================================================
// Clipboard management
// ============================================================================

// Best-effort clipboard write and clear. Failures are logged to stderr but
// are not fatal: the user can always read the secret from terminal output.
// Clipboard operations are inherently insecure (other processes can read the
// clipboard); this is a usability concession.
//
// TODO(#issue-N): enforce auto-clear after a configurable timeout.

namespace detail {

void clipboard_write(std::string_view text) {
#if defined(__linux__)
  // Use xclip if available, fall back to xsel. Both read from stdin.
  FILE* pipe = popen("xclip -selection clipboard 2>/dev/null || "
                     "xsel --clipboard --input 2>/dev/null", "w");
  if (!pipe) {
    std::cerr << "Warning: clipboard write failed "
                 "(xclip or xsel not found)\n";
    return;
  }
  fwrite(text.data(), 1, text.size(), pipe);
  pclose(pipe);
#elif defined(__APPLE__)
  FILE* pipe = popen("pbcopy", "w");
  if (!pipe) {
    std::cerr << "Warning: clipboard write failed (pbcopy unavailable)\n";
    return;
  }
  fwrite(text.data(), 1, text.size(), pipe);
  pclose(pipe);
#elif defined(_WIN32)
  if (!OpenClipboard(nullptr)) {
    std::cerr << "Warning: clipboard write failed (OpenClipboard)\n";
    return;
  }
  EmptyClipboard();
  // Allocate global memory for the text (+1 for null terminator).
  HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
  if (!hMem) {
    CloseClipboard();
    std::cerr << "Warning: clipboard write failed (GlobalAlloc)\n";
    return;
  }
  char* dst = static_cast<char*>(GlobalLock(hMem));
  std::memcpy(dst, text.data(), text.size());
  dst[text.size()] = '\0';
  GlobalUnlock(hMem);
  SetClipboardData(CF_TEXT, hMem);
  CloseClipboard();
#else
  (void)text;
  std::cerr << "Warning: clipboard write not supported on this platform\n";
#endif
}

void clipboard_clear() {
#if defined(__linux__)
  FILE* pipe = popen("xclip -selection clipboard 2>/dev/null || "
                     "xsel --clipboard --input 2>/dev/null", "w");
  if (pipe) {
    fwrite("", 1, 0, pipe);
    pclose(pipe);
  }
#elif defined(__APPLE__)
  FILE* pipe = popen("pbcopy", "w");
  if (pipe) {
    fwrite("", 1, 0, pipe);
    pclose(pipe);
  }
#elif defined(_WIN32)
  if (OpenClipboard(nullptr)) {
    EmptyClipboard();
    CloseClipboard();
  }
#endif
}

}  // namespace detail

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
    int ch = 0;
    while (written < max_bytes - 1) {
      ch = std::cin.get();
      if (ch == EOF || ch == '\n' || ch == '\r') { break; }
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
std::size_t prompt_secret(std::string_view prompt,
                          Secret&          out,
                          std::size_t      max_bytes,
                          bool             confirm = false) {
  std::cout << prompt << ": ";
  std::cout.flush();
  std::size_t n = read_secret_from_stdin(out, max_bytes);

  if (!confirm) { return n; }

  Secret confirm_buf(max_bytes);
  std::cout << "Confirm " << prompt << ": ";
  std::cout.flush();
  std::size_t n2 = read_secret_from_stdin(confirm_buf, max_bytes);

  bool match = false;
  out.with_read_access([&](std::span<const char> a) {
    confirm_buf.with_read_access([&](std::span<const char> b) {
      match = (n == n2) &&
              (sodium_memcmp(a.data(), b.data(), n) == 0);
    });
  });
  // confirm_buf is destroyed here; sodium_free zeroes its allocation.

  if (!match) {
    throw std::runtime_error("Entries do not match");
  }
  return n;
}

// ----------------------------------------------------------------------------
// format_timepoint
// ----------------------------------------------------------------------------
// Formats a system_clock time_point as "YYYY-MM-DD HH:MM:SS UTC".
std::string format_timepoint(std::chrono::system_clock::time_point tp) {
  std::time_t t  = std::chrono::system_clock::to_time_t(tp);
  std::tm     tm = {};
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
bool entry_create(PrimaryTable& table,
                  const Uuid&   uuid,
                  std::string   primary_key,
                  std::string   username_or_email) {
  if (uuid.empty()) {
    throw std::invalid_argument("UUID must not be empty");
  }
  if (table.contains(uuid)) {
    return false;
  }

  // 256 bytes provides 255 usable characters (the last byte holds '\0').
  constexpr std::size_t kMaxSecretBytes = 256;
  constexpr std::size_t kSaltBytes      = crypto_pwhash_SALTBYTES;

  SecretEntry entry(std::move(primary_key),
                    std::move(username_or_email),
                    kMaxSecretBytes,
                    kSaltBytes);

  entry.salt.with_write_access([](std::span<char> buf) {
    randombytes_buf(buf.data(), buf.size());
  });

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
  if (it == table.end()) { return false; }

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
// Clipboard operations
// ============================================================================

// ----------------------------------------------------------------------------
// clipboard_copy_secret
// ----------------------------------------------------------------------------
// Copies the entry's secret to the clipboard via a scoped read guard.
// The actual secret length is determined from the null terminator written
// by read_secret_from_stdin rather than from the full buffer allocation.
void clipboard_copy_secret(const SecretEntry& entry) {
  entry.plaintext_secret.with_read_access([](std::span<const char> buf) {
    std::size_t len = ::strnlen(buf.data(), buf.size());
    detail::clipboard_write(std::string_view(buf.data(), len));
  });
  std::cout << "Secret copied to clipboard. "
               "Run 'clip-clear' when done.\n";
}

// ----------------------------------------------------------------------------
// clipboard_clear_secret
// ----------------------------------------------------------------------------
// Overwrites the clipboard with an empty string.
void clipboard_clear_secret() {
  detail::clipboard_clear();
  std::cout << "Clipboard cleared.\n";
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
  entry.plaintext_secret.with_read_access([&](std::span<const char> buf) {
    secret_len = ::strnlen(buf.data(), buf.size());
  });

  std::cout
    << "UUID            : " << uuid                                            << '\n'
    << "Primary key     : " << entry.primary_key                               << '\n'
    << "Username/email  : " << entry.username_or_email                         << '\n'
    << "Secret length   : " << secret_len << " characters"                     << '\n'
    << "2FA enabled     : " << (entry.security_policy.two_fa_enabled
                                 ? "yes" : "no")                               << '\n'
    << "Strength score  : " << entry.security_policy.strength_score            << '\n'
    << "Expires         : " << (entry.security_policy.expires_at.has_value()
                                 ? format_timepoint(*entry.security_policy.expires_at)
                                 : "never")                                    << '\n'
    << "Created         : " << format_timepoint(entry.metadata.created_at)     << '\n'
    << "Last modified   : " << format_timepoint(entry.metadata.last_modified_at) << '\n'
    << "Last used       : " << format_timepoint(entry.metadata.last_used_at)   << '\n';

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

void cmd_add(PrimaryTable& table) {
  std::string uuid, key, user;
  std::cout << "UUID          : "; std::getline(std::cin, uuid);
  std::cout << "Primary key   : "; std::getline(std::cin, key);
  std::cout << "Username/email: "; std::getline(std::cin, user);

  if (entry_create(table, uuid, std::move(key), std::move(user))) {
    std::cout << "Entry added.\n";
  } else {
    std::cout << "Error: an entry with that UUID already exists.\n";
  }
}

void cmd_get(PrimaryTable& table) {
  std::string uuid;
  std::cout << "UUID: "; std::getline(std::cin, uuid);

  const SecretEntry* entry = entry_read(table, uuid);
  if (!entry) {
    std::cout << "Error: no entry found for UUID '" << uuid << "'.\n";
    return;
  }
  table.at(uuid).metadata.last_used_at = std::chrono::system_clock::now();
  print_entry(uuid, *entry);
}

void cmd_update(PrimaryTable& table) {
  std::string uuid;
  std::cout << "UUID: "; std::getline(std::cin, uuid);

  if (entry_update_secret(table, uuid)) {
    std::cout << "Secret updated.\n";
  } else {
    std::cout << "Error: no entry found for UUID '" << uuid << "'.\n";
  }
}

void cmd_delete(PrimaryTable& table) {
  std::string uuid;
  std::cout << "UUID: "; std::getline(std::cin, uuid);

  std::cout << "Delete entry '" << uuid << "'? [y/N]: ";
  std::string confirm;
  std::getline(std::cin, confirm);
  if (confirm != "y" && confirm != "Y") {
    std::cout << "Cancelled.\n";
    return;
  }

  if (entry_delete(table, uuid)) {
    std::cout << "Entry deleted.\n";
  } else {
    std::cout << "Error: no entry found for UUID '" << uuid << "'.\n";
  }
}

void cmd_list(PrimaryTable& table) {
  print_table(table);
}

void cmd_copy(PrimaryTable& table) {
  std::string uuid;
  std::cout << "UUID: "; std::getline(std::cin, uuid);

  const SecretEntry* entry = entry_read(table, uuid);
  if (!entry) {
    std::cout << "Error: no entry found for UUID '" << uuid << "'.\n";
    return;
  }
  table.at(uuid).metadata.last_used_at = std::chrono::system_clock::now();
  clipboard_copy_secret(*entry);
}

void cmd_clip_clear(PrimaryTable& /*table*/) {
  clipboard_clear_secret();
}

void cmd_help(PrimaryTable& /*table*/) {
  std::cout
    << "Commands:\n"
    << "  add        Add a new entry\n"
    << "  get        Show an entry\n"
    << "  update     Update the secret for an entry\n"
    << "  delete     Delete an entry\n"
    << "  list       List all entries\n"
    << "  copy       Copy an entry's secret to the clipboard\n"
    << "  clip-clear Clear the clipboard\n"
    << "  help       Show this message\n"
    << "  quit       Exit\n";
}

// ----------------------------------------------------------------------------
// run_command_loop
// ----------------------------------------------------------------------------
// Reads command names from stdin and dispatches to the appropriate handler
// until the user types "quit" or stdin is exhausted (EOF). Exceptions from
// command handlers are caught and reported without terminating the session.
void run_command_loop(PrimaryTable& table) {
  using CommandFn = void (*)(PrimaryTable&);

  const std::unordered_map<std::string, CommandFn> dispatch{
    { "add",        cmd_add        },
    { "get",        cmd_get        },
    { "update",     cmd_update     },
    { "delete",     cmd_delete     },
    { "list",       cmd_list       },
    { "copy",       cmd_copy       },
    { "clip-clear", cmd_clip_clear },
    { "help",       cmd_help       },
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
    const auto last  = line.find_last_not_of(" \t\r\n");
    if (first == std::string::npos) { continue; }
    const std::string cmd = line.substr(first, last - first + 1);

    if (cmd == "quit" || cmd == "exit") { break; }

    const auto it = dispatch.find(cmd);
    if (it == dispatch.end()) {
      std::cout << "Unknown command '" << cmd << "'. Type 'help'.\n";
      continue;
    }

    try {
      it->second(table);
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

  // TODO(#issue-N): prompt for the master password here, derive a session key
  // via Argon2id, and use it to decrypt the persisted PrimaryTable from disk.
  // For now the table is empty and in-memory only.
  pwledger::PrimaryTable table;

  pwledger::run_command_loop(table);

  // table goes out of scope here. Each SecretEntry destructor calls
  // Secret::~Secret, which calls sodium_free, zeroing and releasing every
  // sodium-hardened allocation before the process exits.
  return 0;
}
