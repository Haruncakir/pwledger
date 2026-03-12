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

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This is the Native Messaging host for pwledger. It communicates with a
// browser extension via the Chrome/Firefox Native Messaging protocol:
// each message is prefixed with a 4-byte little-endian uint32 length,
// followed by a UTF-8 JSON payload.
//
// SECURITY MODEL
// --------------
// The host process is spawned by the browser with the same user privileges as
// the browser itself. Trust boundary assumptions:
//   - Messages arrive from the browser extension over stdin/stdout.
//   - The extension is assumed to be the legitimate pwledger extension.
//     There is no additional authentication of the caller beyond OS-level
//     process ownership. A compromised browser or a malicious extension
//     with the same extension ID can send arbitrary messages.
//   - The master password is transmitted in plaintext over the JSON message.
//     This is unavoidable given the Native Messaging protocol design; the
//     exposure window is minimized by zeroing the std::string immediately
//     after use (see "PASSWORD HANDLING" below).
//   - Clipboard operations expose the secret to other processes running in
//     the same user session. This is a usability concession documented in
//     Clipboard.h.
//
// PASSWORD HANDLING
// -----------------
// The master password arrives as a JSON string field and is extracted into
// a std::string. std::string cannot provide the same guarantees as Secret
// (no zeroing on destruction, potential SSO, implicit copies). To minimize
// exposure:
//   1. The password is extracted from the JSON object as late as possible.
//   2. It is passed immediately to VaultIO::load_vault by string_view.
//   3. sodium_memzero is called on the string's data() buffer before it
//      goes out of scope.
//   4. The JSON object holding the original copy is discarded immediately
//      after extraction.
// This does not eliminate the risk (the JSON parser may have made internal
// copies) but reduces the exposure window to the minimum achievable without
// a custom JSON parser.
// TODO(#issue-N): evaluate whether VaultIO::load_vault can accept the
// password via a Secret& to eliminate the std::string intermediary entirely.
//
// VAULT STATE
// -----------
// The host maintains a VaultState enum (Locked / Unlocked) and a
// PrimaryTable. Commands that require an unlocked vault are rejected with
// a "locked" error response before touching any table state. The dispatch
// table carries an explicit requires_unlock flag per command so that new
// commands cannot be added without consciously choosing their auth posture.
//
// MESSAGE SIZE LIMIT
// ------------------
// Incoming messages are capped at kMaxMessageBytes. A message exceeding this
// limit is rejected with an error response; the connection is not terminated
// so the extension can recover gracefully.
//
// AUTO-LOCK
// ---------
// TODO(#issue-N): implement idle auto-lock after a configurable timeout.
// The vault should lock automatically if no command is received within N
// minutes. This requires either a background thread or non-blocking I/O
// with a select/poll timeout.
//
// SEARCH
// ------
// The search command performs a case-insensitive substring match on
// primary_key and username_or_email. Results are returned in unspecified
// order (unordered_map iteration order). Ranking by match quality is
// deferred.
// TODO(#issue-N): add ranked fuzzy search once the query volume justifies it.
//
// ============================================================================

// On Windows, stdin/stdout must be switched to binary mode before any I/O.
// This must happen before including headers that open std::cin/std::cout,
// and before any read or write. The pragma/include order here is intentional.
#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#endif

#include <pwledger/Clipboard.h>
#include <pwledger/Config.h>
#include <pwledger/PrimaryTable.h>
#include <pwledger/ProcessHardening.h>
#include <pwledger/Secret.h>
#include <pwledger/VaultIO.h>
#include <pwledger/VaultPath.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include <nlohmann/json.hpp>
#include <sodium.h>

using json = nlohmann::json;

namespace pwledger {

// ============================================================================
// Constants
// ============================================================================

// Maximum permitted size of a single incoming Native Messaging message.
// The Native Messaging protocol used by Chrome and Firefox caps messages
// at 1 MB. We enforce the same limit to reject malformed or malicious
// oversized length prefixes (e.g., 0xFFFFFFFF would otherwise trigger a
// 4 GB std::string allocation).
constexpr uint32_t kMaxMessageBytes = 1024u * 1024u;  // 1 MiB

// ============================================================================
// Vault state
// ============================================================================

// VaultState is the authoritative lock status for the session. All command
// handlers that touch table state check this before proceeding. Using an
// enum class rather than a raw bool makes the intent explicit in code review
// and prevents accidental comparison with integers.
enum class VaultState {
  Locked,
  Unlocked,
};

// ============================================================================
// Native Messaging I/O
// ============================================================================

// ----------------------------------------------------------------------------
// read_message
// ----------------------------------------------------------------------------
// Reads one Native Messaging frame from stdin. The frame format is:
//   [uint32_t length (little-endian)] [length bytes of UTF-8 JSON]
//
// Returns the JSON payload as a string, or nullopt on EOF, I/O error, or
// if the declared length exceeds kMaxMessageBytes.
//
// The length field is read as raw bytes and reinterpreted as uint32_t.
// On all supported platforms (x86, x86-64, ARM) the native byte order is
// little-endian, which matches the Native Messaging specification. A
// static_assert below guards this assumption.
static_assert(
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
    "Native Messaging length prefix assumes little-endian byte order. "
    "Add a byte-swap here for big-endian platforms.");

[[nodiscard]] std::optional<std::string> read_message() {
  uint32_t length = 0;
  if (!std::cin.read(reinterpret_cast<char*>(&length), sizeof(length))) {
    return std::nullopt;  // EOF or I/O error; caller terminates the loop
  }

  if (length == 0) {
    return std::string{};  // zero-length message is valid (e.g., a ping)
  }

  if (length > kMaxMessageBytes) {
    // Reject without reading the body; the stream is now out of sync.
    // Return nullopt to signal a fatal framing error and terminate.
    std::cerr << "Fatal: incoming message length " << length
              << " exceeds limit " << kMaxMessageBytes << "; terminating\n";
    return std::nullopt;
  }

  std::string payload(length, '\0');
  if (!std::cin.read(payload.data(), length)) {
    return std::nullopt;
  }
  return payload;
}

// ----------------------------------------------------------------------------
// write_message
// ----------------------------------------------------------------------------
// Writes one Native Messaging frame to stdout.
// stdout must be in binary mode (see _setmode call in main).
void write_message(const json& msg) noexcept {
  try {
    const std::string payload = msg.dump();

    if (payload.size() > kMaxMessageBytes) {
      // Response too large to send under the protocol limit. This should not
      // happen in normal operation; log and send a truncation error instead.
      std::cerr << "Warning: outgoing message too large ("
                << payload.size() << " bytes); sending error response\n";
      write_message({{"status", "error"}, {"message", "Response too large"}});
      return;
    }

    const uint32_t length = static_cast<uint32_t>(payload.size());
    std::cout.write(reinterpret_cast<const char*>(&length), sizeof(length));
    std::cout.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    std::cout.flush();
  } catch (const std::exception& e) {
    // write_message is called from noexcept contexts; swallow and log.
    std::cerr << "Warning: write_message failed: " << e.what() << '\n';
  }
}

// ============================================================================
// Response helpers
// ============================================================================
//
// All responses follow a consistent shape:
//   { "status": "ok" | "error", ["id": ...,] ["message": "...",] [...] }
//
// make_error and make_ok enforce this shape and prevent command handlers
// from forgetting to set "status". Additional fields are merged in by the
// caller after construction.

[[nodiscard]] json make_error(std::string_view message,
                              std::optional<json> id = std::nullopt) {
  json r = {{"status", "error"}, {"message", std::string(message)}};
  if (id.has_value()) { r["id"] = *id; }
  return r;
}

[[nodiscard]] json make_ok(std::optional<json> id = std::nullopt) {
  json r = {{"status", "ok"}};
  if (id.has_value()) { r["id"] = *id; }
  return r;
}

// ============================================================================
// String utilities
// ============================================================================

// Case-insensitive substring search. Both haystack and needle are converted
// to lowercase for comparison. This is ASCII-only; non-ASCII characters are
// passed through unchanged (acceptable for URL/domain/email matching).
[[nodiscard]] bool icontains(std::string_view haystack,
                             std::string_view needle) noexcept {
  if (needle.empty()) { return true; }
  if (needle.size() > haystack.size()) { return false; }

  auto to_lower = [](unsigned char c) { return std::tolower(c); };

  return std::search(
      haystack.begin(), haystack.end(),
      needle.begin(),   needle.end(),
      [&](unsigned char a, unsigned char b) {
          return to_lower(a) == to_lower(b);
      }) != haystack.end();
}

// ============================================================================
// Command handlers
// ============================================================================
//
// Each handler receives the full request JSON, the current vault state, and
// the PrimaryTable by reference. It returns a json response object.
//
// The dispatch table (below) carries an explicit requires_unlock flag per
// command. Handlers for locked commands never receive a call if the vault is
// locked; they may assert or rely on it without rechecking.

// ----------------------------------------------------------------------------
// handle_ping
// ----------------------------------------------------------------------------
[[nodiscard]] json handle_ping(const json&    /*req*/,
                               VaultState     state,
                               PrimaryTable&  /*table*/,
                               std::optional<json> id) {
  json r = make_ok(id);
  r["is_unlocked"] = (state == VaultState::Unlocked);
  return r;
}

// ----------------------------------------------------------------------------
// handle_unlock
// ----------------------------------------------------------------------------
// Loads the vault from disk using the supplied master password. The password
// is a JSON string and is extracted into a std::string for the duration of
// the call. See "PASSWORD HANDLING" in the file header for the zeroing
// strategy and its limitations.
[[nodiscard]] json handle_unlock(const json&    req,
                                 VaultState&    state,
                                 PrimaryTable&  table,
                                 const Config&  cfg,
                                 std::optional<json> id) {
  // Extract the password as late as possible and zero it before returning.
  // nlohmann::json::value() returns a copy; we cannot avoid the std::string
  // intermediary without a custom JSON parser.
  std::string password = req.value("password", "");

  // Immediately scope the use of the password so that sodium_memzero runs
  // as soon as load_vault returns, before any other work happens.
  json response = make_error("Vault load failed", id);
  {
    const auto vault_path = resolve_vault_path(cfg.vault);

    if (!VaultIO::vault_exists(vault_path)) {
      sodium_memzero(password.data(), password.size());
      // Include the resolved path so the extension can surface it for
      // diagnosis, and direct the caller to init_vault if no vault exists yet.
      return make_error(
          "Vault not found at: " + vault_path.string() +
          ". Use 'init_vault' to create a new vault.", id);
    }

    try {
      table    = VaultIO::load_vault(vault_path, password);
      state    = VaultState::Unlocked;
      response = make_ok(id);
    } catch (const std::exception& e) {
      response = make_error(e.what(), id);
      // table is unchanged on exception; state remains Locked.
    }
  }

  // Zero the password regardless of success or failure.
  // sodium_memzero is not optimized away by the compiler (unlike memset).
  sodium_memzero(password.data(), password.size());
  return response;
}

// ----------------------------------------------------------------------------
// handle_lock
// ----------------------------------------------------------------------------
// Clears the PrimaryTable, destroying all SecretEntry objects. Each
// SecretEntry destructor calls Secret::~Secret -> sodium_free, which zeroes
// and releases every sodium-hardened allocation. std::unordered_map::clear()
// may retain the bucket array; the secrets themselves are fully zeroed.
[[nodiscard]] json handle_lock(const json&    /*req*/,
                               VaultState&    state,
                               PrimaryTable&  table,
                               std::optional<json> id) {
  table.clear();
  state = VaultState::Locked;
  return make_ok(id);
}

// ----------------------------------------------------------------------------
// handle_init_vault
// ----------------------------------------------------------------------------
// Creates a new empty vault at the platform default path, encrypted with the
// supplied master password. Fails if a vault already exists at that path to
// prevent accidental data loss. The parent directory is created if it does
// not yet exist, which is the common case on a fresh Windows installation
// where the AppData\Roaming\pwledger directory has never been created.
//
// After a successful init_vault, the caller should immediately send an
// "unlock" command with the same password to load the (empty) vault into
// the session. init_vault does not automatically unlock the session.
//
// PASSWORD HANDLING: same zeroing strategy as handle_unlock. See file header.
[[nodiscard]] json handle_init_vault(const json&    req,
                                     VaultState&    /*state*/,
                                     PrimaryTable&  /*table*/,
                                     const Config&  cfg,
                                     std::optional<json> id) {
  std::string password = req.value("password", "");

  if (password.empty()) {
    sodium_memzero(password.data(), password.size());
    return make_error("Password must not be empty", id);
  }

  json response = make_error("Vault initialization failed", id);
  {
    const auto vault_path = resolve_vault_path(cfg.vault);

    if (VaultIO::vault_exists(vault_path)) {
      sodium_memzero(password.data(), password.size());
      return make_error(
          "Vault already exists at: " + vault_path.string() +
          ". Delete it before reinitializing.", id);
    }

    // Create the parent directory if it does not exist. VaultIO::save_vault
    // writes to a .tmp file in the same directory; if the directory is absent
    // the write fails with a misleading error.
    try {
      std::filesystem::create_directories(vault_path.parent_path());
    } catch (const std::filesystem::filesystem_error& e) {
      sodium_memzero(password.data(), password.size());
      return make_error(
          std::string("Failed to create vault directory: ") + e.what(), id);
    }

    try {
      // Serialize and encrypt an empty table. The vault file now exists on
      // disk and is readable by subsequent "unlock" commands.
      const PrimaryTable empty_table;
      VaultIO::save_vault(vault_path, empty_table, password);

      json r = make_ok(id);
      r["vault_path"] = vault_path.string();  // surface the path for confirmation
      response = std::move(r);
    } catch (const std::exception& e) {
      response = make_error(e.what(), id);
    }
  }

  // Zero the password regardless of success or failure.
  sodium_memzero(password.data(), password.size());
  return response;
}

// ----------------------------------------------------------------------------
// handle_search
// ----------------------------------------------------------------------------
// Returns a JSON array of entries whose primary_key or username_or_email
// contains the query string (case-insensitive substring match). An empty
// query returns all entries. The secret value is never included in results.
[[nodiscard]] json handle_search(const json&         req,
                                 const PrimaryTable& table,
                                 std::optional<json> id) {
  const std::string query = req.value("query", "");

  json results = json::array();
  for (const auto& [uuid, entry] : table) {
    if (query.empty() ||
        icontains(entry.primary_key,       query) ||
        icontains(entry.username_or_email, query)) {
      results.push_back({
          {"uuid",         uuid.to_string()},
          {"primary_key",  entry.primary_key},
          {"username",     entry.username_or_email},
      });
    }
  }

  json r = make_ok(id);
  r["results"] = std::move(results);
  return r;
}

// ----------------------------------------------------------------------------
// handle_copy
// ----------------------------------------------------------------------------
// Copies the secret for the specified UUID to the system clipboard. The
// secret is accessed via a scoped read guard; it is never stored in a
// std::string or passed through JSON. The clipboard retains a plaintext
// copy in OS memory; the caller should invoke "clip_clear" when done.
[[nodiscard]] json handle_copy(const json&    req,
                               PrimaryTable&  table,
                               std::optional<json> id) {
  const std::string uuid_str = req.value("uuid", "");
  const auto uuid = Uuid::from_string(uuid_str);

  if (!uuid) {
    return make_error("Invalid UUID", id);
  }

  auto it = table.find(*uuid);
  if (it == table.end()) {
    return make_error("Not found", id);
  }

  it->second.plaintext_secret.with_read_access([](std::span<const char> buf) {
    const std::size_t len = ::strnlen(buf.data(), buf.size());
    clipboard_write(std::string_view(buf.data(), len));
  });

  it->second.metadata.last_used_at = std::chrono::system_clock::now();
  return make_ok(id);
}

// ----------------------------------------------------------------------------
// handle_clip_clear
// ----------------------------------------------------------------------------
[[nodiscard]] json handle_clip_clear(const json&    /*req*/,
                                     std::optional<json> id) {
  clipboard_clear();
  return make_ok(id);
}

// ============================================================================
// Dispatch table
// ============================================================================
//
// Each entry names a command, whether it requires an unlocked vault, and a
// handler. The requires_unlock flag is checked centrally in the message loop
// before invoking the handler, so individual handlers do not need to recheck
// it. Adding a new command requires a conscious decision about auth posture.

// Handler signature is intentionally wide to accommodate all commands
// without overloading. Unused parameters are named with /**/ in handlers.
using Handler = json (*)(const json&, VaultState&, PrimaryTable&, const Config&, std::optional<json>);

struct CommandDescriptor {
  bool requires_unlock;
  Handler handle;
};

// Trampoline adapters bridge the uniform dispatch signature to the narrower
// per-handler signatures, keeping the handler implementations clean.
namespace {

json dispatch_ping(const json& req, VaultState& state,
                   PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_ping(req, state, table, std::move(id));
}
json dispatch_unlock(const json& req, VaultState& state,
                     PrimaryTable& table, const Config& cfg, std::optional<json> id) {
  return handle_unlock(req, state, table, cfg, std::move(id));
}
json dispatch_lock(const json& req, VaultState& state,
                   PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_lock(req, state, table, std::move(id));
}
json dispatch_init_vault(const json& req, VaultState& state,
                         PrimaryTable& table, const Config& cfg, std::optional<json> id) {
  return handle_init_vault(req, state, table, cfg, std::move(id));
}
json dispatch_search(const json& req, VaultState& /*state*/,
                     PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_search(req, table, std::move(id));
}
json dispatch_copy(const json& req, VaultState& /*state*/,
                   PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_copy(req, table, std::move(id));
}
json dispatch_clip_clear(const json& req, VaultState& /*state*/,
                         PrimaryTable& /*table*/, const Config& /*cfg*/, std::optional<json> id) {
  return handle_clip_clear(req, std::move(id));
}

}  // anonymous namespace

const std::unordered_map<std::string, CommandDescriptor> kCommands{
  { "ping",        { /*requires_unlock=*/false, dispatch_ping        } },
  { "unlock",      { /*requires_unlock=*/false, dispatch_unlock      } },
  { "lock",        { /*requires_unlock=*/false, dispatch_lock        } },
  { "init_vault",  { /*requires_unlock=*/false, dispatch_init_vault  } },
  { "search",      { /*requires_unlock=*/true,  dispatch_search      } },
  { "copy",        { /*requires_unlock=*/true,  dispatch_copy        } },
  { "clip_clear",  { /*requires_unlock=*/false, dispatch_clip_clear  } },
};

// ============================================================================
// Message loop
// ============================================================================

void run_message_loop(const Config& cfg) {
  PrimaryTable table;
  VaultState   state = VaultState::Locked;

  for (;;) {
    auto raw = read_message();
    if (!raw.has_value()) {
      break;  // EOF, I/O error, or oversized message; terminate cleanly
    }

    // Extract the request ID early so it can be echoed in every response,
    // including parse-error responses.
    std::optional<json> req_id;
    json response;

    try {
      json req = json::parse(*raw);

      if (req.contains("id")) {
        req_id = req["id"];
      }

      const std::string cmd = req.value("command", "");
      const auto it = kCommands.find(cmd);

      if (it == kCommands.end()) {
        response = make_error("Unknown command", req_id);
      } else if (it->second.requires_unlock && state != VaultState::Unlocked) {
        response = make_error("Locked", req_id);
      } else {
        response = it->second.handle(req, state, table, cfg, req_id);
      }
    } catch (const json::parse_error&) {
      response = make_error("Invalid JSON", req_id);
    } catch (const std::exception& e) {
      // Unhandled exception from a command handler. Log locally and return
      // a generic error to the extension to avoid leaking internal details.
      std::cerr << "Warning: unhandled exception in command handler: "
                << e.what() << '\n';
      response = make_error("Internal error", req_id);
    }

    write_message(response);
  }
}

}  // namespace pwledger

// ============================================================================
// Entry point
// ============================================================================

int main() {
  // On Windows, stdin/stdout must be switched to binary mode before any I/O.
  // This must be done before sodium_init and before the message loop to
  // prevent text-mode translation of the raw length prefix bytes.
#ifdef _WIN32
  _setmode(_fileno(stdin),  _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif

  // Process hardening before any Secret is constructed.
  // See ProcessHardening.h and Secret.h "KNOWN LIMITATIONS".
  pwledger::harden_process();

  // sodium_init must be called once before any Secret is constructed.
  // Returns 0 on success, 1 if already initialized, -1 on failure.
  if (sodium_init() < 0) {
    std::cerr << "Fatal: libsodium initialization failed\n";
    return 1;
  }

  // Load user configuration (missing file -> defaults).
  pwledger::Config cfg;
  try {
    cfg = pwledger::load_config();
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to load config: " << e.what()
              << ". Using defaults.\n";
  }

  pwledger::run_message_loop(cfg);
  return 0;
}
