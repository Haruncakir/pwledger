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

#include "CommandHandlers.h"
#include "ResponseHelpers.h"
#include "StringUtils.h"

#include <pwledger/Clipboard.h>
#include <pwledger/VaultIO.h>
#include <pwledger/VaultPath.h>
#include <pwledger/uuid.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <span>
#include <string>

#include <sodium.h>

using json = nlohmann::json;

namespace pwledger {

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
// the call. See "PASSWORD HANDLING" in the original design notes for the
// zeroing strategy and its limitations.
[[nodiscard]] json handle_unlock(const json&    req,
                                 VaultState&    state,
                                 PrimaryTable&  table,
                                 const Config&  cfg,
                                 std::optional<json> id) {
  std::string password = req.value("password", "");

  json response = make_error("Vault load failed", id);
  {
    const auto vault_path = resolve_vault_path(cfg.vault);

    if (!VaultIO::vault_exists(vault_path)) {
      sodium_memzero(password.data(), password.size());
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
    }
  }

  sodium_memzero(password.data(), password.size());
  return response;
}

// ----------------------------------------------------------------------------
// handle_lock
// ----------------------------------------------------------------------------
// Clears the PrimaryTable, destroying all SecretEntry objects.
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
// supplied master password. Fails if a vault already exists.
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

    try {
      std::filesystem::create_directories(vault_path.parent_path());
    } catch (const std::filesystem::filesystem_error& e) {
      sodium_memzero(password.data(), password.size());
      return make_error(
          std::string("Failed to create vault directory: ") + e.what(), id);
    }

    try {
      const PrimaryTable empty_table;
      VaultIO::save_vault(vault_path, empty_table, password);

      json r = make_ok(id);
      r["vault_path"] = vault_path.string();
      response = std::move(r);
    } catch (const std::exception& e) {
      response = make_error(e.what(), id);
    }
  }

  sodium_memzero(password.data(), password.size());
  return response;
}

// ----------------------------------------------------------------------------
// handle_search
// ----------------------------------------------------------------------------
// Returns a JSON array of entries whose primary_key or username_or_email
// contains the query string (case-insensitive substring match).
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
// Copies the secret for the specified UUID to the system clipboard.
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

// ----------------------------------------------------------------------------
// handle_get_credentials
// ----------------------------------------------------------------------------
// Returns the username and plaintext password for the specified UUID.
// The password is extracted from sodium-hardened memory, placed into a
// temporary std::string for JSON serialization, then wiped with
// sodium_memzero before this function returns.
[[nodiscard]] json handle_get_credentials(const json&    req,
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

  // Extract password into a temporary std::string for JSON serialization.
  std::string password;
  it->second.plaintext_secret.with_read_access([&](std::span<const char> buf) {
    const std::size_t len = ::strnlen(buf.data(), buf.size());
    password.assign(buf.data(), len);
  });

  json r = make_ok(id);
  r["username"] = it->second.username_or_email;
  r["password"] = password;

  it->second.metadata.last_used_at = std::chrono::system_clock::now();

  // Wipe the temporary copy before it goes out of scope.
  sodium_memzero(password.data(), password.size());
  return r;
}

}  // namespace pwledger
