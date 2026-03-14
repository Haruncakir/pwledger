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

#include "EntryOps.h"
#include "SecretIO.h"

#include <pwledger/Secret.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

#include <sodium.h>

namespace pwledger {

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

// ----------------------------------------------------------------------------
// touch_last_used
// ----------------------------------------------------------------------------
// Updates the last_used_at timestamp for the entry with the given UUID.
// Returns false if the UUID does not exist.
bool touch_last_used(PrimaryTable& table, const Uuid& uuid) {
  auto it = table.find(uuid);
  if (it == table.end()) {
    return false;
  }
  it->second.metadata.last_used_at = std::chrono::system_clock::now();
  return true;
}

}  // namespace pwledger
