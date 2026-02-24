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
#include <optional>
#include <string>
#include <unordered_map>

// TODO(#issue-N): replace with a proper UUID type (e.g., a fixed-size byte
// array or a thin wrapper) once the identity layer is defined. Using a raw
// string as a key is a placeholder; UUIDs should not be heap-allocated
// strings in the hot path of an unordered_map lookup.
using Uuid = std::string;

namespace pwledger {

// ----------------------------------------------------------------------------
// SecretEntry
// ----------------------------------------------------------------------------
// Represents a single stored credential. The encrypted secret and its
// derivation salt are held in sodium-hardened memory via Secret, which
// zeroes and frees them on destruction. All other fields are non-sensitive
// metadata and may live in ordinary heap memory.
//
// SecretEntry is move-only because Secret is move-only. Copying would require
// duplicating sodium-allocated memory, which is intentionally unsupported.
// See Secret.h invariant 1 (single ownership).
//
// The destructor is implicitly correct: Secret's own destructor calls
// sodium_free, which zeroes and releases the hardened allocation.
struct SecretEntry {
  std::string primary_key;
  std::string username_or_email;
  Secret      encrypted_secret;
  Secret      salt;
  EntryMetadata metadata;
  EntrySecurityPolicy security_policy;

  // Explicit constructor required because Secret has no default constructor.
  // Sizes are placeholders; the caller is expected to supply the correct
  // ciphertext and salt lengths for the chosen algorithm.
  SecretEntry(std::string     pk,
              std::string     user,
              std::size_t     secret_size,
              std::size_t     salt_size)
    : primary_key(std::move(pk)),
      username_or_email(std::move(user)),
      encrypted_secret(secret_size),
      salt(salt_size)
  {}

  ~SecretEntry() = default;

  SecretEntry(SecretEntry&&)            = default;
  SecretEntry& operator=(SecretEntry&&) = default;

  SecretEntry(const SecretEntry&)            = delete;
  SecretEntry& operator=(const SecretEntry&) = delete;
};

// ----------------------------------------------------------------------------
// EntryMetadata
// ----------------------------------------------------------------------------
// Lifecycle timestamps for a stored credential. All fields use a consistent
// clock (system_clock) so that timestamps are comparable and serializable.
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
// strength_score:  Estimated bit-strength of the secret (e.g., from zxcvbn
//                  or a similar estimator). Stored as int; consider a
//                  stronger type (e.g., a newtype wrapper) if the score
//                  has invariants (non-negative, bounded range).
// reuse_count:     Number of times this secret has been reused across
//                  entries. Used to surface reuse warnings in the UI.
// two_fa_enabled:  Whether a second factor is associated with this entry.
// expires_at:      Optional expiry deadline. nullopt means no expiry policy.
// note:            Free-form user annotation. Not encrypted; treat as
//                  non-sensitive. If notes may contain sensitive content,
//                  migrate this field to a Secret.
struct EntrySecurityPolicy {
  int                                            strength_score  = 0;
  int                                            reuse_count     = 0;
  bool                                           two_fa_enabled  = false;
  std::optional<std::chrono::system_clock::time_point> expires_at;
  std::string                                    note;
};

// ----------------------------------------------------------------------------
// PrimaryTable
// ----------------------------------------------------------------------------
// The top-level credential store: a map from UUID to SecretEntry.
// SecretEntry is move-only, so the map stores it by value and moves on
// insertion. unordered_map is appropriate here for O(1) average lookup by
// UUID; if ordered iteration or range queries are needed, consider
// std::map<Uuid, SecretEntry> instead.
//
// TODO(#issue-N): replace Uuid alias with a proper fixed-width UUID type to
// avoid unnecessary heap allocation on every lookup.
using PrimaryTable = std::unordered_map<Uuid, SecretEntry>;

}  // namespace pwledger

int main() {
  // sodium must be initialized once before any Secret is constructed.
  if (sodium_init() < 0) { return 1; } // TODO: Log and explain why

  pwledger::PrimaryTable table; // TODO: make it persistent

  // CRUD password
  // CRUD table entry
  // clipboard management

  return 0;
}
