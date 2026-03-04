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

#ifndef PWLEDGER_SECRETENTRY_H
#define PWLEDGER_SECRETENTRY_H

#include <pwledger/EntryMetadata.h>
#include <pwledger/EntrySecurityPolicy.h>
#include <pwledger/Secret.h>

#include <chrono>
#include <string>

namespace pwledger {

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

}  // namespace pwledger

#endif  // PWLEDGER_SECRETENTRY_H
