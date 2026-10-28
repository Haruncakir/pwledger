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

#ifndef PWLEDGER_VAULTEXCEPTIONS_H
#define PWLEDGER_VAULTEXCEPTIONS_H

#include <stdexcept>
#include <string>

namespace pwledger {

// ----------------------------------------------------------------------------
// Tier 2 Domain & Resource Exceptions (Derived from std::runtime_error)
// ----------------------------------------------------------------------------

// Thrown when a vault payload fails validation: malformed header magic,
// unsupported wire version, structural truncation, invalid entry counts,
// or field length boundary violations.
class VaultCorruptException : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

// Thrown when an untrusted operation exceeds safe operational resources:
// decrypted payload exceeding maximum size limit (64 MiB), or sodium_malloc
// failure (e.g. system out-of-memory or VMA limit exhaustion) during
// untrusted deserialization.
class VaultResourceException : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

// Thrown when cryptographic authentication fails (AEAD MAC mismatch,
// incorrect master password, or tampered ciphertext).
class AuthenticationFailedException : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

// Thrown when filesystem I/O operations fail (file not found, permission
// denied, disk full, atomic rename failure).
class VaultIoException : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

}  // namespace pwledger

#endif  // PWLEDGER_VAULTEXCEPTIONS_H
