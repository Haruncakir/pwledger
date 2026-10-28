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

#include <pwledger/SecretEntry.h>

#include <chrono>

namespace pwledger {

SecretEntry::SecretEntry(std::string pk, std::string user, std::size_t secret_size, std::size_t salt_size)
    : primary_key(std::move(pk))
    , username_or_email(std::move(user))
    , plaintext_secret(secret_size)
    , salt(salt_size)
    , metadata{std::chrono::system_clock::now(), std::chrono::system_clock::now(), std::chrono::system_clock::now()} {
}

SecretEntry::SecretEntry(std::string pk, std::string user, Secret secret_buf, Secret salt_buf)
    : primary_key(std::move(pk))
    , username_or_email(std::move(user))
    , plaintext_secret(std::move(secret_buf))
    , salt(std::move(salt_buf))
    , metadata{std::chrono::system_clock::now(), std::chrono::system_clock::now(), std::chrono::system_clock::now()} {
}

SecretEntry SecretEntry::try_create(std::string pk, std::string user, std::size_t secret_size, std::size_t salt_size) {
  Secret sec = Secret::try_create(secret_size);
  Secret slt = Secret::try_create(salt_size);
  return SecretEntry(std::move(pk), std::move(user), std::move(sec), std::move(slt));
}

}  // namespace pwledger
