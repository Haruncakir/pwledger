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


#include <pwledger/VaultCrypto.h>

#include <cstring>
#include <stdexcept>
#include <vector>

namespace pwledger {

Secret VaultCrypto::derive_master_key(std::string_view password, const std::uint8_t* salt) {
  Secret key(kKeyBytes);
  key.with_write_access([&](std::span<char> buf) {
    if (crypto_pwhash(reinterpret_cast<std::uint8_t*>(buf.data()), buf.size(),
                      password.data(), password.size(), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
      throw std::runtime_error("Argon2id key derivation failed");
    }
  });
  return key;
}

std::vector<std::uint8_t> VaultCrypto::encrypt_vault(std::string_view password, const std::vector<std::uint8_t>& plaintext) {
  std::uint8_t salt[kSaltBytes];
  randombytes_buf(salt, sizeof(salt));

  std::uint8_t nonce[kNonceBytes];
  randombytes_buf(nonce, sizeof(nonce));

  Secret key = derive_master_key(password, salt);

  std::vector<std::uint8_t> out(kHeaderBytes + plaintext.size() + kTagBytes);
  std::memcpy(out.data(), salt, kSaltBytes);
  std::memcpy(out.data() + kSaltBytes, nonce, kNonceBytes);

  unsigned long long ciphertext_len = 0;
  
  key.with_read_access([&](std::span<const char> key_buf) {
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out.data() + kHeaderBytes, &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,  // additional data
            nullptr,     // secret nonce (not used)
            nonce,
            reinterpret_cast<const std::uint8_t*>(key_buf.data())) != 0) {
      throw std::runtime_error("Encryption failed");
    }
  });

  out.resize(kHeaderBytes + ciphertext_len);
  return out;
}

std::vector<std::uint8_t> VaultCrypto::decrypt_vault(std::string_view password, const std::vector<std::uint8_t>& ciphertext_blob) {
  if (ciphertext_blob.size() < kHeaderBytes + kTagBytes) {
    throw std::runtime_error("Ciphertext too short (missing headers or tag)");
  }

  const std::uint8_t* salt = ciphertext_blob.data();
  const std::uint8_t* nonce = ciphertext_blob.data() + kSaltBytes;
  const std::uint8_t* encrypted_data = ciphertext_blob.data() + kHeaderBytes;
  std::size_t encrypted_len = ciphertext_blob.size() - kHeaderBytes;

  Secret key = derive_master_key(password, salt);

  std::vector<std::uint8_t> plaintext(encrypted_len - kTagBytes);
  unsigned long long plaintext_len = 0;

  bool dec_ok = false;
  key.with_read_access([&](std::span<const char> key_buf) {
    dec_ok = crypto_aead_xchacha20poly1305_ietf_decrypt(
                 plaintext.data(), &plaintext_len,
                 nullptr,
                 encrypted_data, encrypted_len,
                 nullptr, 0,
                 nonce,
                 reinterpret_cast<const std::uint8_t*>(key_buf.data())) == 0;
  });

  if (!dec_ok) {
    throw std::runtime_error("Decryption failed (incorrect password or corrupted vault)");
  }

  plaintext.resize(plaintext_len);
  return plaintext;
}

}  // namespace pwledger
