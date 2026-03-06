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

#ifndef PWLEDGER_VAULTIO_H
#define PWLEDGER_VAULTIO_H

#include <pwledger/PrimaryTable.h>
#include <pwledger/VaultCrypto.h>
#include <pwledger/VaultSerializer.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace pwledger {

// ----------------------------------------------------------------------------
// VaultIO
// ----------------------------------------------------------------------------
// High-level integration of VaultSerializer, VaultCrypto, and file I/O.

class VaultIO {
public:
  static bool vault_exists(const std::filesystem::path& path) {
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
  }

  // Atomically saves the table todisk.
  // Writes to a temporary file first, then renames it over the target.
  static void save_vault(const std::filesystem::path& path, const PrimaryTable& table, std::string_view password) {
    // 1. Serialize to plaintext bytes
    std::vector<std::uint8_t> plaintext = VaultSerializer::serialize(table);

    // 2. Encrypt
    std::vector<std::uint8_t> ciphertext = VaultCrypto::encrypt_vault(password, plaintext);

    // 3. Clear plaintext from memory immediately (best effort; std::vector
    // doesn't guarantee zeroing, but we can do it manually before destruction)
    sodium_memzero(plaintext.data(), plaintext.size());
    // Also clear its capacity if it reallocated
    plaintext.clear();
    plaintext.shrink_to_fit();

    // 4. Atomic write
    std::filesystem::path temp_path = path;
    temp_path += ".tmp";

    {
      std::ofstream ofs(temp_path, std::ios::binary | std::ios::trunc);
      if (!ofs) {
        throw std::runtime_error("Failed to open temporary vault file for writing");
      }
      ofs.write(reinterpret_cast<const char*>(ciphertext.data()), static_cast<std::streamsize>(ciphertext.size()));
      if (!ofs.good()) {
        throw std::runtime_error("Write to temporary vault file failed");
      }
    }

    // Set restrictive permissions on the temp file before renaming
    std::filesystem::permissions(
        temp_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);

    std::filesystem::rename(temp_path, path);
  }

  // Loads the vault from disk. Throws on decryption failure, format failure,
  // or read errors.
  static PrimaryTable load_vault(const std::filesystem::path& path, std::string_view password) {
    if (!vault_exists(path)) {
      throw std::runtime_error("Vault file does not exist");
    }

    // 1. Read entire file
    std::vector<std::uint8_t> ciphertext;
    {
      std::ifstream ifs(path, std::ios::binary | std::ios::ate);
      if (!ifs) {
        throw std::runtime_error("Failed to open vault file for reading");
      }
      auto size = ifs.tellg();
      if (size < 0) {
        throw std::runtime_error("Failed to determine vault file size");
      }
      ifs.seekg(0, std::ios::beg);
      ciphertext.resize(static_cast<std::size_t>(size));
      if (!ifs.read(reinterpret_cast<char*>(ciphertext.data()), size)) {
        throw std::runtime_error("Failed to read vault file");
      }
    }

    // 2. Decrypt
    std::vector<std::uint8_t> plaintext = VaultCrypto::decrypt_vault(password, ciphertext);

    // 3. Deserialize
    PrimaryTable table;
    try {
      table = VaultSerializer::deserialize(plaintext.data(), plaintext.size());
    } catch (...) {
      sodium_memzero(plaintext.data(), plaintext.size());
      throw;
    }

    // 4. Clear plaintext
    sodium_memzero(plaintext.data(), plaintext.size());
    
    return table;
  }
};

}  // namespace pwledger

#endif  // PWLEDGER_VAULTIO_H
