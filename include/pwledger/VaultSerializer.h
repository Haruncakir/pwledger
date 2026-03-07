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

#ifndef PWLEDGER_VAULTSERIALIZER_H
#define PWLEDGER_VAULTSERIALIZER_H

#include <pwledger/PrimaryTable.h>
#include <pwledger/Secret.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace pwledger {

// ----------------------------------------------------------------------------
// VaultSerializer
// ----------------------------------------------------------------------------
// Converts a PrimaryTable to and from a flat binary buffer. The buffer is
// unencrypted; encryption (AEAD) is applied in a separate phase by VaultCrypto.
//
// Format Version 1 Layout:
//   Header:
//     [4 bytes magic "PWL\0"]
//     [1 byte version = 1]
//     [8 bytes num_entries (uint64_t)]
//   Entries (repeated num_entries times):
//     [16 bytes UUID]
//     [4 bytes pk_len][pk_len bytes primary_key]
//     [4 bytes uoe_len][uoe_len bytes username_or_email]
//     [4 bytes secret_len][secret_len bytes plaintext_secret]
//     [4 bytes salt_len][salt_len bytes salt]
//     [8 bytes created_at (epoch seconds)]
//     [8 bytes last_modified_at (epoch seconds)]
//     [8 bytes last_used_at (epoch seconds)]
//     [4 bytes strength_score]
//     [4 bytes reuse_count]
//     [1 byte two_fa_enabled]
//     [1 byte has_expires_at][if 1: 8 bytes expires_at (epoch seconds)]
//     [4 bytes note_len][note_len bytes note]
//
// Integers are stored in little-endian.

class VaultSerializer {
public:
  static constexpr std::uint8_t kMagic[4] = {'P', 'W', 'L', '\0'};
  static constexpr std::uint8_t kVersion = 1;

  // Serializes the table to a heap-allocated buffer. Since the table contains
  // sensitive plaintext secrets, the returned buffer should be passed to
  // sodium_memzero or wrapped in a Secret as soon as encryption completes.
  static std::vector<std::uint8_t> serialize(const PrimaryTable& table);

  // Deserializes a buffer back into a PrimaryTable. Throws std::runtime_error
  // on format violations. The input pointer must be valid for `size` bytes.
  static PrimaryTable deserialize(const std::uint8_t* data, std::size_t size);

private:
  // Write helpers
  static void write_u8(std::vector<std::uint8_t>& out, std::uint8_t val);
  static void write_u32(std::vector<std::uint8_t>& out, std::uint32_t val);
  static void write_u64(std::vector<std::uint8_t>& out, std::uint64_t val);
  static void write_bytes(std::vector<std::uint8_t>& out, const std::uint8_t* data, std::size_t len);
  static void write_string(std::vector<std::uint8_t>& out, const std::string& str);
  static void write_time(std::vector<std::uint8_t>& out, std::chrono::system_clock::time_point tp);

  // Read helpers
  static std::uint32_t read_u32(const std::uint8_t* data, std::size_t& pos, std::size_t size);
  static std::uint64_t read_u64(const std::uint8_t* data, std::size_t& pos, std::size_t size);
  static std::string read_string(const std::uint8_t* data, std::size_t& pos, std::size_t size);
  static std::chrono::system_clock::time_point read_time(const std::uint8_t* data, std::size_t& pos, std::size_t size);
};

}  // namespace pwledger

#endif  // PWLEDGER_VAULTSERIALIZER_H
