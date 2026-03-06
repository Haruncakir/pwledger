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
  static std::vector<std::uint8_t> serialize(const PrimaryTable& table) {
    std::vector<std::uint8_t> out;
    // Rough preallocation estimate: 128 bytes per entry + header
    out.reserve(13 + table.size() * 128);

    // Header
    write_bytes(out, kMagic, 4);
    write_u8(out, kVersion);
    write_u64(out, static_cast<std::uint64_t>(table.size()));

    // Entries
    for (const auto& [uuid, entry] : table) {
      write_bytes(out, uuid.bytes.data(), 16);

      write_string(out, entry.primary_key);
      write_string(out, entry.username_or_email);

      // Secret data reading requires access guard
      entry.plaintext_secret.with_read_access([&](std::span<const char> buf) {
        std::size_t len = ::strnlen(buf.data(), buf.size());
        write_u32(out, static_cast<std::uint32_t>(len));
        write_bytes(out, reinterpret_cast<const std::uint8_t*>(buf.data()), len);
      });

      entry.salt.with_read_access([&](std::span<const char> buf) {
        write_u32(out, static_cast<std::uint32_t>(buf.size()));
        write_bytes(out, reinterpret_cast<const std::uint8_t*>(buf.data()), buf.size());
      });

      // Metadata
      write_time(out, entry.metadata.created_at);
      write_time(out, entry.metadata.last_modified_at);
      write_time(out, entry.metadata.last_used_at);

      // Security Policy
      write_u32(out, static_cast<std::uint32_t>(entry.security_policy.strength_score));
      write_u32(out, static_cast<std::uint32_t>(entry.security_policy.reuse_count));
      write_u8(out, entry.security_policy.two_fa_enabled ? 1 : 0);

      if (entry.security_policy.expires_at.has_value()) {
        write_u8(out, 1);
        write_time(out, *entry.security_policy.expires_at);
      } else {
        write_u8(out, 0);
      }

      write_string(out, entry.security_policy.note);
    }

    return out;
  }

  // Deserializes a buffer back into a PrimaryTable. Throws std::runtime_error
  // on format violations. The input pointer must be valid for `size` bytes.
  static PrimaryTable deserialize(const std::uint8_t* data, std::size_t size) {
    PrimaryTable table;
    std::size_t pos = 0;

    auto require = [&](std::size_t bytes) {
      if (pos + bytes > size) {
        throw std::runtime_error("Vault payload truncated");
      }
    };

    require(4);
    if (std::memcmp(data + pos, kMagic, 4) != 0) {
      throw std::runtime_error("Invalid vault magic number");
    }
    pos += 4;

    require(1);
    if (data[pos] != kVersion) {
      throw std::runtime_error("Unsupported vault version");
    }
    pos += 1;

    std::uint64_t num_entries = read_u64(data, pos, size);

    for (std::uint64_t i = 0; i < num_entries; ++i) {
      require(16);
      Uuid uuid;
      std::memcpy(uuid.bytes.data(), data + pos, 16);
      pos += 16;

      std::string pk = read_string(data, pos, size);
      std::string uoe = read_string(data, pos, size);

      std::uint32_t secret_len = read_u32(data, pos, size);
      require(secret_len);
      const std::uint8_t* secret_data = data + pos;
      pos += secret_len;

      std::uint32_t salt_len = read_u32(data, pos, size);
      require(salt_len);
      const std::uint8_t* salt_data = data + pos;
      pos += salt_len;

      // SecretEntry needs the max allocation sizes (kMaxSecretBytes, kSaltBytes)
      // We derive them here or pad up to match the runtime defaults (256, 16).
      // If the serialized secret is longer than 256, we allocate exactly its size.
      std::size_t alloc_secret = (secret_len > 256) ? secret_len : 256;
      std::size_t alloc_salt = (salt_len > 16) ? salt_len : 16;

      SecretEntry entry(std::move(pk), std::move(uoe), alloc_secret, alloc_salt);

      // Copy bytes into the hardened buffer
      entry.plaintext_secret.with_write_access([&](std::span<char> buf) {
        std::memset(buf.data(), 0, buf.size());
        std::memcpy(buf.data(), secret_data, secret_len);
      });

      entry.salt.with_write_access([&](std::span<char> buf) {
        std::memset(buf.data(), 0, buf.size());
        std::memcpy(buf.data(), salt_data, salt_len);
      });

      entry.metadata.created_at = read_time(data, pos, size);
      entry.metadata.last_modified_at = read_time(data, pos, size);
      entry.metadata.last_used_at = read_time(data, pos, size);

      entry.security_policy.strength_score = static_cast<int>(read_u32(data, pos, size));
      entry.security_policy.reuse_count = static_cast<int>(read_u32(data, pos, size));
      
      require(1);
      entry.security_policy.two_fa_enabled = (data[pos++] != 0);

      require(1);
      if (data[pos++] != 0) {
        entry.security_policy.expires_at = read_time(data, pos, size);
      }

      entry.security_policy.note = read_string(data, pos, size);

      table.emplace(uuid, std::move(entry));
    }

    return table;
  }

private:
  // Write helpers
  static void write_u8(std::vector<std::uint8_t>& out, std::uint8_t val) {
    out.push_back(val);
  }

  static void write_u32(std::vector<std::uint8_t>& out, std::uint32_t val) {
    out.push_back(static_cast<std::uint8_t>(val & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
  }

  static void write_u64(std::vector<std::uint8_t>& out, std::uint64_t val) {
    out.push_back(static_cast<std::uint8_t>(val & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 32) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 40) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 48) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((val >> 56) & 0xFF));
  }

  static void write_bytes(std::vector<std::uint8_t>& out, const std::uint8_t* data, std::size_t len) {
    out.insert(out.end(), data, data + len);
  }

  static void write_string(std::vector<std::uint8_t>& out, const std::string& str) {
    std::uint32_t len = static_cast<std::uint32_t>(str.size());
    write_u32(out, len);
    write_bytes(out, reinterpret_cast<const std::uint8_t*>(str.data()), len);
  }

  static void write_time(std::vector<std::uint8_t>& out, std::chrono::system_clock::time_point tp) {
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
    write_u64(out, static_cast<std::uint64_t>(sec));
  }

  // Read helpers
  static std::uint32_t read_u32(const std::uint8_t* data, std::size_t& pos, std::size_t size) {
    if (pos + 4 > size) throw std::runtime_error("Truncated buffer");
    std::uint32_t val = static_cast<std::uint32_t>(data[pos]) |
                        (static_cast<std::uint32_t>(data[pos + 1]) << 8) |
                        (static_cast<std::uint32_t>(data[pos + 2]) << 16) |
                        (static_cast<std::uint32_t>(data[pos + 3]) << 24);
    pos += 4;
    return val;
  }

  static std::uint64_t read_u64(const std::uint8_t* data, std::size_t& pos, std::size_t size) {
    if (pos + 8 > size) throw std::runtime_error("Truncated buffer");
    std::uint64_t val = static_cast<std::uint64_t>(data[pos]) |
                        (static_cast<std::uint64_t>(data[pos + 1]) << 8) |
                        (static_cast<std::uint64_t>(data[pos + 2]) << 16) |
                        (static_cast<std::uint64_t>(data[pos + 3]) << 24) |
                        (static_cast<std::uint64_t>(data[pos + 4]) << 32) |
                        (static_cast<std::uint64_t>(data[pos + 5]) << 40) |
                        (static_cast<std::uint64_t>(data[pos + 6]) << 48) |
                        (static_cast<std::uint64_t>(data[pos + 7]) << 56);
    pos += 8;
    return val;
  }

  static std::string read_string(const std::uint8_t* data, std::size_t& pos, std::size_t size) {
    std::uint32_t len = read_u32(data, pos, size);
    if (pos + len > size) throw std::runtime_error("Truncated string");
    std::string str(reinterpret_cast<const char*>(data + pos), len);
    pos += len;
    return str;
  }

  static std::chrono::system_clock::time_point read_time(const std::uint8_t* data, std::size_t& pos, std::size_t size) {
    std::int64_t sec = static_cast<std::int64_t>(read_u64(data, pos, size));
    return std::chrono::system_clock::time_point(std::chrono::seconds(sec));
  }
};

}  // namespace pwledger

#endif  // PWLEDGER_VAULTSERIALIZER_H
