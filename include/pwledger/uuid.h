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

#ifndef PWLEDGER_UUID_H
#define PWLEDGER_UUID_H

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// Uuid represents a 128-bit UUID-v4 identifier stored as a raw byte array.
// This header is intentionally self-contained: it provides generation,
// string parsing, string formatting, and hashing so that both the CLI and
// native messaging host can use UUIDs without pulling in heavy dependencies.
//
// STRING FORMAT
// -------------
// The canonical string representation follows RFC 4122:
//   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   (36 characters, lowercase hex)
//
// from_string() also accepts the 32-character compact form (no hyphens).
// to_string() always produces the canonical 36-character form.
//
// SECURITY
// --------
// generate() uses std::random_device + std::mt19937_64, which is NOT
// cryptographically secure. This is acceptable for table keys but must
// not be used for nonces or key material. If cryptographic UUIDs are
// needed, replace the PRNG with randombytes_buf() from libsodium.
//
// ============================================================================

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <optional>
#include <ostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace pwledger {

struct Uuid {
  std::array<std::uint8_t, 16> bytes{};

  // --------------------------------------------------------------------------
  // Queries
  // --------------------------------------------------------------------------

  // Returns true if all 16 bytes are zero (the nil UUID per RFC 4122 §4.1.7).
  bool empty() const noexcept {
    for (std::uint8_t b : bytes) {
      if (b != 0) return false;
    }
    return true;
  }

  // --------------------------------------------------------------------------
  // Generation
  // --------------------------------------------------------------------------

  // Generates a version-4 (random) UUID per RFC 4122.
  // NOT cryptographically secure — see DESIGN NOTES.
  static Uuid generate() {
    Uuid id;

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<std::uint64_t> dist;

    std::uint64_t part1 = dist(gen);
    std::uint64_t part2 = dist(gen);

    std::memcpy(id.bytes.data(), &part1, 8);
    std::memcpy(id.bytes.data() + 8, &part2, 8);

    // Set version to 4 (bits 4–7 of byte 6).
    id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;

    // Set variant to RFC 4122 (bits 6–7 of byte 8).
    id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;
    return id;
  }

  // --------------------------------------------------------------------------
  // String conversion
  // --------------------------------------------------------------------------

  // Formats as the canonical RFC 4122 representation:
  //   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  std::string to_string() const {
    // Byte groups: 4-2-2-2-6, separated by hyphens.
    constexpr int kGroups[]    = {4, 2, 2, 2, 6};
    constexpr int kNumGroups   = 5;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    int byte_index = 0;
    for (int g = 0; g < kNumGroups; ++g) {
      if (g > 0) { oss << '-'; }
      for (int i = 0; i < kGroups[g]; ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[byte_index++]);
      }
    }
    return oss.str();
  }

  // Parses a UUID from its string representation. Accepts both the canonical
  // 36-character form (with hyphens) and the 32-character compact form.
  // Returns std::nullopt on malformed input rather than throwing, so callers
  // can provide user-friendly error messages.
  static std::optional<Uuid> from_string(std::string_view str) {
    // Strip hyphens to get a uniform 32-character hex string.
    std::string hex;
    hex.reserve(32);
    for (char c : str) {
      if (c == '-') { continue; }
      if (!is_hex_digit(c)) { return std::nullopt; }
      hex += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (hex.size() != 32) { return std::nullopt; }

    Uuid id;
    for (std::size_t i = 0; i < 16; ++i) {
      id.bytes[i] = static_cast<std::uint8_t>(
        (hex_value(hex[i * 2]) << 4) | hex_value(hex[i * 2 + 1]));
    }
    return id;
  }

  // --------------------------------------------------------------------------
  // Comparison
  // --------------------------------------------------------------------------

  bool operator==(const Uuid& other) const noexcept {
    return bytes == other.bytes;
  }

  bool operator!=(const Uuid& other) const noexcept {
    return bytes != other.bytes;
  }

  // --------------------------------------------------------------------------
  // Stream output
  // --------------------------------------------------------------------------

  friend std::ostream& operator<<(std::ostream& os, const Uuid& uuid) {
    return os << uuid.to_string();
  }

private:
  static bool is_hex_digit(char c) noexcept {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
  }

  static int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return 0;  // unreachable after is_hex_digit check
  }
};

}  // namespace pwledger

namespace std {
// Specialize std::hash for pwledger::Uuid so it can be used as an
// unordered_map key. The hash combines the two 64-bit halves of the UUID.
template<> struct hash<pwledger::Uuid> {
  std::size_t operator()(const pwledger::Uuid& uuid) const noexcept {
    const std::uint64_t* p =
      reinterpret_cast<const std::uint64_t*>(uuid.bytes.data());

    return std::hash<std::uint64_t>{}(p[0]) ^
      (std::hash<std::uint64_t>{}(p[1]) << 1);
  }
};
}  // namespace std

#endif  // PWLEDGER_UUID_H
