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
// generate() uses libsodium's randombytes_buf() CSPRNG to produce
// cryptographically secure UUIDv4 identifiers.
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
      if (b != 0)
        return false;
    }
    return true;
  }

  // --------------------------------------------------------------------------
  // Generation
  // --------------------------------------------------------------------------

  // Generates a version-4 (random) UUID per RFC 4122.
  // NOT cryptographically secure — see DESIGN NOTES.
  static Uuid generate();

  // --------------------------------------------------------------------------
  // String conversion
  // --------------------------------------------------------------------------

  // Formats as the canonical RFC 4122 representation:
  //   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  std::string to_string() const;

  // Parses a UUID from its string representation. Accepts both the canonical
  // 36-character form (with hyphens) and the 32-character compact form.
  // Returns std::nullopt on malformed input rather than throwing, so callers
  // can provide user-friendly error messages.
  static std::optional<Uuid> from_string(std::string_view str);

  // --------------------------------------------------------------------------
  // Comparison
  // --------------------------------------------------------------------------

  bool operator==(const Uuid& other) const noexcept { return bytes == other.bytes; }

  bool operator!=(const Uuid& other) const noexcept { return bytes != other.bytes; }

  // --------------------------------------------------------------------------
  // Stream output
  // --------------------------------------------------------------------------

  friend std::ostream& operator<<(std::ostream& os, const Uuid& uuid);

private:
  static bool is_hex_digit(char c) noexcept;

  static int hex_value(char c) noexcept;
};

}  // namespace pwledger

namespace std {
// Specialize std::hash for pwledger::Uuid so it can be used as an
// unordered_map key. The hash combines the two 64-bit halves of the UUID safely
// using std::memcpy to prevent unaligned load undefined behavior.
template <>
struct hash<pwledger::Uuid> {
  std::size_t operator()(const pwledger::Uuid& uuid) const noexcept {
    std::uint64_t p0 = 0;
    std::uint64_t p1 = 0;
    std::memcpy(&p0, uuid.bytes.data(), sizeof(p0));
    std::memcpy(&p1, uuid.bytes.data() + sizeof(p0), sizeof(p1));
    return std::hash<std::uint64_t>{}(p0) ^ (std::hash<std::uint64_t>{}(p1) << 1);
  }
};
}  // namespace std

#endif  // PWLEDGER_UUID_H
