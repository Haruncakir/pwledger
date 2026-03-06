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

#ifndef UUID_H
#define UUID_H

#include <array>
#include <cstdint>
#include <functional>
#include <random>

namespace pwledger {

struct Uuid {
  std::array<std::uint8_t, 16> bytes;
  // uuid-v4
  static Uuid generate() {
    Uuid id;

    std::random_device rd;
    std::mt19937_64 gen(rd());  // not cryptographically secure
    std::uniform_int_distribution<std::uint64_t> dist;

    uint64_t part1 = dist(gen);
    uint64_t part2 = dist(gen);

    std::memcpy(id.bytes.data(), &part1, 8);
    std::memcpy(id.bytes.data() + 8, &part2, 8);

    // Set version to 4
    id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;

    // Set variant to RFC 4122
    id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;
    return id;
  }

  bool operator==(const UUID& other) const noexcept { return bytes == other.bytes; }
};

}  // namespace pwledger

namespace std {
// specialize std::hash for pwledger::Uuid
template <>
struct hash<pwledger::Uuid> {
  std::size_t operator()(const pwledger::Uuid& uuid) const noexcept {
    const uint64_t* p = reinterpret_cast<const uint64_t*>(uuid.bytes.data());

    return std::hash<uint64_t>{}(p[0]) ^ (std::hash<uint64_t>{}(p[1]) << 1);
  }
};
}  // namespace std

#endif  // UUID_H
