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

#ifndef PWLEDGER_HOST_NATIVE_MESSAGING_H
#define PWLEDGER_HOST_NATIVE_MESSAGING_H

#include <cstdint>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace pwledger {

// Maximum permitted size of a single incoming Native Messaging message.
// The Native Messaging protocol used by Chrome and Firefox caps messages
// at 1 MB. We enforce the same limit to reject malformed or malicious
// oversized length prefixes.
constexpr uint32_t kMaxMessageBytes = 1024u * 1024u;  // 1 MiB

// Reads one Native Messaging frame from stdin.
// Returns the JSON payload as a string, or nullopt on EOF, I/O error, or
// if the declared length exceeds kMaxMessageBytes.
[[nodiscard]] std::optional<std::string> read_message();

// Writes one Native Messaging frame to stdout.
// stdout must be in binary mode (see _setmode call in main).
void write_message(const nlohmann::json& msg) noexcept;

}  // namespace pwledger

#endif  // PWLEDGER_HOST_NATIVE_MESSAGING_H
