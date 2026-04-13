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

#include "NativeMessaging.h"

#include <iostream>
#include <bit>

namespace pwledger {

// The length field is read as raw bytes and reinterpreted as uint32_t.
// On all supported platforms (x86, x86-64, ARM) the native byte order is
// little-endian, which matches the Native Messaging specification. A
// static_assert below guards this assumption.
static_assert(
    std::endian::native == std::endian::little,
    "Native Messaging length prefix assumes little-endian byte order. "
    "Add a byte-swap here for big-endian platforms.");

// ----------------------------------------------------------------------------
// read_message
// ----------------------------------------------------------------------------
// Reads one Native Messaging frame from stdin. The frame format is:
//   [uint32_t length (little-endian)] [length bytes of UTF-8 JSON]
[[nodiscard]] std::optional<std::string> read_message() {
  uint32_t length = 0;
  if (!std::cin.read(reinterpret_cast<char*>(&length), sizeof(length))) {
    return std::nullopt;  // EOF or I/O error; caller terminates the loop
  }

  if (length == 0) {
    return std::string{};  // zero-length message is valid (e.g., a ping)
  }

  if (length > kMaxMessageBytes) {
    // Reject without reading the body; the stream is now out of sync.
    // Return nullopt to signal a fatal framing error and terminate.
    std::cerr << "Fatal: incoming message length " << length
              << " exceeds limit " << kMaxMessageBytes << "; terminating\n";
    return std::nullopt;
  }

  std::string payload(length, '\0');
  if (!std::cin.read(payload.data(), length)) {
    return std::nullopt;
  }
  return payload;
}

// ----------------------------------------------------------------------------
// write_message
// ----------------------------------------------------------------------------
// Writes one Native Messaging frame to stdout.
void write_message(const nlohmann::json& msg) noexcept {
  try {
    const std::string payload = msg.dump();

    if (payload.size() > kMaxMessageBytes) {
      // Response too large to send under the protocol limit.
      std::cerr << "Warning: outgoing message too large ("
                << payload.size() << " bytes); sending error response\n";
      write_message({{"status", "error"}, {"message", "Response too large"}});
      return;
    }

    const uint32_t length = static_cast<uint32_t>(payload.size());
    std::cout.write(reinterpret_cast<const char*>(&length), sizeof(length));
    std::cout.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    std::cout.flush();
  } catch (const std::exception& e) {
    // write_message is called from noexcept contexts; swallow and log.
    std::cerr << "Warning: write_message failed: " << e.what() << '\n';
  }
}

}  // namespace pwledger
