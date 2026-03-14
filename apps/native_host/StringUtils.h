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

#ifndef PWLEDGER_HOST_STRING_UTILS_H
#define PWLEDGER_HOST_STRING_UTILS_H

#include <algorithm>
#include <cctype>
#include <string_view>

namespace pwledger {

// Case-insensitive substring search. Both haystack and needle are converted
// to lowercase for comparison. This is ASCII-only; non-ASCII characters are
// passed through unchanged (acceptable for URL/domain/email matching).
[[nodiscard]] inline bool icontains(std::string_view haystack,
                                    std::string_view needle) noexcept {
  if (needle.empty()) { return true; }
  if (needle.size() > haystack.size()) { return false; }

  auto to_lower = [](unsigned char c) { return std::tolower(c); };

  return std::search(
      haystack.begin(), haystack.end(),
      needle.begin(),   needle.end(),
      [&](unsigned char a, unsigned char b) {
          return to_lower(a) == to_lower(b);
      }) != haystack.end();
}

}  // namespace pwledger

#endif  // PWLEDGER_HOST_STRING_UTILS_H
