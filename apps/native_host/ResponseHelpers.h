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

#ifndef PWLEDGER_HOST_RESPONSE_HELPERS_H
#define PWLEDGER_HOST_RESPONSE_HELPERS_H

#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace pwledger {

// All responses follow a consistent shape:
//   { "status": "ok" | "error", ["id": ...,] ["message": "...",] [...] }

[[nodiscard]] inline nlohmann::json make_error(std::string_view message,
                                               std::optional<nlohmann::json> id = std::nullopt) {
  nlohmann::json r = {{"status", "error"}, {"message", std::string(message)}};
  if (id.has_value()) { r["id"] = *id; }
  return r;
}

[[nodiscard]] inline nlohmann::json make_ok(std::optional<nlohmann::json> id = std::nullopt) {
  nlohmann::json r = {{"status", "ok"}};
  if (id.has_value()) { r["id"] = *id; }
  return r;
}

}  // namespace pwledger

#endif  // PWLEDGER_HOST_RESPONSE_HELPERS_H
