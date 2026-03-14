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

#include "Display.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace pwledger {

// ----------------------------------------------------------------------------
// format_timepoint
// ----------------------------------------------------------------------------
// Formats a system_clock time_point as "YYYY-MM-DD HH:MM:SS UTC".
std::string format_timepoint(std::chrono::system_clock::time_point tp) {
  std::time_t t = std::chrono::system_clock::to_time_t(tp);
  std::tm tm = {};
#ifdef _WIN32
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S UTC");
  return oss.str();
}

// ----------------------------------------------------------------------------
// print_entry
// ----------------------------------------------------------------------------
// Prints a human-readable summary of an entry. The secret value is never
// printed; only its byte length is shown so the user can verify it is
// non-empty without exposing the content.
void print_entry(const Uuid& uuid, const SecretEntry& entry) {
  std::size_t secret_len = 0;
  entry.plaintext_secret.with_read_access(
      [&](std::span<const char> buf) { secret_len = ::strnlen(buf.data(), buf.size()); });

  std::cout << "UUID            : " << uuid << '\n'
            << "Primary key     : " << entry.primary_key << '\n'
            << "Username/email  : " << entry.username_or_email << '\n'
            << "Secret length   : " << secret_len << " characters" << '\n'
            << "2FA enabled     : " << (entry.security_policy.two_fa_enabled ? "yes" : "no") << '\n'
            << "Strength score  : " << entry.security_policy.strength_score << '\n'
            << "Expires         : "
            << (entry.security_policy.expires_at.has_value() ? format_timepoint(*entry.security_policy.expires_at)
                                                             : "never")
            << '\n'
            << "Created         : " << format_timepoint(entry.metadata.created_at) << '\n'
            << "Last modified   : " << format_timepoint(entry.metadata.last_modified_at) << '\n'
            << "Last used       : " << format_timepoint(entry.metadata.last_used_at) << '\n';

  if (!entry.security_policy.note.empty()) {
    std::cout << "Note            : " << entry.security_policy.note << '\n';
  }
}

// ----------------------------------------------------------------------------
// print_table
// ----------------------------------------------------------------------------
// Lists all entries. Only non-sensitive fields are shown.
void print_table(const PrimaryTable& table) {
  if (table.empty()) {
    std::cout << "(no entries)\n";
    return;
  }
  for (const auto& [uuid, entry] : table) {
    std::cout << "----\n";
    print_entry(uuid, entry);
  }
  std::cout << "----\n";
}

}  // namespace pwledger
