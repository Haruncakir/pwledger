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

#ifndef PWLEDGER_CLI_DISPLAY_H
#define PWLEDGER_CLI_DISPLAY_H

#include <pwledger/PrimaryTable.h>
#include <pwledger/SecretEntry.h>
#include <pwledger/uuid.h>

#include <chrono>
#include <string>

namespace pwledger {

using Uuid = pwledger::Uuid;

// Formats a system_clock time_point as "YYYY-MM-DD HH:MM:SS UTC".
std::string format_timepoint(std::chrono::system_clock::time_point tp);

// Prints a human-readable summary of an entry. The secret value is never
// printed; only its byte length is shown.
void print_entry(const Uuid& uuid, const SecretEntry& entry);

// Lists all entries. Only non-sensitive fields are shown.
void print_table(const PrimaryTable& table);

}  // namespace pwledger

#endif  // PWLEDGER_CLI_DISPLAY_H
