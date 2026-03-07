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

#ifndef PWLEDGER_CLIPBOARD_H
#define PWLEDGER_CLIPBOARD_H

#include <pwledger/SecretEntry.h>

#include <cstring>
#include <iostream>
#include <string_view>

namespace pwledger {

// ============================================================================
// Clipboard management
// ============================================================================
//
// Best-effort clipboard write and clear. Failures are logged to stderr but
// are not fatal: the user can always read the secret from terminal output.
// Clipboard operations are inherently insecure (other processes can read the
// clipboard); this is a usability concession.
//
// TODO(#issue-N): enforce auto-clear after a configurable timeout.

namespace detail {

void clipboard_write(std::string_view text);
void clipboard_clear();

}  // namespace detail

// ----------------------------------------------------------------------------
// clipboard_copy_secret
// ----------------------------------------------------------------------------
// Copies the entry's secret to the clipboard via a scoped read guard.
// The actual secret length is determined from the null terminator written
// by read_secret_from_stdin rather than from the full buffer allocation.
void clipboard_copy_secret(const SecretEntry& entry);

// ----------------------------------------------------------------------------
// clipboard_clear_secret
// ----------------------------------------------------------------------------
// Overwrites the clipboard with an empty string.
void clipboard_clear_secret();

}  // namespace pwledger

#endif  // PWLEDGER_CLIPBOARD_H
