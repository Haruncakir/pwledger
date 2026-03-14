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

#ifndef PWLEDGER_CLI_SECRET_IO_H
#define PWLEDGER_CLI_SECRET_IO_H

#include "AppState.h"

#include <pwledger/Secret.h>

#include <cstddef>
#include <string_view>

namespace pwledger {

// Reads a secret from stdin with echo disabled. Returns the number of bytes
// written (excluding the null terminator).
std::size_t read_secret_from_stdin(Secret& out, std::size_t max_bytes);

// Prints a prompt, reads a secret with echo suppressed, and optionally
// confirms by asking the user to enter it a second time. Throws
// std::runtime_error on confirmation mismatch.
std::size_t prompt_secret(std::string_view prompt, Secret& out, std::size_t max_bytes, bool confirm = false);

// Attempts to save the vault. Prints a warning on failure but does not throw.
void save_vault_safe(const AppState& state);

}  // namespace pwledger

#endif  // PWLEDGER_CLI_SECRET_IO_H
