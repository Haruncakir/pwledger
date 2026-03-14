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

#include "SecretIO.h"

#include <pwledger/TerminalManager.h>
#include <pwledger/VaultIO.h>

#include <cstring>
#include <iostream>
#include <stdexcept>

#include <sodium.h>

namespace pwledger {

// ----------------------------------------------------------------------------
// read_secret_from_stdin
// ----------------------------------------------------------------------------
// Reads a secret from stdin with echo disabled. TerminalManager_v suppresses
// echo and canonical mode for the duration of the read and restores terminal
// settings on return or exception (RAII, via TCSAFLUSH which discards any
// buffered keystrokes entered under echo suppression).
//
// The secret is read into `out`, which must have been allocated with at least
// `max_bytes` bytes. Excess input beyond max_bytes - 1 is silently truncated.
// A null terminator is written at buf[written] so the buffer can be passed to
// crypto functions that require a C-string.
//
// Returns the number of bytes written (excluding the null terminator).
std::size_t read_secret_from_stdin(Secret& out, std::size_t max_bytes) {
  if (max_bytes < 2) {
    throw std::invalid_argument("max_bytes must be at least 2");
  }

  TerminalManager_v terminal_guard;

  std::size_t written = 0;
  out.with_write_access([&](std::span<char> buf) {
    sodium_memzero(buf.data(), buf.size());
    // std::cin.get() returns int (to distinguish EOF from valid bytes).
    // The cast to char is intentionally ASCII-only: passwords are sequences
    // of printable ASCII characters for interoperability with the widest
    // set of services. A UTF-8 migration would require:
    //   - reading multi-byte sequences (std::codecvt or ICU)
    //   - NFC normalization (to ensure consistent byte representation)
    //   - updating Secret buffer sizing (multi-byte characters need more space)
    // Until then, the supported input range is [0x20, 0x7E] plus control keys.
    int ch = 0;
    while (written < max_bytes - 1) {
      ch = std::cin.get();
      if (ch == EOF || ch == '\n' || ch == '\r') {
        break;
      }
      buf[written++] = static_cast<char>(ch);
    }
    buf[written] = '\0';
  });

  std::cout << '\n';  // advance past the suppressed newline the user typed
  return written;
}

// ----------------------------------------------------------------------------
// prompt_secret
// ----------------------------------------------------------------------------
// Prints a prompt to stdout, reads a secret from stdin with echo suppressed,
// and optionally asks the user to confirm by entering it a second time.
// Returns the number of bytes written into `out`.
//
// On a confirmation mismatch, throws std::runtime_error. The caller is
// responsible for handling the error and re-prompting if desired.
//
// Comparison is performed with sodium_memcmp (constant-time) to avoid timing
// side-channels on the confirmation check.
std::size_t prompt_secret(std::string_view prompt, Secret& out, std::size_t max_bytes, bool confirm) {
  std::cout << prompt << ": ";
  std::cout.flush();
  std::size_t n = read_secret_from_stdin(out, max_bytes);

  if (!confirm) {
    return n;
  }

  Secret confirm_buf(max_bytes);
  std::cout << "Confirm " << prompt << ": ";
  std::cout.flush();
  std::size_t n2 = read_secret_from_stdin(confirm_buf, max_bytes);

  // The nested with_read_access calls below operate on two *different* Secret
  // objects (out and confirm_buf), so there is no overlapping-guard UB.
  // The ACCESS GUARD RULES in Secret.h prohibit overlapping guards on the
  // *same* Secret; distinct Secrets may be opened concurrently.
  bool match = false;
  out.with_read_access([&](std::span<const char> a) {
    confirm_buf.with_read_access(
        [&](std::span<const char> b) { match = (n == n2) && (sodium_memcmp(a.data(), b.data(), n) == 0); });
  });
  // confirm_buf is destroyed here; sodium_free zeroes its allocation.

  if (!match) {
    throw std::runtime_error("Entries do not match");
  }
  return n;
}

// ----------------------------------------------------------------------------
// save_vault_safe
// ----------------------------------------------------------------------------
// Attempts to save the vault. If it fails, prints the error but does not
// throw, so the command loop can continue.
void save_vault_safe(const AppState& state) {
  try {
    state.master_password.with_read_access([&](std::span<const char> buf) {
      std::size_t len = ::strnlen(buf.data(), buf.size());
      VaultIO::save_vault(state.vault_path, state.table, std::string_view(buf.data(), len));
    });
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to save vault: " << e.what() << '\n';
  }
}

}  // namespace pwledger
