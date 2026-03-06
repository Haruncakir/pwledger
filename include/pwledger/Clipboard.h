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

inline void clipboard_write(std::string_view text) {
#if defined(__linux__)
  // Use xclip if available, fall back to xsel. Both read from stdin.
  FILE* pipe = popen(
      "xclip -selection clipboard 2>/dev/null || "
      "xsel --clipboard --input 2>/dev/null",
      "w");
  if (!pipe) {
    std::cerr << "Warning: clipboard write failed "
                 "(xclip or xsel not found)\n";
    return;
  }
  fwrite(text.data(), 1, text.size(), pipe);
  pclose(pipe);
#elif defined(__APPLE__)
  FILE* pipe = popen("pbcopy", "w");
  if (!pipe) {
    std::cerr << "Warning: clipboard write failed (pbcopy unavailable)\n";
    return;
  }
  fwrite(text.data(), 1, text.size(), pipe);
  pclose(pipe);
#elif defined(_WIN32)
  if (!OpenClipboard(nullptr)) {
    std::cerr << "Warning: clipboard write failed (OpenClipboard)\n";
    return;
  }
  EmptyClipboard();
  // Allocate global memory for the text (+1 for null terminator).
  HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
  if (!hMem) {
    CloseClipboard();
    std::cerr << "Warning: clipboard write failed (GlobalAlloc)\n";
    return;
  }
  char* dst = static_cast<char*>(GlobalLock(hMem));
  std::memcpy(dst, text.data(), text.size());
  dst[text.size()] = '\0';
  GlobalUnlock(hMem);
  SetClipboardData(CF_TEXT, hMem);
  CloseClipboard();
#else
  (void)text;
  std::cerr << "Warning: clipboard write not supported on this platform\n";
#endif
}

inline void clipboard_clear() {
#if defined(__linux__)
  FILE* pipe = popen(
      "xclip -selection clipboard 2>/dev/null || "
      "xsel --clipboard --input 2>/dev/null",
      "w");
  if (pipe) {
    fwrite("", 1, 0, pipe);
    pclose(pipe);
  }
#elif defined(__APPLE__)
  FILE* pipe = popen("pbcopy", "w");
  if (pipe) {
    fwrite("", 1, 0, pipe);
    pclose(pipe);
  }
#elif defined(_WIN32)
  if (OpenClipboard(nullptr)) {
    EmptyClipboard();
    CloseClipboard();
  }
#endif
}

}  // namespace detail

// ----------------------------------------------------------------------------
// clipboard_copy_secret
// ----------------------------------------------------------------------------
// Copies the entry's secret to the clipboard via a scoped read guard.
// The actual secret length is determined from the null terminator written
// by read_secret_from_stdin rather than from the full buffer allocation.
inline void clipboard_copy_secret(const SecretEntry& entry) {
  entry.plaintext_secret.with_read_access([](std::span<const char> buf) {
    std::size_t len = ::strnlen(buf.data(), buf.size());
    detail::clipboard_write(std::string_view(buf.data(), len));
  });
  std::cout << "Secret copied to clipboard. "
               "Run 'clip-clear' when done.\n";
}

// ----------------------------------------------------------------------------
// clipboard_clear_secret
// ----------------------------------------------------------------------------
// Overwrites the clipboard with an empty string.
inline void clipboard_clear_secret() {
  detail::clipboard_clear();
  std::cout << "Clipboard cleared.\n";
}

}  // namespace pwledger

#endif  // PWLEDGER_CLIPBOARD_H
