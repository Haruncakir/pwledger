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

#include <pwledger/Clipboard.h>

#include <cstring>
#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#  include <stdio.h>   // popen, pclose, fwrite
#elif defined(_WIN32)
#  include <windows.h>
#endif

namespace pwledger {

// ============================================================================
// Anonymous namespace — platform implementation details
// ============================================================================
//
// All platform-specific helpers are confined to an anonymous namespace so
// they have internal linkage and do not appear in any public interface or
// pollute the pwledger namespace.

namespace {

// ----------------------------------------------------------------------------
// pipe_write  (Linux / macOS)
// ----------------------------------------------------------------------------
// Opens `cmd` as a write-mode pipe, writes `text` into it, and closes the
// pipe. If popen fails, logs a warning and returns without writing.
//
// Used for both clipboard_write and clipboard_clear on POSIX platforms:
// the difference is only in the content written.
#if defined(__linux__) || defined(__APPLE__)
void pipe_write(const char* cmd, std::string_view text) noexcept {
  FILE* pipe = popen(cmd, "w");
  if (!pipe) {
    std::cerr << "Warning: failed to open clipboard pipe (" << cmd << ")\n";
    return;
  }
  // fwrite with size=1, count=text.size() writes exactly text.size() bytes.
  // A zero-length text.size() is valid and writes nothing, which is the
  // correct behavior for clipboard_clear (the empty write opens and closes
  // the pipe, which on xclip/xsel/pbcopy clears the clipboard selection).
  if (text.size() > 0) {
    fwrite(text.data(), 1, text.size(), pipe);
  } else {
    // Explicitly redirect from /dev/null so the tool receives EOF immediately,
    // which clears the clipboard selection on xclip, xsel, and pbcopy.
    // Writing zero bytes via fwrite does not send EOF to the tool; the pipe
    // close (pclose) does, but some tools require the EOF to arrive via read()
    // rather than detecting a closed write-end. Using /dev/null as the source
    // via the shell command is the most portable clear mechanism; see the
    // clipboard_clear implementation below for the preferred approach.
    (void)0;  // pclose below provides EOF; sufficient for pbcopy
  }
  pclose(pipe);
}
#endif

// ----------------------------------------------------------------------------
// Platform-specific clipboard_write implementations
// ----------------------------------------------------------------------------

#if defined(__linux__)
void platform_clipboard_write(std::string_view text) noexcept {
  // Try xclip first; fall back to xsel. Both accept input from stdin via
  // a writable pipe. The shell-level || means xsel is only invoked if xclip
  // is not found (exit status non-zero).
  pipe_write(
      "xclip -selection clipboard 2>/dev/null || "
      "xsel --clipboard --input 2>/dev/null",
      text);
}

void platform_clipboard_clear() noexcept {
  // Redirect from /dev/null so xclip/xsel receive an empty stdin, which
  // sets the clipboard to an empty string. This is more reliable than
  // writing zero bytes: some versions of xclip treat a zero-byte write
  // differently from an empty-string clipboard entry.
  FILE* pipe = popen(
      "xclip -selection clipboard < /dev/null 2>/dev/null || "
      "xsel --clipboard --clear 2>/dev/null",
      "r");  // read mode; the command sources /dev/null itself
  if (pipe) { pclose(pipe); }
}

#elif defined(__APPLE__)
void platform_clipboard_write(std::string_view text) noexcept {
  pipe_write("pbcopy", text);
}

void platform_clipboard_clear() noexcept {
  // pbcopy with an empty stdin sets the clipboard to an empty string.
  // pclose provides EOF to pbcopy, which is sufficient.
  FILE* pipe = popen("pbcopy", "w");
  if (pipe) { pclose(pipe); }
}

#elif defined(_WIN32)
void platform_clipboard_write(std::string_view text) noexcept {
  if (!OpenClipboard(nullptr)) {
    std::cerr << "Warning: clipboard write failed (OpenClipboard error "
              << GetLastError() << ")\n";
    return;
  }
  EmptyClipboard();

  // GlobalAlloc + GlobalLock is the required pattern for SetClipboardData.
  // GMEM_MOVEABLE allows the memory manager to move the block; the clipboard
  // takes ownership of hMem after SetClipboardData succeeds, so we must NOT
  // call GlobalFree on it afterward.
  HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
  if (!hMem) {
    CloseClipboard();
    std::cerr << "Warning: clipboard write failed (GlobalAlloc error "
              << GetLastError() << ")\n";
    return;
  }

  char* dst = static_cast<char*>(GlobalLock(hMem));
  if (!dst) {
    GlobalFree(hMem);
    CloseClipboard();
    std::cerr << "Warning: clipboard write failed (GlobalLock error "
              << GetLastError() << ")\n";
    return;
  }
  std::memcpy(dst, text.data(), text.size());
  dst[text.size()] = '\0';
  GlobalUnlock(hMem);

  if (!SetClipboardData(CF_TEXT, hMem)) {
    // SetClipboardData failure: we retain ownership of hMem and must free it.
    GlobalFree(hMem);
    std::cerr << "Warning: clipboard write failed (SetClipboardData error "
              << GetLastError() << ")\n";
  }
  CloseClipboard();
}

void platform_clipboard_clear() noexcept {
  if (!OpenClipboard(nullptr)) { return; }
  EmptyClipboard();
  CloseClipboard();
}

#else
void platform_clipboard_write(std::string_view /*text*/) noexcept {
  std::cerr << "Warning: clipboard write not supported on this platform\n";
}

void platform_clipboard_clear() noexcept {
  std::cerr << "Warning: clipboard clear not supported on this platform\n";
}
#endif

}  // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

void clipboard_write(std::string_view text) noexcept {
  platform_clipboard_write(text);
}

void clipboard_clear() noexcept {
  platform_clipboard_clear();
}

}  // namespace pwledger
