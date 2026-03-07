#include <pwledger/Clipboard.h>
#include <pwledger/SecretEntry.h>

#include <cstring>
#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <stdio.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace pwledger {

namespace detail {

void clipboard_write(std::string_view text) {
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

void clipboard_clear() {
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

void clipboard_copy_secret(const SecretEntry& entry) {
  entry.plaintext_secret.with_read_access([](std::span<const char> buf) {
    std::size_t len = ::strnlen(buf.data(), buf.size());
    detail::clipboard_write(std::string_view(buf.data(), len));
  });
  std::cout << "Secret copied to clipboard. "
               "Run 'clip-clear' when done.\n";
}

void clipboard_clear_secret() {
  detail::clipboard_clear();
  std::cout << "Clipboard cleared.\n";
}

}  // namespace pwledger
