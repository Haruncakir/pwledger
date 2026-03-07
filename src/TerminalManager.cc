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

#include <pwledger/TerminalManager.h>

namespace pwledger {

namespace detail {

#ifdef _WIN32

WinTerminalManager::WinTerminalManager() {
  configureTerminal();  // throws on failure; see FAILURE MODEL
}

WinTerminalManager::~WinTerminalManager() noexcept {
  restore();
}

void WinTerminalManager::configureTerminal() {
  hStdin_ = GetStdHandle(STD_INPUT_HANDLE);
  if (hStdin_ == INVALID_HANDLE_VALUE) {
    throw std::runtime_error("Failed to get standard input handle");
  }
  if (!GetConsoleMode(hStdin_, &originalMode_)) {
    throw std::runtime_error("Failed to get console mode");
  }

  // For secure input: disable echo and line input.
  // ENABLE_ECHO_INPUT: prevents typed characters from appearing on screen.
  // ENABLE_LINE_INPUT: disables line buffering, allowing immediate character
  //                    processing without waiting for Enter.
  // See: https://learn.microsoft.com/en-us/windows/console/setconsolemode
  DWORD newMode = originalMode_ & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
  if (!SetConsoleMode(hStdin_, newMode)) {
    throw std::runtime_error("Failed to set console mode");
  }

  modeChanged_ = true;
}

void WinTerminalManager::restore() noexcept {
  if (modeChanged_ && hStdin_ != INVALID_HANDLE_VALUE) {
    // SetConsoleMode is a C API; failures are surfaced via return value.
    // A restore failure is logged but not treated as fatal.
    // TODO(#issue-N): replace with structured logging once available.
    if (!SetConsoleMode(hStdin_, originalMode_)) {
      std::cerr << "Warning: Failed to restore console mode (error " << GetLastError() << ")\n";
    }
    modeChanged_ = false;
  }
}

#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)

UnixTerminalManager::UnixTerminalManager() {
  configureTerminal();  // throws on failure; see FAILURE MODEL
}

UnixTerminalManager::~UnixTerminalManager() noexcept {
  restore();
}

void UnixTerminalManager::configureTerminal() {
  if (tcgetattr(STDIN_FILENO, &originalSettings_) != 0) {
    throw std::runtime_error("Failed to get terminal attributes");
  }

  struct termios newSettings = originalSettings_;

  // Disable echo and canonical mode.
  // ECHO:   prevents typed characters from appearing on screen.
  // ICANON: disables line buffering, allowing immediate character processing
  //         without waiting for Enter.
  // The explicit cast to tcflag_t suppresses a signedness warning on
  // platforms where ECHO | ICANON is computed as a signed int.
  // See: https://www.man7.org/linux/man-pages/man3/termios.3.html
  newSettings.c_lflag &= ~(static_cast<tcflag_t>(ECHO | ICANON));

  // VMIN=1 / VTIME=0: read() blocks until exactly 1 byte is available,
  // then returns immediately with no timeout.
  newSettings.c_cc[VMIN] = 1;
  newSettings.c_cc[VTIME] = 0;

  if (tcsetattr(STDIN_FILENO, TCSANOW, &newSettings) != 0) {
    throw std::runtime_error("Failed to set terminal attributes");
  }

  settingsChanged_ = true;
}

void UnixTerminalManager::restore() noexcept {
  if (settingsChanged_) {
    // tcsetattr is a C function; failures are surfaced via return value.
    //
    // TCSAFLUSH is used rather than TCSANOW: it waits for all pending
    // output to drain and discards any unread input before applying the
    // restored settings. This prevents pending keystrokes that were entered
    // under echo-suppressed settings from being replayed and displayed once
    // echo is re-enabled.
    //
    // A restore failure is logged but not treated as fatal.
    // TODO(#issue-N): replace with structured logging once available.
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &originalSettings_) != 0) {
      std::cerr << "Warning: Failed to restore terminal attributes\n";
    }
    settingsChanged_ = false;
  }
}

#endif  // platform selection

}  // namespace detail

}  // namespace pwledger
