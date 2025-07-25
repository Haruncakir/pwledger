/* Copyright (c) 2025 Harun
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

#ifndef PWLEDGER_TERMINALMANAGER_H
#define PWLEDGER_TERMINALMANAGER_H

#include <concepts>
#include <iostream>
#include <stdexcept>
#include <type_traits>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <termios.h>
#include <unistd.h>
#endif

namespace pwledger {

template <typename T>
concept TerminalManagerDerivable = requires(T t, const T ct) {
  !std::is_copy_constructible_v<T>;
  !std::is_copy_assignable_v<T>;
  !std::is_move_constructible_v<T>;
  !std::is_move_assignable_v<T>;

  { t.configureTerminal() } -> std::same_as<void>;
  { t.restore() } -> std::same_as<void>;
  { ct.isConfigured() } -> std::same_as<bool>;
};

// The TerminalManager class provides cross-platform terminal control for secure input operations.
// When handling sensitive data like passwords, standard terminal behavior can inadvertently
// expose user input through echoing (displaying typed characters) or line buffering
// (waiting for Enter before processing input). These behaviors vary significantly across
// operating systems and terminal implementations, making secure input handling challenging.
//
// This class uses the Resource Acquisition Is Initialization (RAII) pattern to ensure
// terminal settings are automatically restored when the object is destroyed, regardless
// of how the program exits (normal completion or exception).

template <typename Derived>
struct TerminalManager {
  TerminalManager() {
    try {
      static_cast<Derived*>(this)->configureTerminal();
    } catch (const std::exception& e) {
      // if configuration fails, we should still be in a valid state
      // the destructor will handle any partial changes
      std::cerr << "Warning: Failed to configure terminal: " << e.what() << std::endl;
    }
  }

  // automatically restore original terminal settings
  ~TerminalManager() noexcept { static_cast<Derived*>(this)->restore(); }

  // prevent resource duplication
  TerminalManager(const TerminalManager&) = delete;
  TerminalManager(TerminalManager&&) = delete;
  TerminalManager& operator=(const TerminalManager&) = delete;
  TerminalManager& operator=(TerminalManager&&) = delete;

  bool isConfigured() const { return static_cast<Derived*>(this)->isConfigured(); }
};


namespace details {
/**
 * @brief Key features of the input handling.
 *
 * - Disables input echoing to prevent password visibility.
 * - Enables immediate character processing (no line buffering).
 * - Automatically restores original settings on destruction.
 * - Provides cross-platform compatibility for Windows and Unix-like systems.
 */
#ifdef _WIN32
class WinTerminalManager : public TerminalManager<WinTerminalManager> {
public:
  WinTerminalManager(const WinTerminalManager&) = delete;
  WinTerminalManager(WinTerminalManager&&) = delete;
  WinTerminalManager& operator=(const WinTerminalManager&) = delete;
  WinTerminalManager& operator=(WinTerminalManager&&) = delete;
  ~WinTerminalManager() = default;

  void configureTerminal() {
    hStdin_ = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin_ == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("Failed to get standard input handle");
    }
    if (!GetConsoleMode(hStdin_, &originalMode_)) {
      throw std::runtime_error("Failed to get console mode");
    }

    // for secure input: disable echo and line input
    // ENABLE_ECHO_INPUT: prevents typed characters from appearing on screen
    // ENABLE_LINE_INPUT: allows immediate character processing without waiting for Enter
    // see more in table: https://learn.microsoft.com/en-us/windows/console/setconsolemode
    DWORD newMode = originalMode_ & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);

    if (!SetConsoleMode(hStdin_, newMode)) {
      throw std::runtime_error("Failed to set console mode");
    }

    modeChanged_ = true;
  }
  bool isConfigured() const { return modeChanged_; }
  void restore() noexcept {
    try {
      if (modeChanged_ && hStdin_ != INVALID_HANDLE_VALUE) {
        SetConsoleMode(hStdin_, originalMode_);
        modeChanged_ = false;
      }
    } catch (...) {
      // swallow exceptions in destructor to prevent termination for now
      // TODO: log this error
    }
  }

private:
  HANDLE hStdin_;
  DWORD originalMode_;
  bool modeChanged_;
};
static_assert(TerminalManagerDerivable<WinTerminalManager>, "Windows Terminal Manager is not properly defined");
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
class UnixTerminalManager : public TerminalManager<UnixTerminalManager> {
public:
  UnixTerminalManager(const UnixTerminalManager&) = delete;
  UnixTerminalManager(UnixTerminalManager&&) = delete;
  UnixTerminalManager& operator=(const UnixTerminalManager&) = delete;
  UnixTerminalManager& operator=(UnixTerminalManager&&) = delete;
  ~UnixTerminalManager() = default;

  void configureTerminal() {
    if (tcgetattr(STDIN_FILENO, &originalSettings_) != 0) {
      throw std::runtime_error("Failed to get terminal attributes");
    }

    struct termios newSettings = originalSettings_;

    // disable echo and canonical mode
    // ECHO: prevents typed characters from appearing on screen
    // ICANON: disables line buffering, allowing immediate character processing
    // see more in: https://www.man7.org/linux/man-pages/man3/termios.3.html
    // explicit cast is needed for signedness warning
    newSettings.c_lflag &= ~(static_cast<tcflag_t>(ECHO | ICANON));

    // for immediate input processing
    newSettings.c_cc[VMIN] = 1;   // read at least 1 character
    newSettings.c_cc[VTIME] = 0;  // no timeout for character input

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newSettings) != 0) {
      throw std::runtime_error("Failed to set terminal attributes");
    }

    settingsChanged_ = true;
  }
  bool isConfigured() const { return settingsChanged_; }
  void restore() noexcept {
    try {
      if (settingsChanged_) {
        tcsetattr(STDIN_FILENO, TCSANOW, &originalSettings_);
        settingsChanged_ = false;
      }
    } catch (...) {
      // swallow exceptions in destructor to prevent termination for now
      // TODO: log this error
    }
  }

private:
  struct termios originalSettings_ {};
  bool settingsChanged_{false};
};
static_assert(TerminalManagerDerivable<UnixTerminalManager>, "Unix Terminal Manager is not properly defined");
#endif
}  // namespace details

#ifdef _WIN32
using TerminalManager_v = TerminalManager<details::WinTerminalManager>;
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
using TerminalManager_v = TerminalManager<details::UnixTerminalManager>;
#endif

}  // namespace pwledger

#endif  // PWLEDGER_TERMINALMANAGER_H