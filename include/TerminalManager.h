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

#ifndef PWLEDGER_TERMINALMANAGER_H
#define PWLEDGER_TERMINALMANAGER_H

#include <concepts>
#include <iostream>
#include <stdexcept>
#include <type_traits>

#ifdef _WIN32
#  include <io.h>
#  include <windows.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#  include <termios.h>
#  include <unistd.h>
#endif

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This header provides cross-platform terminal control for secure input
// operations (passwords, PINs, sensitive prompts). Standard terminal behavior
// can inadvertently expose user input through:
//   - Echo: displaying typed characters on screen as they are entered.
//   - Canonical (line-buffered) mode: buffering input until Enter is pressed,
//     which may trigger intermediate flushes or logging.
//
// These behaviors vary significantly across operating systems and terminal
// implementations, making secure input handling non-trivial to write portably.
//
// DESIGN: CRTP (Curiously Recurring Template Pattern)
// ----------------------------------------------------
// TerminalManager<Derived> is a non-polymorphic CRTP base. It enforces the
// non-copyable / non-movable contract and documents the required interface via
// the TerminalManagerDerivable concept. Concrete implementations live in the
// detail namespace and are selected via a platform alias (TerminalManager_v).
//
// RAII GUARANTEE
// --------------
// Terminal settings are restored in the concrete destructor regardless of how
// the scope is exited (normal return or exception). The base destructor is
// intentionally trivial (= default) and does NOT call restore(). This is
// because base destructors run *after* the derived object's members are
// already destroyed. Calling restore() from the base destructor would access
// destroyed data (hStdin_, originalSettings_, etc.), which is undefined
// behavior. Each concrete class is responsible for calling restore() in its
// own destructor.
//
// FAILURE MODEL
// -------------
// configureTerminal() throws std::runtime_error on failure. The exception is
// NOT caught or swallowed by the base constructor — it propagates to the
// caller. This is deliberate: a caller who wants to tolerate a terminal
// configuration failure can catch it themselves and check isConfigured().
// Swallowing it in the base would force every caller to check isConfigured()
// after construction to detect a silent failure, which no one will reliably do.
//
// restore() is noexcept and best-effort. The underlying C functions
// (tcsetattr, SetConsoleMode) do not throw; they return error codes. A failure
// in restore() is logged to stderr if possible but does not abort, because
// a partially-restored terminal is better than a crash during stack unwinding.
//
// THREAD SAFETY
// -------------
// TerminalManager and its derived classes are NOT thread-safe. Only one
// instance should be active at a time per process, as terminal attributes
// are process-global state.
//
// ============================================================================

namespace pwledger {

// ----------------------------------------------------------------------------
// TerminalManagerDerivable concept
// ----------------------------------------------------------------------------
// Enforces the interface contract for CRTP derived classes at compile time.
//
// IMPORTANT: The original implementation placed the trait checks
// (!std::is_copy_constructible_v<T>, etc.) inside a requires{} expression
// block. That is incorrect: a requires{} block tests whether expressions are
// *syntactically well-formed*, not whether they evaluate to true. A bare bool
// expression like `!std::is_copy_constructible_v<T>` is always syntactically
// valid regardless of the actual trait value, so the concept was vacuously
// satisfied by every type. The trait checks must appear as top-level
// conjuncts (&&) outside the requires{} block to be evaluated correctly.
template <typename T>
concept TerminalManagerDerivable =
    !std::is_copy_constructible_v<T>  &&
    !std::is_copy_assignable_v<T>     &&
    !std::is_move_constructible_v<T>  &&
    !std::is_move_assignable_v<T>     &&
    requires(T t, const T ct) {
        { t.configureTerminal() } -> std::same_as<void>;
        { t.restore()           } -> std::same_as<void>;
        { ct.isConfigured()     } -> std::same_as<bool>;
    };

// ----------------------------------------------------------------------------
// TerminalManager<Derived> — CRTP base
// ----------------------------------------------------------------------------
// The TerminalManager class provides cross-platform terminal control for
// secure input operations. When handling sensitive data like passwords,
// standard terminal behavior can inadvertently expose user input through
// echoing (displaying typed characters) or line buffering (waiting for Enter
// before processing input). These behaviors vary significantly across
// operating systems and terminal implementations, making secure input
// handling challenging.
//
// This class uses the Resource Acquisition Is Initialization (RAII) pattern
// to ensure terminal settings are automatically restored when the object is
// destroyed, regardless of how the program exits (normal completion or
// exception). See "RAII GUARANTEE" in the file header for why restore() is
// NOT called from this base destructor.
//
// The base does NOT provide isConfigured(). Derived classes must implement it.
// If a derived class omits it, the TerminalManagerDerivable concept and the
// static_assert in the detail namespace will produce a compile-time error.
// There is no fallback in the base to avoid the infinite-recursion trap where
// a missing derived override causes the base to call itself.
template <typename Derived>
struct TerminalManager {
  // configureTerminal() is called by the derived class constructor, not here.
  // See "FAILURE MODEL" in the file header for why exceptions must propagate.
  TerminalManager()  = default;

  // Trivial. restore() is intentionally NOT called here.
  // See "RAII GUARANTEE" in the file header.
  ~TerminalManager() noexcept = default;

  // Prevent resource duplication. Terminal attributes are process-global
  // state; two live managers would fight over the same settings.
  // Derived classes inherit these deletions and do not need to re-declare them.
  TerminalManager(const TerminalManager&)            = delete;
  TerminalManager(TerminalManager&&)                 = delete;
  TerminalManager& operator=(const TerminalManager&) = delete;
  TerminalManager& operator=(TerminalManager&&)      = delete;
};

// ----------------------------------------------------------------------------
// detail namespace
// ----------------------------------------------------------------------------
// Platform-specific implementations. "detail" (singular) follows the
// convention used in Abseil, Folly, libc++, and libstdc++.
namespace detail {

// ----------------------------------------------------------------------------
// Key features of the input handling (both platforms):
//
//   - Disables input echoing to prevent password visibility.
//   - Enables immediate character processing (no line buffering / canonical
//     mode), so each keystroke is available without waiting for Enter.
//   - Automatically restores original settings on destruction via RAII.
//   - Provides cross-platform compatibility for Windows and Unix-like systems.
// ----------------------------------------------------------------------------

#ifdef _WIN32

// --------------------------------------------------------------------------
// WinTerminalManager
// --------------------------------------------------------------------------
class WinTerminalManager : public TerminalManager<WinTerminalManager> {
public:
  // Members are initialized to safe sentinel values so that restore() is
  // always safe to call, even if configureTerminal() throws before assigning
  // them. The original code left hStdin_ and originalMode_ uninitialized,
  // which meant restore() could read garbage on a partial-construction throw.
  WinTerminalManager() {
    configureTerminal();  // throws on failure; see FAILURE MODEL
  }

  // restore() must be called from the concrete destructor, not the base.
  // See "RAII GUARANTEE" in the file header.
  ~WinTerminalManager() noexcept { restore(); }

  // Inherited from base: copy and move are deleted. Re-declaring them here
  // is redundant and adds noise; the base deletions are sufficient.

  void configureTerminal() {
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

  [[nodiscard]] bool isConfigured() const noexcept { return modeChanged_; }

  void restore() noexcept {
    if (modeChanged_ && hStdin_ != INVALID_HANDLE_VALUE) {
      // SetConsoleMode is a C API and does not throw. The original code
      // wrapped this in try/catch, which silently discarded the only signal
      // of failure: the return value. We check it and log to stderr instead.
      // A restore failure is logged but not aborted — a partially-restored
      // terminal is preferable to a crash during stack unwinding.
      if (!SetConsoleMode(hStdin_, originalMode_)) {
        // TODO(#issue-N): replace with structured logging once available.
        std::cerr << "Warning: Failed to restore console mode (error "
                  << GetLastError() << ")\n";
      }
      modeChanged_ = false;
    }
  }

private:
  HANDLE hStdin_       = INVALID_HANDLE_VALUE;
  DWORD  originalMode_ = 0;
  bool   modeChanged_  = false;
};

static_assert(TerminalManagerDerivable<WinTerminalManager>,
              "WinTerminalManager does not satisfy TerminalManagerDerivable. "
              "Ensure configureTerminal(), restore(), and isConfigured() are "
              "correctly defined, and that copy/move operations are deleted.");

#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)

// --------------------------------------------------------------------------
// UnixTerminalManager
// --------------------------------------------------------------------------
class UnixTerminalManager : public TerminalManager<UnixTerminalManager> {
public:
  UnixTerminalManager() {
    configureTerminal();  // throws on failure; see FAILURE MODEL
  }

  // restore() must be called from the concrete destructor, not the base.
  // See "RAII GUARANTEE" in the file header.
  ~UnixTerminalManager() noexcept { restore(); }

  // Inherited from base: copy and move are deleted. Re-declaring them here
  // is redundant and adds noise; the base deletions are sufficient.

  void configureTerminal() {
    if (tcgetattr(STDIN_FILENO, &originalSettings_) != 0) {
      throw std::runtime_error("Failed to get terminal attributes");
    }

    struct termios newSettings = originalSettings_;

    // Disable echo and canonical mode.
    // ECHO:   prevents typed characters from appearing on screen.
    // ICANON: disables line buffering, allowing immediate character processing
    //         without waiting for Enter (canonical mode).
    // The explicit cast to tcflag_t is required to suppress a signedness
    // warning on platforms where ECHO | ICANON is computed as signed int.
    // See: https://www.man7.org/linux/man-pages/man3/termios.3.html
    newSettings.c_lflag &= ~(static_cast<tcflag_t>(ECHO | ICANON));

    // For immediate input processing: require at least 1 character with no
    // timeout. VMIN=1 / VTIME=0 means read() blocks until exactly 1 byte is
    // available, then returns immediately.
    newSettings.c_cc[VMIN]  = 1;
    newSettings.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newSettings) != 0) {
      throw std::runtime_error("Failed to set terminal attributes");
    }

    settingsChanged_ = true;
  }

  [[nodiscard]] bool isConfigured() const noexcept { return settingsChanged_; }

  void restore() noexcept {
    if (settingsChanged_) {
      // tcsetattr is a C function and does not throw. The original code
      // wrapped this in try/catch, which silently discarded the only signal
      // of failure: the return value. We check it and log to stderr instead.
      //
      // TCSAFLUSH is used here instead of TCSANOW. TCSAFLUSH waits for all
      // pending output to be transmitted and discards any unread input before
      // applying the settings. This avoids partial terminal state when
      // restoring: e.g., pending echo-suppressed keystrokes that the old
      // settings would have handled are discarded rather than replayed under
      // the restored (echo-enabled) settings, which could expose them.
      if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &originalSettings_) != 0) {
        // TODO(#issue-N): replace with structured logging once available.
        std::cerr << "Warning: Failed to restore terminal attributes\n";
      }
      settingsChanged_ = false;
    }
  }

private:
  struct termios originalSettings_ {};  // zero-initialized sentinel
  bool           settingsChanged_  = false;
};

static_assert(TerminalManagerDerivable<UnixTerminalManager>,
              "UnixTerminalManager does not satisfy TerminalManagerDerivable. "
              "Ensure configureTerminal(), restore(), and isConfigured() are "
              "correctly defined, and that copy/move operations are deleted.");

#endif  // platform selection

}  // namespace detail

// ----------------------------------------------------------------------------
// TerminalManager_v — platform alias
// ----------------------------------------------------------------------------
// Resolves to the concrete platform implementation, not the CRTP base.
//
// The original code aliased TerminalManager<details::WinTerminalManager>
// (the base), which meant constructing TerminalManager_v called
// static_cast<Derived*>(this)->configureTerminal() on a base object, not a
// WinTerminalManager — undefined behavior. The alias must name the concrete
// class so that construction, destruction, and CRTP dispatch all operate on
// a complete object.
#ifdef _WIN32
using TerminalManager_v = detail::WinTerminalManager;
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
using TerminalManager_v = detail::UnixTerminalManager;
#endif

}  // namespace pwledger

#endif  // PWLEDGER_TERMINALMANAGER_H
