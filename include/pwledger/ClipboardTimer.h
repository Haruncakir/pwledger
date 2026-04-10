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

#ifndef PWLEDGER_CLIPBOARD_TIMER_H
#define PWLEDGER_CLIPBOARD_TIMER_H

#include <pwledger/Clipboard.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <thread>

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// ClipboardTimer provides a fire-and-forget auto-clear mechanism for the
// system clipboard. After a "copy" operation, the caller calls schedule()
// with a delay in seconds. A background thread sleeps for that duration and
// then calls clipboard_clear(). If schedule() is called again before the
// timer fires, the previous timer is cancelled and a new one starts (only
// the most recent copy matters).
//
// THREAD SAFETY
// -------------
// schedule() and cancel() are thread-safe; they may be called from any
// thread. The background thread is joined on destruction.
//
// LIFETIME
// --------
// A single ClipboardTimer instance should be owned by the application's
// top-level state (AppState for the CLI, or the message loop for the native
// host). It is destroyed (and any pending timer cancelled + joined) when the
// owning object goes out of scope.
//
// ============================================================================

namespace pwledger {

class ClipboardTimer {
public:
  ClipboardTimer() = default;

  ~ClipboardTimer() noexcept {
    cancel();
    join();
  }

  // Not copyable or movable (owns a thread and mutex).
  ClipboardTimer(const ClipboardTimer&) = delete;
  ClipboardTimer& operator=(const ClipboardTimer&) = delete;
  ClipboardTimer(ClipboardTimer&&) = delete;
  ClipboardTimer& operator=(ClipboardTimer&&) = delete;

  // Schedule a clipboard clear after `delay_seconds`. If a timer is already
  // pending, it is cancelled and replaced. A delay of 0 means "disabled"
  // (no timer is started).
  void schedule(int delay_seconds) {
    if (delay_seconds <= 0) return;

    cancel();
    join();

    {
      std::lock_guard<std::mutex> lk(mu_);
      cancelled_ = false;
    }

    thread_ = std::thread([this, delay_seconds]() {
      std::unique_lock<std::mutex> lk(mu_);
      bool was_cancelled = cv_.wait_for(
          lk,
          std::chrono::seconds(delay_seconds),
          [this]() { return cancelled_.load(); });

      if (!was_cancelled) {
        // Timer expired without cancellation — clear the clipboard.
        clipboard_clear();
      }
    });
  }

  // Cancel any pending timer. Does not block; call join() afterwards if
  // you need to wait for the thread to finish.
  void cancel() {
    {
      std::lock_guard<std::mutex> lk(mu_);
      cancelled_ = true;
    }
    cv_.notify_all();
  }

private:
  void join() {
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  std::mutex              mu_;
  std::condition_variable cv_;
  std::atomic<bool>       cancelled_{false};
  std::thread             thread_;
};

}  // namespace pwledger

#endif  // PWLEDGER_CLIPBOARD_TIMER_H
