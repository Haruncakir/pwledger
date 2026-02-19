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

#ifndef PWLEDGER_SECRET_H
#define PWLEDGER_SECRET_H

#include <atomic>
#include <cassert>
#include <cstddef>
#include <span>
#include <sodium.h>

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This header provides Secret, a RAII container for sensitive byte buffers
// (passwords, private keys, API tokens, etc.) backed by libsodium's
// hardened allocator. The guiding invariants are:
//
//   1. Single ownership: no copies. Move invalidates the source.
//   2. All sensitive bytes live in sodium-secured memory at all times.
//   3. No implicit conversions, no stream operators, no accidental formatting.
//   4. Allocation failure is fatal (fail-fast). See "Failure Model" below.
//   5. Partial construction never leaks memory.
//   6. Memory is always in NOACCESS state except inside an active access guard.
//
// FAILURE MODEL
// -------------
// sodium_malloc and sodium_mprotect_* failures call std::abort(). This is a
// deliberate "fail fast" policy: a failure here means either the system is
// severely out of resources or memory protection has been tampered with.
// Continuing in either case risks silent exposure of secrets, which is worse
// than crashing. This mirrors the policy used in BoringSSL and libsodium
// itself for critical allocation paths.
//
// THREAD SAFETY
// -------------
// Secret and its access guards are NOT thread-safe. External synchronization
// is required if a Secret is shared across threads. Accessing the same Secret
// from multiple threads without synchronization is undefined behavior.
//
// KNOWN LIMITATIONS (OS-LEVEL)
// -----------------------------
// Even with sodium_malloc and mprotect, the following remain outside our
// control at the application layer:
//   - The OS may still snapshot process memory (e.g., for checkpoint/restore).
//   - Crash dumps (core files) may contain secrets.
//     Mitigate on Linux:  prctl(PR_SET_DUMPABLE, 0);   // <sys/prctl.h>
//     Mitigate with:      setrlimit(RLIMIT_CORE, {0,0}); // <sys/resource.h>
//     Note: prctl must be called before any Secret is constructed.
//   - Debuggers see everything.
//     Partial mitigations (all easily bypassed by a determined attacker,
//     but useful to detect accidental debugging and fail fast in production):
//       Linux:   prctl(PR_SET_DUMPABLE, 0);
//       macOS:   enable Hardened Runtime; disable the debugger entitlement.
//       Windows: IsDebuggerPresent, CheckRemoteDebuggerPresent.
//
// MINIMIZE TIME-IN-MEMORY
// -----------------------
// Prefer scoped lifetimes. Bad pattern:
//
//   Secret pwd = read_password();
//   ... lots of unrelated code ...
//   authenticate(pwd);
//
// Good pattern:
//
//   with_secret_from_input([](Secret& pwd) {
//       authenticate(pwd);
//   });
//
// ACCESS GUARD RULES (read carefully)
// ------------------------------------
// Access guards MUST NOT outlive the Secret they reference. Example of
// undefined behavior the compiler will NOT catch:
//
//   Secret_readaccess r(secret);      // OK
//   secret = Secret(32);              // moves, frees old memory
//   r.get();                          // !! dangling reference -> UB
//
// Nested / overlapping guards on the same Secret are undefined behavior
// because the inner guard's constructor silently overrides the outer guard's
// mprotect state, and both destructors will attempt to re-lock:
//
//   Secret_readaccess r(secret);
//   Secret_writeaccess w(secret);     // overrides r's protection level
//   // w destructor re-locks -> OK
//   // r destructor re-locks -> also OK *by accident*, but semantics are wrong
//
// The preferred API is with_read_access / with_write_access (below), which
// enforces single-guard-at-a-time through scope and makes nesting visually
// obvious. Use the raw guard constructors only when the RAII lambda style is
// genuinely impractical.
//
// In debug builds, an atomic access counter detects overlapping guards and
// aborts with a diagnostic message.
//
// ============================================================================

namespace pwledger {

// ----------------------------------------------------------------------------
// SecureAllocator (CRTP interface stub)
// ----------------------------------------------------------------------------
// TODO(#issue-N): This stub exists to enforce usage of safe alternatives to
// malloc/memzero at the allocator layer (e.g., a SecureCharAllocator for
// std::basic_string). It is intentionally incomplete: std::string with a
// custom allocator still does not fully solve the problem because:
//   - std::string may make hidden internal copies during operations.
//   - Small String Optimization (SSO) stores short strings inline inside the
//     object itself; the custom allocator never sees that data, so it cannot
//     zero it on destruction.
// Until a satisfactory design is found, prefer Secret for all sensitive data.
// Do not add new users of this template until the above issues are resolved.
template <class Derived>
struct SecureAllocator {};

// ----------------------------------------------------------------------------
// Secret
// ----------------------------------------------------------------------------
// std::string is unsafe for sensitive data for several reasons:
//   - It does not zero memory on destruction or reassignment; it simply marks
//     the region as available for reuse. Sensitive bytes linger.
//   - That memory can be paged to swap (and therefore to disk, which is
//     non-volatile storage), where it may persist indefinitely.
//   - SSO may store short values on the stack or inside the object, bypassing
//     any custom allocator entirely.
//   - Copies are made implicitly by many std::string operations.
//
// Secret avoids all of these by:
//   - Allocating via sodium_malloc, which uses mlock, guard pages, and
//     canaries to harden the allocation.
//   - Keeping the buffer in NOACCESS state (hardware-enforced) at all times
//     except inside an active access guard.
//   - Disabling copy construction and copy assignment entirely.
//   - Zeroing and freeing via sodium_free on destruction (sodium_free
//     internally calls sodium_memzero before releasing the page).
class Secret {
public:
  // -- Forward declarations for access guard friends --------------------------
  // Secret_readaccess and Secret_writeaccess are granted friendship to access
  // the raw pointer and size, but their public constructors are the only
  // intended way to open a window into Secret's memory.
  // See "ACCESS GUARD RULES" in the file header before using them directly.
  friend class details::Secret_readaccess;
  friend class details::Secret_writeaccess;

  // -- Construction -----------------------------------------------------------
  //
  // Default construction is intentionally deleted. A zero-size Secret has no
  // valid use and would cause sodium_malloc(0) which is implementation-defined.
  // Wrapping an unconstructed Secret directly in an access guard would also
  // segfault (null pointer to mprotect). Named construction via Secret(size)
  // makes the intent explicit at every call site.
  //
  // If a "not-yet-allocated" state is needed in the future, use
  // std::optional<Secret> at the call site instead of adding a default ctor.
  Secret() = delete;

  // Allocates `size` bytes of sodium-hardened memory and immediately places
  // the buffer in NOACCESS state. Aborts on allocation failure (see FAILURE
  // MODEL in file header).
  explicit Secret(std::size_t size) { allocate(size); }

  // -- Destruction ------------------------------------------------------------
  // sodium_free internally calls sodium_memzero before releasing the page,
  // so wipe_and_free() does not need to call sodium_memzero separately.
  // The name "wipe_and_free" is kept to document intent at the call site;
  // the actual zeroing is guaranteed by sodium_free.
  ~Secret() noexcept { wipe_and_free(); }

  // -- Move semantics ---------------------------------------------------------
  // Move transfers ownership. The source is left in a valid but empty state
  // (null pointer, zero size). Any access guard holding a reference to the
  // *source* after a move is a dangling reference (see ACCESS GUARD RULES).
  Secret(Secret&& other) noexcept
    : data_(other.data_),
      size_(other.size_)
  {
    other.data_ = nullptr;
    other.size_ = 0;
#ifndef NDEBUG
    // The source's access_count should be 0; if it isn't, a guard is alive
    // concurrently with a move, which is a misuse.
    assert(other.access_count_.load(std::memory_order_relaxed) == 0 &&
           "Secret moved while an access guard is still alive");
    // Reset counter on the moved-to object so it starts clean.
    access_count_.store(0, std::memory_order_relaxed);
#endif
  }

  Secret& operator=(Secret&& other) noexcept {
    if (this != &other) {
#ifndef NDEBUG
      assert(access_count_.load(std::memory_order_relaxed) == 0 &&
             "Secret move-assigned while an access guard is still alive (destination)");
      assert(other.access_count_.load(std::memory_order_relaxed) == 0 &&
             "Secret moved while an access guard is still alive (source)");
#endif
      // sodium_free zeros before freeing, satisfying the wipe requirement.
      if (data_) {
        sodium_free(data_);
      }
      data_ = other.data_;
      size_ = other.size_;
      other.data_ = nullptr;
      other.size_ = 0;
#ifndef NDEBUG
      access_count_.store(0, std::memory_order_relaxed);
#endif
    }
    return *this;
  }

  // Copying to/from is not allowed (invariant 1: single ownership).
  // Copies would require either duplicating sodium-allocated memory (expensive,
  // and potentially surprising to callers reasoning about secret lifetimes) or
  // sharing a pointer (violating single ownership). The rule-of-five requires
  // explicit deletion when a destructor or move operation is user-defined.
  // See: https://en.cppreference.com/w/cpp/language/rule_of_three
  Secret(const Secret&)            = delete;
  Secret& operator=(const Secret&) = delete;

  // -- Capacity ---------------------------------------------------------------
  // Returns the size (in bytes) of the allocated buffer. Does not require an
  // access guard; size is not sensitive information.
  [[nodiscard]] std::size_t size() const noexcept { return size_; }

  // -- Zeroing ----------------------------------------------------------------
  // Overwrites all bytes in the buffer with zeros without freeing or resizing.
  // The buffer remains allocated at the same size and returns to NOACCESS state
  // after this call. Named "zeroize" rather than "clear" to avoid the STL
  // implication that size() becomes 0.
  //
  // Not thread-safe. Requires external synchronization.
  void zeroize() noexcept {
    if (data_) {
      // Temporarily open for writing; sodium_memzero; re-lock.
      if (sodium_mprotect_readwrite(data_) != 0) { std::abort(); }
      sodium_memzero(data_, size_);
      if (sodium_mprotect_noaccess(data_) != 0) { std::abort(); }
    }
  }

  // -- Safe scoped access (preferred API) ------------------------------------
  // These methods are the preferred way to access Secret's memory. They open
  // a time-limited window via an RAII guard, pass a span into the user
  // callback, and re-lock the buffer when the callback returns. Using these
  // instead of constructing access guards directly makes nesting visually
  // obvious and prevents guards from escaping their intended scope.
  //
  // The return value of `f` is forwarded, so value-returning lambdas work:
  //   bool ok = secret.with_read_access([](std::span<const char> s) {
  //       return verify(s);
  //   });
  //
  // [[nodiscard]] is applied so that a value returned by `f` is not silently
  // discarded at the call site.
  template <typename F>
  [[nodiscard]] decltype(auto) with_read_access(F&& f) const {
    details::Secret_readaccess guard(*this);
    return std::forward<F>(f)(guard.get());
  }

  template <typename F>
  [[nodiscard]] decltype(auto) with_write_access(F&& f) {
    details::Secret_writeaccess guard(*this);
    return std::forward<F>(f)(guard.get());
  }

private:
  char*       data_ = nullptr;
  std::size_t size_ = 0;

#ifndef NDEBUG
  // Tracks the number of currently live access guards for this Secret.
  // Mutable so that const methods (with_read_access, Secret_readaccess ctor)
  // can increment/decrement. Only meaningful in debug builds; zero overhead
  // in release builds.
  mutable std::atomic<int> access_count_{0};
#endif

  void allocate(std::size_t size) {
    assert(size > 0 && "Secret size must be greater than 0");
    data_ = static_cast<char*>(sodium_malloc(size));
    if (!data_) { std::abort(); }  // see FAILURE MODEL in file header
    size_ = size;
    // Buffer starts life locked. Every access must go through a guard.
    if (sodium_mprotect_noaccess(data_) != 0) { std::abort(); }
  }

  // sodium_free internally zeroes the allocation before releasing it.
  // This satisfies the "wipe before free" requirement without an explicit
  // sodium_memzero call. The method is named "wipe_and_free" to document
  // intent; the actual zeroing is done inside sodium_free.
  void wipe_and_free() noexcept {
    if (data_) {
      // sodium_free handles zeroing internally. Do not call sodium_memzero
      // here; the buffer is in NOACCESS state and an extra mprotect_readwrite
      // + memzero before sodium_free would be redundant.
      sodium_free(data_);
      data_ = nullptr;
      size_ = 0;
    }
  }
};

namespace details {
// ----------------------------------------------------------------------------
// Secret_readaccess
// ----------------------------------------------------------------------------
// RAII guard that temporarily opens a Secret buffer for reading. The buffer
// is placed in READONLY state on construction and returned to NOACCESS state
// on destruction, even if an exception is thrown.
//
// std::span is used instead of a C-string pointer to avoid assumptions about
// content: secrets may be passwords, private keys, API tokens, or raw binary
// data. None of these can be assumed to be null-terminated, UTF-8, or even
// printable.
//
// PREFER with_read_access() over constructing this guard directly.
// See "ACCESS GUARD RULES" in the file header.
//
// Copy and move are deleted to prevent double-mprotect in destructors:
//   auto a = Secret_readaccess(secret);
//   auto b = a;  // two destructors -> sodium_mprotect_noaccess called twice
//                // on the same pointer -> second call is at best a no-op,
//                // at worst UB if the pointer has been freed in between.
class Secret_readaccess {
public:
  explicit Secret_readaccess(const Secret& s) : sec_(s) {
#ifndef NDEBUG
    int prev = s.access_count_.fetch_add(1, std::memory_order_relaxed);
    assert(prev == 0 &&
           "Overlapping access guards on the same Secret are undefined behavior. "
           "See ACCESS GUARD RULES in Secret.h.");
#endif
    if (sodium_mprotect_readonly(sec_.data_) != 0) {
      // mprotect failure means we cannot safely read the secret.
      // Abort rather than silently continuing with an unlocked buffer or,
      // worse, continuing with the assumption that the lock is held.
#ifndef NDEBUG
      sec_.access_count_.fetch_sub(1, std::memory_order_relaxed);
#endif
      std::abort();
    }
  }

  ~Secret_readaccess() noexcept {
    // Re-locking in the destructor must not throw or fail silently.
    // If sodium_mprotect_noaccess fails here, the buffer is permanently
    // unlocked, which is a security violation. Abort.
    if (sodium_mprotect_noaccess(sec_.data_) != 0) { std::abort(); }
#ifndef NDEBUG
    sec_.access_count_.fetch_sub(1, std::memory_order_relaxed);
#endif
  }

  [[nodiscard]] std::span<const char> get() const noexcept {
    return {sec_.data_, sec_.size_};
  }

  Secret_readaccess(const Secret_readaccess&)            = delete;
  Secret_readaccess& operator=(const Secret_readaccess&) = delete;
  Secret_readaccess(Secret_readaccess&&)                 = delete;
  Secret_readaccess& operator=(Secret_readaccess&&)      = delete;

private:
  const Secret& sec_;
};

// ----------------------------------------------------------------------------
// Secret_writeaccess
// ----------------------------------------------------------------------------
// RAII guard that temporarily opens a Secret buffer for reading and writing.
// The buffer is placed in READWRITE state on construction and returned to
// NOACCESS state on destruction, even if an exception is thrown.
//
// PREFER with_write_access() over constructing this guard directly.
// See "ACCESS GUARD RULES" in the file header.
//
// Copy and move are deleted for the same reasons as Secret_readaccess.
class Secret_writeaccess {
public:
  explicit Secret_writeaccess(Secret& s) : sec_(s) {
#ifndef NDEBUG
    int prev = s.access_count_.fetch_add(1, std::memory_order_relaxed);
    assert(prev == 0 &&
           "Overlapping access guards on the same Secret are undefined behavior. "
           "See ACCESS GUARD RULES in Secret.h.");
#endif
    if (sodium_mprotect_readwrite(sec_.data_) != 0) {
#ifndef NDEBUG
      sec_.access_count_.fetch_sub(1, std::memory_order_relaxed);
#endif
      std::abort();
    }
  }

  ~Secret_writeaccess() noexcept {
    if (sodium_mprotect_noaccess(sec_.data_) != 0) { std::abort(); }
#ifndef NDEBUG
    sec_.access_count_.fetch_sub(1, std::memory_order_relaxed);
#endif
  }

  [[nodiscard]] std::span<char> get() noexcept {
    return {sec_.data_, sec_.size_};
  }

  Secret_writeaccess(const Secret_writeaccess&)            = delete;
  Secret_writeaccess& operator=(const Secret_writeaccess&) = delete;
  Secret_writeaccess(Secret_writeaccess&&)                 = delete;
  Secret_writeaccess& operator=(Secret_writeaccess&&)      = delete;

private:
  Secret& sec_;
};
}  // namespace details

}  // namespace pwledger

#endif  // PWLEDGER_SECRET_H
