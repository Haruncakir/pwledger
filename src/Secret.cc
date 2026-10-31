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

#include <pwledger/Secret.h>

#include <atomic>
#include <cstdlib>
#include <stdexcept>

namespace pwledger {

#if defined(PWLEDGER_TESTING)
namespace {
std::atomic<Secret::AllocationFailureHook> s_allocation_failure_hook{nullptr};
}

void Secret::set_allocation_failure_hook(AllocationFailureHook hook) noexcept {
  s_allocation_failure_hook.store(hook, std::memory_order_release);
}
#endif

Secret::Secret(UntrustedTag, std::size_t capacity, std::size_t payload_length) {
  try_allocate(capacity);
  payload_length_ = (payload_length <= capacity_) ? payload_length : capacity_;
}

Secret Secret::try_create(std::size_t capacity, std::size_t payload_length) {
  if (capacity == 0) {
    throw VaultResourceException("Secret allocation capacity cannot be zero");
  }
  return Secret(UntrustedTag{}, capacity, payload_length == 0 ? capacity : payload_length);
}

void Secret::try_allocate(std::size_t size) {
  if (size == 0) {
    throw VaultResourceException("Secret allocation size cannot be zero");
  }
#if defined(PWLEDGER_TESTING)
  auto hook = s_allocation_failure_hook.load(std::memory_order_acquire);
  if (hook && hook(size)) {
    throw VaultResourceException("Simulated secure memory allocation refusal");
  }
#endif
  char* new_data = static_cast<char*>(sodium_malloc(size));
  if (!new_data) {
    throw VaultResourceException("sodium_malloc failed to allocate secure memory");
  }
  if (data_) {
    wipe_and_free();
  }
  data_ = new_data;
  capacity_ = size;
  if (sodium_mprotect_noaccess(data_) != 0) {
    std::abort();
  }
}

Secret::Secret(std::size_t capacity) : Secret(capacity, capacity) {}

Secret::Secret(std::size_t capacity, std::size_t payload_length) {
  allocate(capacity);
  payload_length_ = (payload_length <= capacity_) ? payload_length : capacity_;
}

void Secret::set_length(std::size_t new_length) {
  if (new_length > capacity_) {
    throw std::length_error("Secret payload length exceeds allocated capacity");
  }
  payload_length_ = new_length;
}

Secret::~Secret() noexcept {
  wipe_and_free();
}

Secret::Secret(Secret&& other) noexcept
    : data_(other.data_), capacity_(other.capacity_), payload_length_(other.payload_length_) {
  other.data_ = nullptr;
  other.capacity_ = 0;
  other.payload_length_ = 0;
#ifndef NDEBUG
  // The source's access_count should be 0; if it isn't, a guard is alive
  // concurrently with a move, which is a misuse.
  assert(other.access_count_.load(std::memory_order_relaxed) == 0 &&
         "Secret moved while an access guard is still alive");
  // Reset counter on the moved-to object so it starts clean.
  access_count_.store(0, std::memory_order_relaxed);
#endif
}

Secret& Secret::operator=(Secret&& other) noexcept {
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
    capacity_ = other.capacity_;
    payload_length_ = other.payload_length_;
    other.data_ = nullptr;
    other.capacity_ = 0;
    other.payload_length_ = 0;
#ifndef NDEBUG
    access_count_.store(0, std::memory_order_relaxed);
#endif
  }
  return *this;
}

void Secret::zeroize() noexcept {
  if (data_) {
    // Temporarily open for writing; sodium_memzero; re-lock.
    if (sodium_mprotect_readwrite(data_) != 0) {
      std::abort();
    }
    sodium_memzero(data_, capacity_);
    if (sodium_mprotect_noaccess(data_) != 0) {
      std::abort();
    }
  }
}

void Secret::allocate(std::size_t size) {
  if (size == 0) {
    std::abort();
  }
  data_ = static_cast<char*>(sodium_malloc(size));
  if (!data_) {
    std::abort();
  }  // see FAILURE MODEL in file header
  capacity_ = size;
  // Buffer starts life locked. Every access must go through a guard.
  if (sodium_mprotect_noaccess(data_) != 0) {
    std::abort();
  }
}

void Secret::wipe_and_free() noexcept {
  if (data_) {
    // sodium_free handles zeroing internally. Do not call sodium_memzero
    // here; the buffer is in NOACCESS state and an extra mprotect_readwrite
    // + memzero before sodium_free would be redundant.
    sodium_free(data_);
    data_ = nullptr;
    capacity_ = 0;
    payload_length_ = 0;
  }
}

namespace details {

Secret_readaccess::Secret_readaccess(const Secret& s) : sec_(s) {
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

Secret_readaccess::~Secret_readaccess() noexcept {
  // Re-locking in the destructor must not throw or fail silently.
  // If sodium_mprotect_noaccess fails here, the buffer is permanently
  // unlocked, which is a security violation. Abort.
  if (sodium_mprotect_noaccess(sec_.data_) != 0) {
    std::abort();
  }
#ifndef NDEBUG
  sec_.access_count_.fetch_sub(1, std::memory_order_relaxed);
#endif
}

Secret_writeaccess::Secret_writeaccess(Secret& s) : sec_(s) {
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

Secret_writeaccess::~Secret_writeaccess() noexcept {
  if (sodium_mprotect_noaccess(sec_.data_) != 0) {
    std::abort();
  }
#ifndef NDEBUG
  sec_.access_count_.fetch_sub(1, std::memory_order_relaxed);
#endif
}

}  // namespace details

}  // namespace pwledger
