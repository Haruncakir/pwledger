#include <pwledger/Secret.h>

#include <cstdlib>

namespace pwledger {

Secret::Secret(std::size_t size) {
  allocate(size);
}

Secret::~Secret() noexcept {
  wipe_and_free();
}

Secret::Secret(Secret&& other) noexcept : data_(other.data_), size_(other.size_) {
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
    size_ = other.size_;
    other.data_ = nullptr;
    other.size_ = 0;
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
    sodium_memzero(data_, size_);
    if (sodium_mprotect_noaccess(data_) != 0) {
      std::abort();
    }
  }
}

void Secret::allocate(std::size_t size) {
  assert(size > 0 && "Secret size must be greater than 0");
  data_ = static_cast<char*>(sodium_malloc(size));
  if (!data_) {
    std::abort();
  }  // see FAILURE MODEL in file header
  size_ = size;
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
    size_ = 0;
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
