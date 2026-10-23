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

#include <pwledger/SecureBuffer.h>
#include <sodium.h>

#include <algorithm>
#include <new>

namespace pwledger {

void SecureBuffer::set_growth_wipe_observer(GrowthWipeObserver observer) noexcept {
  growth_wipe_observer_ = observer;
}

SecureBuffer::SecureBuffer(std::size_t initial_capacity) {
  if (initial_capacity > 0) {
    reallocate(initial_capacity);
    size_ = initial_capacity;
  }
}

SecureBuffer::~SecureBuffer() noexcept {
  wipe_and_free();
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_), capacity_(other.capacity_) {
  other.data_ = nullptr;
  other.size_ = 0;
  other.capacity_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this != &other) {
    wipe_and_free();
    data_ = other.data_;
    size_ = other.size_;
    capacity_ = other.capacity_;
    other.data_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
  }
  return *this;
}

void SecureBuffer::reallocate(std::size_t new_capacity) {
  if (new_capacity > kMaxSecureBufferBytes) {
    throw std::length_error("SecureBuffer allocation request exceeds maximum allowable limit (64 MiB)");
  }
  if (sodium_init() < 0) {
    throw std::runtime_error("libsodium initialization failed in SecureBuffer");
  }

  std::uint8_t* new_data = static_cast<std::uint8_t*>(sodium_malloc(new_capacity));
  if (!new_data) {
    throw std::bad_alloc();
  }

  if (data_) {
    std::size_t copy_len = std::min(size_, new_capacity);
    if (copy_len > 0) {
      std::memcpy(new_data, data_, copy_len);
    }
    // Wipe old buffer completely before free
    sodium_memzero(data_, capacity_);
    if (growth_wipe_observer_) {
      growth_wipe_observer_(data_, capacity_);
    }
    sodium_free(data_);
  }

  data_ = new_data;
  capacity_ = new_capacity;
}

void SecureBuffer::wipe_and_free() noexcept {
  if (data_) {
    sodium_memzero(data_, capacity_);
    sodium_free(data_);
    data_ = nullptr;
    size_ = 0;
    capacity_ = 0;
  }
}

void SecureBuffer::resize(std::size_t new_size) {
  if (new_size > capacity_) {
    reallocate(new_size);
  }
  size_ = new_size;
}

void SecureBuffer::reserve(std::size_t new_capacity) {
  if (new_capacity > capacity_) {
    reallocate(new_capacity);
  }
}

void SecureBuffer::clear() noexcept {
  if (data_ && size_ > 0) {
    sodium_memzero(data_, size_);
  }
  size_ = 0;
}

void SecureBuffer::append(const std::uint8_t* src, std::size_t len) {
  if (len == 0 || !src) return;
  if (size_ + len > capacity_) {
    std::size_t next_cap = (capacity_ == 0) ? 64 : capacity_ * 2;
    if (next_cap < size_ + len) {
      next_cap = size_ + len;
    }
    reallocate(next_cap);
  }
  std::memcpy(data_ + size_, src, len);
  size_ += len;
}

void SecureBuffer::append(std::span<const std::uint8_t> bytes) {
  append(bytes.data(), bytes.size());
}

void SecureBuffer::push_back(std::uint8_t byte) {
  append(&byte, 1);
}

}  // namespace pwledger
