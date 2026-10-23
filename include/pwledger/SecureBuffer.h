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

#ifndef PWLEDGER_SECUREBUFFER_H
#define PWLEDGER_SECUREBUFFER_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace pwledger {

// Maximum allowable buffer capacity for operations to prevent memory exhaustion (64 MiB)
inline constexpr std::size_t kMaxSecureBufferBytes = 64 * 1024 * 1024;

// ============================================================================
// SecureBuffer
// ============================================================================
// A move-only, RAII-managed secure buffer backed by libsodium hardened memory
// (sodium_malloc / sodium_free). Features:
//   - Page-locked into physical RAM (mlock / VirtualLock, non-swappable)
//   - Surrounded by hardware guard pages (PAGE_NOACCESS)
//   - Safe reallocation: growth zero-wipes the old block before releasing it
//   - Deterministic wipe-on-destruction: zeroized before freeing
//   - Safe error handling: throws std::bad_alloc / std::length_error on untrusted
//     allocation failure rather than aborting.
class SecureBuffer {
public:
  // Hook for testing that growth zeroizes old memory before deallocation
  using GrowthWipeObserver = void (*)(const std::uint8_t* old_data, std::size_t old_cap);
  static void set_growth_wipe_observer(GrowthWipeObserver observer) noexcept;

  SecureBuffer() noexcept = default;

  explicit SecureBuffer(std::size_t initial_capacity);

  ~SecureBuffer() noexcept;

  // Move-only semantics
  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  // Accessors
  [[nodiscard]] std::uint8_t* data() noexcept { return data_; }
  [[nodiscard]] const std::uint8_t* data() const noexcept { return data_; }

  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

  [[nodiscard]] std::span<std::uint8_t> span() noexcept { return {data_, size_}; }
  [[nodiscard]] std::span<const std::uint8_t> span() const noexcept { return {data_, size_}; }

  [[nodiscard]] std::uint8_t* begin() noexcept { return data_; }
  [[nodiscard]] const std::uint8_t* begin() const noexcept { return data_; }
  [[nodiscard]] const std::uint8_t* cbegin() const noexcept { return data_; }

  [[nodiscard]] std::uint8_t* end() noexcept { return data_ + size_; }
  [[nodiscard]] const std::uint8_t* end() const noexcept { return data_ + size_; }
  [[nodiscard]] const std::uint8_t* cend() const noexcept { return data_ + size_; }

  friend bool operator==(const SecureBuffer& lhs, const SecureBuffer& rhs) noexcept {
    if (lhs.size() != rhs.size()) return false;
    if (lhs.empty()) return true;
    return std::memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
  }

  friend bool operator==(const SecureBuffer& lhs, std::span<const std::uint8_t> rhs) noexcept {
    if (lhs.size() != rhs.size()) return false;
    if (lhs.empty()) return true;
    return std::memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
  }

  friend bool operator==(std::span<const std::uint8_t> lhs, const SecureBuffer& rhs) noexcept {
    return rhs == lhs;
  }

  friend bool operator==(const SecureBuffer& lhs, const std::vector<std::uint8_t>& rhs) noexcept {
    return lhs == std::span<const std::uint8_t>(rhs);
  }

  friend bool operator==(const std::vector<std::uint8_t>& lhs, const SecureBuffer& rhs) noexcept {
    return rhs == lhs;
  }

  // Modifiers
  void resize(std::size_t new_size);
  void reserve(std::size_t new_capacity);
  void clear() noexcept;

  void append(const std::uint8_t* src, std::size_t len);
  void append(std::span<const std::uint8_t> bytes);
  void push_back(std::uint8_t byte);

private:
  std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  std::size_t capacity_ = 0;

  static inline GrowthWipeObserver growth_wipe_observer_ = nullptr;

  void reallocate(std::size_t new_capacity);
  void wipe_and_free() noexcept;
};

}  // namespace pwledger

#endif  // PWLEDGER_SECUREBUFFER_H
