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

#include <gtest/gtest.h>
#include <pwledger/Secret.h>
#include <pwledger/TerminalManager.h>

#include <cstring>

// ============================================================================
// TEST STRATEGY
// ============================================================================
//
// Secret must guarantee six invariants documented in the Secret.h header.
// This file tests each invariant through a combination of compile-time
// static_asserts and runtime GoogleTest cases:
//
//   Invariant 1 (single ownership, no copies):
//     - static_assert: copy construction and assignment are deleted
//     - Runtime: move constructor invalidates source (size → 0)
//     - Runtime: move constructor preserves data in destination
//     - Runtime: move-assignment operator transfers ownership correctly
//     - Runtime: self-move-assignment is a safe no-op
//
//   Invariant 2 (sodium-secured memory):
//     - Implicitly tested by every test that constructs a Secret:
//       sodium_malloc is called on construction; if it fails, abort() fires
//       and the test never reaches ASSERT. A passing test proves allocation
//       succeeded on sodium-secured memory.
//
//   Invariant 3 (no implicit conversions):
//     - static_assert: not convertible to bool, char*, or std::string
//     - These are compile-time checks; no runtime test needed.
//
//   Invariant 4 (allocation failure is fatal):
//     - Not directly testable without mocking sodium_malloc. A future test
//       could use LD_PRELOAD to inject allocation failures and verify abort.
//
//   Invariant 5 (partial construction never leaks):
//     - Same as invariant 4: requires controlled allocation failure. Verified
//       by code inspection of the allocate() implementation.
//
//   Invariant 6 (NOACCESS state except inside access guards):
//     - Runtime: zeroize() works through a temporary readwrite window
//     - Runtime: with_read_access provides correct read-only view
//     - Runtime: with_write_access allows mutation and persists
//     - Death test: constructing Secret(0) triggers assert in debug builds
//
// TerminalManager invariants (non-copyable, non-movable):
//     - static_assert: copy and move operations are deleted for both
//       the concrete platform class and the CRTP base.
//
// ============================================================================

// ============================================================================
// Invariant 1: Single ownership — no copies
// ============================================================================
// These are compile-time assertions. If Secret were ever made copyable
// (accidentally or intentionally), this test file would fail to compile,
// catching the regression before any runtime test runs.
static_assert(!std::is_copy_constructible_v<pwledger::Secret>, "Secret must not be copy-constructible");
static_assert(!std::is_copy_assignable_v<pwledger::Secret>, "Secret must not be copy-assignable");

// ============================================================================
// Invariant 3: No implicit conversions
// ============================================================================
// Secret must never implicitly convert to bool, char*, void*, or std::string.
// These assertions prevent accidental logging, formatting, or truth-testing.
static_assert(!std::is_convertible_v<pwledger::Secret, bool>, "Secret must not be implicitly convertible to bool");
static_assert(!std::is_convertible_v<pwledger::Secret, char*>, "Secret must not be implicitly convertible to char*");
static_assert(!std::is_convertible_v<pwledger::Secret, const char*>,
              "Secret must not be implicitly convertible to const char*");
static_assert(!std::is_convertible_v<pwledger::Secret, std::string>,
              "Secret must not be implicitly convertible to std::string");

// ============================================================================
// TerminalManager invariants: non-copyable, non-movable
// ============================================================================
// Terminal attributes are process-global state. Two live managers would produce
// conflicting saves and restores. These assertions verify the CRTP enforcement.
static_assert(!std::is_copy_constructible_v<pwledger::TerminalManager_v>,
              "TerminalManager must not be copy-constructible");
static_assert(!std::is_copy_assignable_v<pwledger::TerminalManager_v>, "TerminalManager must not be copy-assignable");
static_assert(!std::is_move_constructible_v<pwledger::TerminalManager_v>,
              "TerminalManager must not be move-constructible");
static_assert(!std::is_move_assignable_v<pwledger::TerminalManager_v>, "TerminalManager must not be move-assignable");


// ============================================================================
// Invariant 1: Single ownership — move semantics
// ============================================================================

class SecretTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    if (sodium_init() < 0) {
      throw std::runtime_error("libsodium init failed");
    }
  }
};

using SecretDeathTest = SecretTest;

// After a move, the source Secret must be invalidated (size → 0, data → null).
// Any attempt to use the source after this point is a programmer error, and
// the debug-build access_count assert will catch it if a guard is opened.
TEST_F(SecretTest, move_invalidates_source) {
  pwledger::Secret src(32);
  src.with_write_access(
      [](std::span<char> buf) { std::memcpy(buf.data(), "secret-material-here-31-bytes!!", buf.size()); });

  pwledger::Secret dst(std::move(src));

  ASSERT_EQ(src.size(), 0u);
}

// The destination of a move must contain the exact bytes that were in the
// source. This verifies that the pointer transfer is correct and the data
// was not corrupted during the move.
TEST_F(SecretTest, move_preserves_data_in_destination) {
  constexpr std::string_view kMaterial = "secret-material-here-31-bytes!!";
  pwledger::Secret src(kMaterial.size());
  src.with_write_access([&](std::span<char> buf) { std::memcpy(buf.data(), kMaterial.data(), buf.size()); });

  pwledger::Secret dst(std::move(src));

  dst.with_read_access(
      [&](std::span<const char> buf) { ASSERT_EQ(std::string_view(buf.data(), buf.size()), kMaterial); });
}

// Move-assignment must free the destination's old allocation (preventing a
// leak) and then transfer ownership from the source. After the assignment,
// the source is invalidated and the destination holds the original data.
TEST_F(SecretTest, move_assignment_transfers_ownership) {
  constexpr std::string_view kMaterial = "assignment-test-data-here!!!!!";
  pwledger::Secret src(kMaterial.size());
  src.with_write_access([&](std::span<char> buf) { std::memcpy(buf.data(), kMaterial.data(), buf.size()); });

  // dst starts with a different-size allocation to verify it's freed.
  pwledger::Secret dst(64);
  dst = std::move(src);

  ASSERT_EQ(src.size(), 0u);
  ASSERT_EQ(dst.size(), kMaterial.size());
  dst.with_read_access(
      [&](std::span<const char> buf) { ASSERT_EQ(std::string_view(buf.data(), buf.size()), kMaterial); });
}

// Self-move-assignment (x = std::move(x)) must be a safe no-op. The C++
// standard does not require this, but our implementation explicitly checks
// (this != &other) and returns early. This test ensures that check works
// correctly and the Secret remains intact.
TEST_F(SecretTest, self_move_assignment_is_safe) {
  constexpr std::string_view kMaterial = "self-move-test-data!!!!!!!!!!!!";
  pwledger::Secret secret(kMaterial.size());
  secret.with_write_access([&](std::span<char> buf) { std::memcpy(buf.data(), kMaterial.data(), buf.size()); });

  // Suppress the compiler's self-move warning; we intentionally test this.
  pwledger::Secret& ref = secret;
  secret = std::move(ref);

  ASSERT_EQ(secret.size(), kMaterial.size());
  secret.with_read_access(
      [&](std::span<const char> buf) { ASSERT_EQ(std::string_view(buf.data(), buf.size()), kMaterial); });
}

// ============================================================================
// Invariant 6: Memory protection — access guards and zeroize
// ============================================================================

// with_write_access must open the buffer for writing and persist the written
// data so that a subsequent with_read_access sees the same bytes.
TEST_F(SecretTest, write_then_read_access_round_trip) {
  constexpr std::string_view kMaterial = "roundtrip-verification-data!!!!";
  pwledger::Secret secret(kMaterial.size());

  secret.with_write_access([&](std::span<char> buf) { std::memcpy(buf.data(), kMaterial.data(), buf.size()); });

  secret.with_read_access(
      [&](std::span<const char> buf) { ASSERT_EQ(std::string_view(buf.data(), buf.size()), kMaterial); });
}

// with_read_access must return the value produced by the caller's lambda.
// The [[nodiscard]] attribute on with_read_access ensures the return value
// is not silently discarded at the call site.
TEST_F(SecretTest, with_read_access_returns_value) {
  pwledger::Secret secret(16);
  secret.with_write_access([](std::span<char> buf) { std::memset(buf.data(), 'X', buf.size()); });

  std::size_t len = secret.with_read_access([](std::span<const char> buf) { return buf.size(); });

  ASSERT_EQ(len, 16u);
}

// zeroize() must overwrite all bytes with zeros without freeing or resizing
// the buffer. After zeroize, the buffer should still be allocated at the
// same size, but every byte should be 0x00.
TEST_F(SecretTest, zeroize_clears_all_bytes) {
  constexpr std::size_t kSize = 64;
  pwledger::Secret secret(kSize);
  secret.with_write_access([](std::span<char> buf) { std::memset(buf.data(), 0xFF, buf.size()); });

  secret.zeroize();

  ASSERT_EQ(secret.size(), kSize);
  secret.with_read_access([&](std::span<const char> buf) {
    for (std::size_t i = 0; i < buf.size(); ++i) {
      ASSERT_EQ(buf[i], '\0') << "Byte " << i << " was not zeroed";
    }
  });
}

// ============================================================================
// Invariant 6: Death test — zero-size allocation
// ============================================================================
// Secret(0) triggers an assert in debug builds because sodium_malloc(0) is
// implementation-defined and a zero-size Secret has no valid use case. This
// test only runs in debug builds where NDEBUG is not defined.
#ifndef NDEBUG
TEST_F(SecretDeathTest, zero_size_aborts_in_debug) {
  ASSERT_DEATH({ pwledger::Secret s(0); }, "");
}
#endif
