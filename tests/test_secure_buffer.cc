#include <gtest/gtest.h>
#include <pwledger/SecureBuffer.h>
#include <sodium.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace {

class SecureBufferTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    if (sodium_init() < 0) {
      throw std::runtime_error("libsodium initialization failed");
    }
  }

  void TearDown() override {
    pwledger::SecureBuffer::set_growth_wipe_observer(nullptr);
  }
};

TEST_F(SecureBufferTest, DefaultConstructedIsEmpty) {
  pwledger::SecureBuffer buf;
  EXPECT_EQ(buf.data(), nullptr);
  EXPECT_EQ(buf.size(), 0U);
  EXPECT_EQ(buf.capacity(), 0U);
  EXPECT_TRUE(buf.empty());
}

TEST_F(SecureBufferTest, InitialCapacityAllocates) {
  pwledger::SecureBuffer buf(64);
  EXPECT_NE(buf.data(), nullptr);
  EXPECT_EQ(buf.size(), 64U);
  EXPECT_GE(buf.capacity(), 64U);
  EXPECT_FALSE(buf.empty());
}

TEST_F(SecureBufferTest, MoveLeavesSourceEmpty) {
  pwledger::SecureBuffer src(32);
  src.push_back(0x42);
  std::size_t orig_size = src.size();

  pwledger::SecureBuffer dst(std::move(src));
  EXPECT_EQ(src.data(), nullptr);
  EXPECT_EQ(src.size(), 0U);
  EXPECT_EQ(src.capacity(), 0U);
  EXPECT_TRUE(src.empty());

  EXPECT_NE(dst.data(), nullptr);
  EXPECT_EQ(dst.size(), orig_size);
  EXPECT_EQ(dst.data()[32], 0x42);
}

TEST_F(SecureBufferTest, MoveAssignmentTransfersOwnership) {
  pwledger::SecureBuffer src(16);
  src.push_back(0x99);

  pwledger::SecureBuffer dst;
  dst = std::move(src);

  EXPECT_EQ(src.data(), nullptr);
  EXPECT_EQ(src.size(), 0U);
  EXPECT_TRUE(src.empty());

  EXPECT_NE(dst.data(), nullptr);
  EXPECT_EQ(dst.size(), 17U);
  EXPECT_EQ(dst.data()[16], 0x99);
}

TEST_F(SecureBufferTest, GrowthWipesOldBlockBeforeFree) {
  static bool observer_called = false;
  static bool was_completely_zeroed = true;
  observer_called = false;
  was_completely_zeroed = true;

  pwledger::SecureBuffer::set_growth_wipe_observer([](const std::uint8_t* old_data, std::size_t old_cap) {
    observer_called = true;
    for (std::size_t i = 0; i < old_cap; ++i) {
      if (old_data[i] != 0) {
        was_completely_zeroed = false;
      }
    }
  });

  pwledger::SecureBuffer buf(16);
  std::memset(buf.data(), 0xAA, 16);

  // Trigger reallocation
  buf.reserve(128);

  EXPECT_TRUE(observer_called);
  EXPECT_TRUE(was_completely_zeroed);
}

TEST_F(SecureBufferTest, AppendAndPushBack) {
  pwledger::SecureBuffer buf;
  const std::uint8_t sample[] = {1, 2, 3, 4, 5};
  buf.append(sample, 5);
  EXPECT_EQ(buf.size(), 5U);
  EXPECT_EQ(std::memcmp(buf.data(), sample, 5), 0);

  buf.push_back(6);
  EXPECT_EQ(buf.size(), 6U);
  EXPECT_EQ(buf.data()[5], 6);
}

TEST_F(SecureBufferTest, UntrustedSizeLimitEnforced) {
  EXPECT_THROW(pwledger::SecureBuffer(pwledger::kMaxSecureBufferBytes + 1), std::length_error);
}

using SecureBufferDeathTest = SecureBufferTest;

TEST_F(SecureBufferDeathTest, GuardPageAccessAborts) {
  ASSERT_DEATH({
    pwledger::SecureBuffer buf(16);
    volatile std::uint8_t* ptr = buf.data();
    volatile std::uint8_t b = ptr[buf.capacity()];
    (void)b;
  }, "");
}

}  // namespace
