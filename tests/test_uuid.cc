#include <gtest/gtest.h>
#include <pwledger/uuid.h>
#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <unordered_set>
#include <vector>

TEST(UuidTest, UnalignedHashUnderUBSan) {
  // Allocate a buffer with odd offsets to create deliberately misaligned Uuid instances
  alignas(std::uint64_t) std::uint8_t raw[sizeof(pwledger::Uuid) + 8];
  for (std::size_t offset = 1; offset < 8; ++offset) {
    pwledger::Uuid* misaligned = reinterpret_cast<pwledger::Uuid*>(raw + offset);
    for (std::size_t i = 0; i < 16; ++i) {
      misaligned->bytes[i] = static_cast<std::uint8_t>(i + offset);
    }
    std::hash<pwledger::Uuid> hasher;
    std::size_t h = hasher(*misaligned);
    EXPECT_NE(h, 0U);
  }
}

TEST(UuidTest, VersionAndVariantRFC4122) {
  for (int i = 0; i < 100; ++i) {
    pwledger::Uuid id = pwledger::Uuid::generate();
    // Version 4 check: top 4 bits of byte 6 must be 0100 (0x4)
    EXPECT_EQ((id.bytes[6] >> 4), 0x04);
    // Variant 1 check: top 2 bits of byte 8 must be 10 (0x8, 0x9, 0xa, 0xb)
    EXPECT_EQ((id.bytes[8] >> 6), 0x02);
  }
}

TEST(UuidTest, StringFormattingAndParsing) {
  pwledger::Uuid id = pwledger::Uuid::generate();
  std::string s = id.to_string();
  EXPECT_EQ(s.length(), 36U);
  EXPECT_EQ(s[8], '-');
  EXPECT_EQ(s[13], '-');
  EXPECT_EQ(s[18], '-');
  EXPECT_EQ(s[23], '-');

  auto parsed = pwledger::Uuid::from_string(s);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(*parsed, id);

  // Compact form (32 hex characters without hyphens)
  std::string compact = s;
  compact.erase(std::remove(compact.begin(), compact.end(), '-'), compact.end());
  EXPECT_EQ(compact.length(), 32U);
  auto parsed_compact = pwledger::Uuid::from_string(compact);
  ASSERT_TRUE(parsed_compact.has_value());
  EXPECT_EQ(*parsed_compact, id);
}

TEST(UuidTest, UniquenessAndNonEmpty) {
  std::unordered_set<std::string> seen;
  for (int i = 0; i < 1000; ++i) {
    pwledger::Uuid id = pwledger::Uuid::generate();
    EXPECT_FALSE(id.empty());
    std::string s = id.to_string();
    EXPECT_TRUE(seen.insert(s).second) << "Duplicate UUID generated: " << s;
  }
}
