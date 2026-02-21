#include <gtest/gtest.h>
#include <pwledger/Secret.h>

// Secret must guarantee the guiding invariants mentioned in the header:
// 1. Single ownership: no copies. Move invalidates the source.
// 2. All sensitive bytes live in sodium-secured memory at all times.
// 3. No implicit conversions, no stream operators, no accidental formatting.
// 4. Allocation failure is fatal (fail-fast). See "Failure Model" below.
// 5. Partial construction never leaks memory.
// 6. Memory is always in NOACCESS state except inside an active access guard.
//
// So lets test them one-by-one

// test no copies, compile-time assertions are enough
static_assert(!std::is_copy_constructible_v<pwledger::Secret>);
static_assert(!std::is_copy_assignable_v<pwledger::Secret>);

// test single ownership policy
TEST(SecretTest, move_invalidates_source) {
  pwledger::Secret src(32);
  src.with_write_access([](std::span<char> buf) {
    std::memcpy(buf.data(), "secret-material-here-31-bytes!!", buf.size());
  });

  pwledger::Secret dst(std::move(src));

  ASSERT_EQ(src.size(), 0u);
}
TEST(SecretTest, move_preserves_data_in_destination) {
  constexpr std::string_view kMaterial = "secret-material-here-31-bytes!!";
  pwledger::Secret src(kMaterial.size());
  src.with_write_access([&](std::span<char> buf) {
    std::memcpy(buf.data(), kMaterial.data(), buf.size());
  });

  pwledger::Secret dst(std::move(src));

  dst.with_read_access([&](std::span<const char> buf) {
    ASSERT_EQ(std::string_view(buf.data(), buf.size()), kMaterial);
  });
}
