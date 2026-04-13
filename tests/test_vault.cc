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

#include <pwledger/PrimaryTable.h>
#include <pwledger/ProcessHardening.h>
#include <pwledger/Secret.h>
#include <pwledger/VaultCrypto.h>
#include <pwledger/VaultIO.h>
#include <pwledger/VaultPath.h>
#include <pwledger/VaultSerializer.h>
#include <pwledger/uuid.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>

using namespace pwledger;

class VaultTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    harden_process();
    if (sodium_init() < 0) {
      throw std::runtime_error("libsodium init failed");
    }
  }

  void SetUp() override {
    // Unique path per test to avoid parallel execution collisions on Windows
    auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string filename = std::string("pwledger_test_")
                         + info->test_suite_name() + "_"
                         + info->name() + ".dat";
    test_vault_path = std::filesystem::temp_directory_path() / filename;

    if (std::filesystem::exists(test_vault_path)) {
        std::filesystem::remove(test_vault_path);
    }
  }

  void TearDown() override {
    if (std::filesystem::exists(test_vault_path)) {
      std::filesystem::remove(test_vault_path);
    }
  }

  std::filesystem::path test_vault_path;
};

TEST_F(VaultTest, SerializationRoundTrip) {
  PrimaryTable original;
  
  // Entry 1: Minimal
  Uuid u1 = Uuid::generate();
  SecretEntry e1("example.com", "user1", 256, VaultCrypto::kSaltBytes);
  e1.plaintext_secret.with_write_access([](std::span<char> buf) {
    std::string s = "hunter2";
    std::memset(buf.data(), 0, buf.size());
    std::memcpy(buf.data(), s.data(), s.size());
  });
  e1.salt.with_write_access([](std::span<char> buf) {
    std::string s = "salt1";
    std::memset(buf.data(), 0, buf.size());
    std::memcpy(buf.data(), s.data(), s.size());
  });
  original.emplace(u1, std::move(e1));

  // Entry 2: Full features
  Uuid u2 = Uuid::generate();
  SecretEntry e2("bank.com", "finance@example.com", 256, VaultCrypto::kSaltBytes);
  e2.plaintext_secret.with_write_access([](std::span<char> buf) {
    std::string s = "very_long_complex_password_123!@#";
    std::memset(buf.data(), 0, buf.size());
    std::memcpy(buf.data(), s.data(), s.size());
  });
  e2.salt.with_write_access([](std::span<char> buf) {
    std::string s = "salt2";
    std::memset(buf.data(), 0, buf.size());
    std::memcpy(buf.data(), s.data(), s.size());
  });
  
  auto now = std::chrono::system_clock::now();
  // Truncate to seconds for comparison, as our format only stores seconds
  auto sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
  e2.metadata.created_at = std::chrono::system_clock::time_point(sec);
  e2.metadata.last_modified_at = std::chrono::system_clock::time_point(sec);
  e2.metadata.last_used_at = std::chrono::system_clock::time_point(sec);
  
  e2.security_policy.strength_score = 99;
  e2.security_policy.reuse_count = 0;
  e2.security_policy.two_fa_enabled = true;
  e2.security_policy.expires_at = std::chrono::system_clock::time_point(sec + std::chrono::seconds(86400));
  e2.security_policy.note = "PIN: 1234";
  original.emplace(u2, std::move(e2));

  // Serialize
  std::vector<std::uint8_t> buffer = VaultSerializer::serialize(original);
  EXPECT_GT(buffer.size(), 13); // Larger than header

  // Deserialize
  PrimaryTable recovered = VaultSerializer::deserialize(buffer.data(), buffer.size());

  ASSERT_EQ(original.size(), recovered.size());

  // Compare U1
  auto it1 = recovered.find(u1);
  ASSERT_NE(it1, recovered.end());
  EXPECT_EQ(it1->second.primary_key, "example.com");
  it1->second.plaintext_secret.with_read_access([](std::span<const char> buf) {
    EXPECT_STREQ(buf.data(), "hunter2");
  });

  // Compare U2
  auto it2 = recovered.find(u2);
  ASSERT_NE(it2, recovered.end());
  EXPECT_EQ(it2->second.primary_key, "bank.com");
  EXPECT_EQ(it2->second.security_policy.strength_score, 99);
  EXPECT_TRUE(it2->second.security_policy.two_fa_enabled);
  EXPECT_TRUE(it2->second.security_policy.expires_at.has_value());
  EXPECT_EQ(it2->second.security_policy.note, "PIN: 1234");
  it2->second.plaintext_secret.with_read_access([](std::span<const char> buf) {
    EXPECT_STREQ(buf.data(), "very_long_complex_password_123!@#");
  });
}

TEST_F(VaultTest, EncryptDecryptRoundTrip) {
  std::string password = "strong_master_password";
  std::vector<std::uint8_t> plaintext = {1, 2, 3, 4, 5, 255, 0, 42};

  std::vector<std::uint8_t> ciphertext = VaultCrypto::encrypt_vault(password, plaintext);
  EXPECT_GT(ciphertext.size(), plaintext.size() + VaultCrypto::kHeaderBytes);

  std::vector<std::uint8_t> decrypted = VaultCrypto::decrypt_vault(password, ciphertext);
  EXPECT_EQ(plaintext, decrypted);
}

TEST_F(VaultTest, DecryptWithWrongPasswordFails) {
  std::string password = "strong_master_password";
  std::vector<std::uint8_t> plaintext = {1, 2, 3};

  std::vector<std::uint8_t> ciphertext = VaultCrypto::encrypt_vault(password, plaintext);

  EXPECT_THROW(VaultCrypto::decrypt_vault("wrong_password", ciphertext), std::runtime_error);
}

TEST_F(VaultTest, DecryptCorruptDataFails) {
  std::string password = "password";
  std::vector<std::uint8_t> plaintext = {1, 2, 3};
  std::vector<std::uint8_t> ciphertext = VaultCrypto::encrypt_vault(password, plaintext);

  // Flip a bit in the ciphertext part
  ciphertext.back() ^= 1;

  EXPECT_THROW(VaultCrypto::decrypt_vault(password, ciphertext), std::runtime_error);
}

TEST_F(VaultTest, FullVaultIORoundtrip) {
  std::string master_password = "my_vault_password";

  PrimaryTable original;
  Uuid u1 = Uuid::generate();
  SecretEntry e1("test.com", "user", 256, VaultCrypto::kSaltBytes);
  e1.plaintext_secret.with_write_access([](std::span<char> buf) {
    std::string s = "my_secret_token";
    std::memset(buf.data(), 0, buf.size());
    std::memcpy(buf.data(), s.data(), s.size());
  });
  e1.salt.with_write_access([](std::span<char> buf) {
    std::string s = "somesalt";
    std::memset(buf.data(), 0, buf.size());
    std::memcpy(buf.data(), s.data(), s.size());
  });
  original.emplace(u1, std::move(e1));

  EXPECT_FALSE(VaultIO::vault_exists(test_vault_path));

  VaultIO::save_vault(test_vault_path, original, master_password);

  EXPECT_TRUE(VaultIO::vault_exists(test_vault_path));

  PrimaryTable recovered = VaultIO::load_vault(test_vault_path, master_password);

  ASSERT_EQ(recovered.size(), 1);
  auto it = recovered.find(u1);
  ASSERT_NE(it, recovered.end());

  it->second.plaintext_secret.with_read_access([](std::span<const char> buf) {
    EXPECT_STREQ(buf.data(), "my_secret_token");
  });
}
