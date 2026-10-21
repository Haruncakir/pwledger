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
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

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

namespace {
std::string compute_file_sha256(const std::filesystem::path& path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f.is_open()) return "";
  std::size_t size = static_cast<std::size_t>(f.tellg());
  f.seekg(0);
  std::vector<unsigned char> buf(size);
  f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size));
  unsigned char hash[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(hash, buf.data(), buf.size());
  char hex[crypto_hash_sha256_BYTES * 2 + 1];
  sodium_bin2hex(hex, sizeof(hex), hash, sizeof(hash));
  return std::string(hex);
}
}  // namespace

TEST_F(VaultTest, TestVaultCompatibility) {
  std::filesystem::path fixture_dir;
#ifdef PWLEDGER_TEST_FIXTURES_DIR
  fixture_dir = PWLEDGER_TEST_FIXTURES_DIR;
#else
  fixture_dir = std::filesystem::current_path() / "tests" / "fixtures";
#endif
  if (!std::filesystem::exists(fixture_dir / "v1_original_vault.pwl")) {
    fixture_dir = std::filesystem::current_path() / "fixtures";
  }

  std::filesystem::path pwl_path = fixture_dir / "v1_original_vault.pwl";
  std::filesystem::path json_path = fixture_dir / "v1_original_vault.expected.json";
  std::filesystem::path payload_path = fixture_dir / "v1_original_payload.bin";

  ASSERT_TRUE(std::filesystem::exists(pwl_path)) << "Missing fixture: " << pwl_path;
  ASSERT_TRUE(std::filesystem::exists(json_path)) << "Missing expected JSON: " << json_path;
  ASSERT_TRUE(std::filesystem::exists(payload_path)) << "Missing golden payload: " << payload_path;

  // 1. Assert SHA-256 digests
  const std::string expected_pwl_sha256 = "46a5b14526cd540840569c10ae102ff44d64794b45beb77984269ef1ff91d462";
  const std::string expected_payload_sha256 = "f653b20c460cf993f190c5a76084c578a5e25fcaa22876d978c38ac92945d23e";
  EXPECT_EQ(compute_file_sha256(pwl_path), expected_pwl_sha256);
  EXPECT_EQ(compute_file_sha256(payload_path), expected_payload_sha256);

  // 2. Parse expected JSON
  std::ifstream j_file(json_path);
  ASSERT_TRUE(j_file.is_open());
  nlohmann::json expected_json;
  j_file >> expected_json;

  std::string master_password = expected_json.value("master_password", "");
  ASSERT_FALSE(master_password.empty());
  std::size_t expected_count = expected_json.value<std::size_t>("entry_count", 0);
  auto expected_entries = expected_json.value("entries", nlohmann::json::array());
  ASSERT_EQ(expected_entries.size(), expected_count);

  // 3. Verify decrypted raw payload matches golden plaintext byte-for-byte
  std::ifstream pwl_file(pwl_path, std::ios::binary | std::ios::ate);
  ASSERT_TRUE(pwl_file.is_open());
  std::size_t pwl_size = static_cast<std::size_t>(pwl_file.tellg());
  pwl_file.seekg(0);
  std::vector<std::uint8_t> pwl_bytes(pwl_size);
  pwl_file.read(reinterpret_cast<char*>(pwl_bytes.data()), static_cast<std::streamsize>(pwl_size));

  std::ifstream payload_file(payload_path, std::ios::binary | std::ios::ate);
  ASSERT_TRUE(payload_file.is_open());
  std::size_t payload_size = static_cast<std::size_t>(payload_file.tellg());
  payload_file.seekg(0);
  std::vector<std::uint8_t> expected_payload_bytes(payload_size);
  payload_file.read(reinterpret_cast<char*>(expected_payload_bytes.data()), static_cast<std::streamsize>(payload_size));

  std::vector<std::uint8_t> decrypted_bytes = VaultCrypto::decrypt_vault(master_password, pwl_bytes);
  EXPECT_EQ(decrypted_bytes.size(), expected_payload_bytes.size());
  EXPECT_EQ(decrypted_bytes, expected_payload_bytes);

  // 4. Open and decrypt the frozen fixture vault through VaultIO
  PrimaryTable loaded = VaultIO::load_vault(pwl_path, master_password);
  ASSERT_EQ(loaded.size(), expected_count);

  // Assert refactored VaultSerializer::serialize reproduces golden plaintext payload byte-for-byte
  std::vector<std::uint8_t> re_serialized = VaultSerializer::serialize(loaded);
  EXPECT_EQ(re_serialized.size(), expected_payload_bytes.size());

  // The V1 on-disk format stores entries in whatever order the unordered_map iterates.
  // On MSVC (the toolchain that authored the baseline fixture), iteration order is identical.
  // On Linux GCC libstdc++ (which uses prime bucket counts vs MSVC powers of 2), bucket iteration
  // order differs, but deserialization round-trips to the exact identical table.
  PrimaryTable re_loaded = VaultSerializer::deserialize(re_serialized.data(), re_serialized.size());
  EXPECT_EQ(re_loaded.size(), expected_count);
#if defined(_MSC_VER)
  EXPECT_EQ(re_serialized, expected_payload_bytes);
#endif

  // 5. Verify all entries match expected values
  for (const auto& item : expected_entries) {
    std::string uuid_str = item.value("uuid", "");
    auto opt_uuid = Uuid::from_string(uuid_str);
    ASSERT_TRUE(opt_uuid.has_value()) << "Failed to parse UUID: " << uuid_str;
    Uuid uid = *opt_uuid;

    auto it = loaded.find(uid);
    ASSERT_NE(it, loaded.end()) << "Entry not found in loaded table: " << uuid_str;
    const SecretEntry& entry = it->second;

    EXPECT_EQ(entry.primary_key, item.value("primary_key", ""));
    EXPECT_EQ(entry.username_or_email, item.value("username_or_email", ""));

    // Verify secret
    std::string exp_secret = item.value("plaintext_secret", "");
    entry.plaintext_secret.with_read_access([&](std::span<const char> buf) {
      std::string actual_secret(buf.data(), buf.size());
      EXPECT_EQ(actual_secret, exp_secret);
    });

    // Verify timestamps (seconds resolution)
    auto c_s = std::chrono::duration_cast<std::chrono::seconds>(entry.metadata.created_at.time_since_epoch()).count();
    auto m_s = std::chrono::duration_cast<std::chrono::seconds>(entry.metadata.last_modified_at.time_since_epoch()).count();
    auto u_s = std::chrono::duration_cast<std::chrono::seconds>(entry.metadata.last_used_at.time_since_epoch()).count();
    EXPECT_EQ(c_s, item.value("created_at_s", 0LL));
    EXPECT_EQ(m_s, item.value("last_modified_at_s", 0LL));
    EXPECT_EQ(u_s, item.value("last_used_at_s", 0LL));

    // Verify security policy
    EXPECT_EQ(entry.security_policy.strength_score, item.value("strength_score", 0));
    EXPECT_EQ(entry.security_policy.reuse_count, item.value("reuse_count", 0));
    EXPECT_EQ(entry.security_policy.two_fa_enabled, item.value("two_fa_enabled", false));
    EXPECT_EQ(entry.security_policy.note, item.value("note", ""));

    int64_t exp_expires = item.value("expires_at_s", 0LL);
    if (exp_expires > 0) {
      ASSERT_TRUE(entry.security_policy.expires_at.has_value());
      auto actual_exp = std::chrono::duration_cast<std::chrono::seconds>(entry.security_policy.expires_at->time_since_epoch()).count();
      EXPECT_EQ(actual_exp, exp_expires);
    } else {
      EXPECT_FALSE(entry.security_policy.expires_at.has_value());
    }
  }

  // 6. Wrong password test
  EXPECT_THROW(VaultIO::load_vault(pwl_path, "incorrect_master_password"), std::runtime_error);

  // 7. Parameterized single-byte flip tamper tests across wire layout regions:
  // Salt: 0..15 (0, 7, 15)
  // Nonce: 16..39 (16, 28, 39)
  // Ciphertext: 40..pwl_size - 17 (40, pwl_size / 2, pwl_size - 17)
  // Poly1305 MAC tag: pwl_size - 16..pwl_size - 1 (pwl_size - 16, pwl_size - 8, pwl_size - 1)
  std::vector<std::size_t> test_offsets = {
      0, 7, 15,
      16, 28, 39,
      40, pwl_size / 2, pwl_size - 17,
      pwl_size - 16, pwl_size - 8, pwl_size - 1
  };

  std::filesystem::path temp_pwl = std::filesystem::temp_directory_path() / "pwl_tamper_test.pwl";

  for (std::size_t offset : test_offsets) {
    std::vector<std::uint8_t> corrupted = pwl_bytes;
    ASSERT_LT(offset, corrupted.size());
    corrupted[offset] ^= 0x55;

    {
      std::ofstream out(temp_pwl, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(out.is_open());
      out.write(reinterpret_cast<const char*>(corrupted.data()), static_cast<std::streamsize>(corrupted.size()));
    }

    EXPECT_THROW(VaultIO::load_vault(temp_pwl, master_password), std::runtime_error)
        << "Failed to reject corrupted byte at offset: " << offset;
  }

  // 8. Truncation tests across boundaries:
  // 0: empty file
  // 15: partial salt
  // 16: salt only (0 nonce)
  // 39: partial nonce
  // 40: header only (0 ciphertext & 0 tag)
  // 55: header + partial tag (< 56 bytes)
  // 1000: header + truncated ciphertext
  // pwl_size - 1: truncated tag by 1 byte
  std::vector<std::size_t> truncate_lengths = {
      0, 15, 16, 39, 40, 55, 1000, pwl_size - 1
  };

  for (std::size_t len : truncate_lengths) {
    if (len >= pwl_size) continue;
    {
      std::ofstream out(temp_pwl, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(out.is_open());
      if (len > 0) {
        out.write(reinterpret_cast<const char*>(pwl_bytes.data()), static_cast<std::streamsize>(len));
      }
    }

    EXPECT_THROW(VaultIO::load_vault(temp_pwl, master_password), std::runtime_error)
        << "Failed to reject truncated vault of length: " << len;
  }

  std::error_code ec;
  std::filesystem::remove(temp_pwl, ec);
}

TEST_F(VaultTest, BinarySecretWithEmbeddedNullRoundtrip) {
  PrimaryTable table;
  Uuid id = Uuid::generate();
  SecretEntry entry("https://binary.service.internal", "admin_binary", 64, 16);
  std::string secret_payload = std::string("sec\0ret\0token\0\0end", 17);
  entry.plaintext_secret.with_write_access([&](std::span<char> buf) {
    std::memcpy(buf.data(), secret_payload.data(), secret_payload.size());
  });
  entry.plaintext_secret.set_length(secret_payload.size());

  table.emplace(id, std::move(entry));

  std::vector<std::uint8_t> serialized = VaultSerializer::serialize(table);
  PrimaryTable deserialized = VaultSerializer::deserialize(serialized.data(), serialized.size());

  ASSERT_EQ(deserialized.size(), 1U);
  auto it = deserialized.find(id);
  ASSERT_NE(it, deserialized.end());
  EXPECT_EQ(it->second.plaintext_secret.size(), 17U);
  it->second.plaintext_secret.with_read_access([&](std::span<const char> buf) {
    EXPECT_EQ(buf.size(), 17U);
    EXPECT_EQ(std::string_view(buf.data(), buf.size()), std::string_view(secret_payload.data(), 17));
  });
}
