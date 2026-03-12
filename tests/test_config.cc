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

#include <pwledger/Config.h>
#include <pwledger/VaultPath.h>

#include <filesystem>
#include <fstream>
#include <string>

using namespace pwledger;

class ConfigTest : public ::testing::Test {
protected:
  void SetUp() override {
    test_config_path = std::filesystem::temp_directory_path() / "pwledger_test_config.json";
    if (std::filesystem::exists(test_config_path)) {
      std::filesystem::remove(test_config_path);
    }
  }

  void TearDown() override {
    if (std::filesystem::exists(test_config_path)) {
      std::filesystem::remove(test_config_path);
    }
  }

  void write_json(const std::string& content) {
    std::ofstream ofs(test_config_path);
    ofs << content;
  }

  std::filesystem::path test_config_path;
};

// 1. Default-constructed Config has expected defaults.
TEST_F(ConfigTest, DefaultValues) {
  Config cfg;

  EXPECT_EQ(cfg.security.auto_lock_seconds, 300);
  EXPECT_EQ(cfg.security.clear_clipboard_seconds, 20);
  EXPECT_TRUE(cfg.security.lock_on_suspend);
  EXPECT_TRUE(cfg.security.mlock_secrets);

  EXPECT_EQ(cfg.vault.directory, "");
  EXPECT_EQ(cfg.vault.default_vault, "vault.dat");
  EXPECT_FALSE(cfg.vault.auto_unlock);

  EXPECT_TRUE(cfg.cli.color);
  EXPECT_TRUE(cfg.cli.confirm_before_delete);
  EXPECT_TRUE(cfg.cli.clipboard_copy_default);

  EXPECT_TRUE(cfg.integration.browser_native_host);
  EXPECT_TRUE(cfg.integration.allowed_extensions.empty());
}

// 2. Loading from a non-existent file returns defaults without throwing.
TEST_F(ConfigTest, LoadMissingFile) {
  auto nonexistent = std::filesystem::temp_directory_path() / "does_not_exist_pwledger.json";
  Config cfg;
  EXPECT_NO_THROW(cfg = load_config(nonexistent));

  // Should be identical to defaults.
  Config defaults;
  EXPECT_EQ(cfg.security.auto_lock_seconds, defaults.security.auto_lock_seconds);
  EXPECT_EQ(cfg.vault.default_vault, defaults.vault.default_vault);
  EXPECT_EQ(cfg.cli.color, defaults.cli.color);
}

// 3. Save and load round-trip preserves all fields.
TEST_F(ConfigTest, SaveAndLoad) {
  Config original;
  original.security.auto_lock_seconds       = 600;
  original.security.clear_clipboard_seconds = 10;
  original.security.lock_on_suspend         = false;
  original.security.mlock_secrets           = false;

  original.vault.directory     = "/custom/vaults";
  original.vault.default_vault = "mydb.pwl";
  original.vault.auto_unlock   = true;

  original.cli.color                  = false;
  original.cli.confirm_before_delete  = false;
  original.cli.clipboard_copy_default = false;

  original.integration.browser_native_host = false;
  original.integration.allowed_extensions  = {"ext1", "ext2"};

  EXPECT_NO_THROW(save_config(original, test_config_path));

  Config loaded = load_config(test_config_path);

  EXPECT_EQ(loaded.security.auto_lock_seconds, 600);
  EXPECT_EQ(loaded.security.clear_clipboard_seconds, 10);
  EXPECT_FALSE(loaded.security.lock_on_suspend);
  EXPECT_FALSE(loaded.security.mlock_secrets);

  // Note: directory will have tilde expansion applied, but "/custom/vaults"
  // has no tilde so it should be unchanged.
  EXPECT_EQ(loaded.vault.directory, "/custom/vaults");
  EXPECT_EQ(loaded.vault.default_vault, "mydb.pwl");
  EXPECT_TRUE(loaded.vault.auto_unlock);

  EXPECT_FALSE(loaded.cli.color);
  EXPECT_FALSE(loaded.cli.confirm_before_delete);
  EXPECT_FALSE(loaded.cli.clipboard_copy_default);

  EXPECT_FALSE(loaded.integration.browser_native_host);
  ASSERT_EQ(loaded.integration.allowed_extensions.size(), 2);
  EXPECT_EQ(loaded.integration.allowed_extensions[0], "ext1");
  EXPECT_EQ(loaded.integration.allowed_extensions[1], "ext2");
}

// 4. Partial JSON only overrides specified keys; all others retain defaults.
TEST_F(ConfigTest, PartialJson) {
  write_json(R"({ "cli": { "color": false } })");

  Config cfg = load_config(test_config_path);

  // Overridden value
  EXPECT_FALSE(cfg.cli.color);

  // Everything else should be default
  EXPECT_TRUE(cfg.cli.confirm_before_delete);
  EXPECT_TRUE(cfg.cli.clipboard_copy_default);
  EXPECT_EQ(cfg.security.auto_lock_seconds, 300);
  EXPECT_EQ(cfg.vault.default_vault, "vault.dat");
  EXPECT_TRUE(cfg.integration.browser_native_host);
}

// 5. Malformed JSON throws std::runtime_error.
TEST_F(ConfigTest, MalformedJson) {
  write_json("this is { not valid json !!!");

  EXPECT_THROW(load_config(test_config_path), std::runtime_error);
}

// 6. resolve_vault_dir respects VaultConfig::directory override.
TEST_F(ConfigTest, VaultDirOverride) {
  VaultConfig vcfg;
  vcfg.directory = "/custom/dir";

  auto dir = resolve_vault_dir(vcfg);
  EXPECT_EQ(dir, std::filesystem::path("/custom/dir"));
}

// 7. resolve_vault_dir falls through to platform default when directory is empty.
TEST_F(ConfigTest, VaultDirDefault) {
  VaultConfig vcfg;
  vcfg.directory = "";

  auto dir = resolve_vault_dir(vcfg);
  EXPECT_EQ(dir, default_vault_dir());
}

// 8. default_config_path returns a non-empty path ending in config.json.
TEST_F(ConfigTest, DefaultConfigPath) {
  auto path = default_config_path();
  EXPECT_FALSE(path.empty());
  EXPECT_EQ(path.filename(), "config.json");
}

// 9. resolve_vault_path joins directory and default_vault correctly.
TEST_F(ConfigTest, ResolveVaultPath) {
  VaultConfig vcfg;
  vcfg.directory     = "/my/vaults";
  vcfg.default_vault = "personal.pwl";

  auto path = resolve_vault_path(vcfg);
  EXPECT_EQ(path, std::filesystem::path("/my/vaults/personal.pwl"));
}
