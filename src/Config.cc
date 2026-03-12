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

#include <pwledger/Config.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace pwledger {

// ============================================================================
// nlohmann::json serialization helpers
// ============================================================================
//
// Each from_json function uses .value() with a default so that missing keys
// silently fall back to the struct's compiled defaults, implementing the
// merge semantics described in Config.h.

// --- SecurityConfig ---------------------------------------------------------

void to_json(json& j, const SecurityConfig& s) {
  j = json{
      {"auto_lock_seconds", s.auto_lock_seconds},
      {"clear_clipboard_seconds", s.clear_clipboard_seconds},
      {"lock_on_suspend", s.lock_on_suspend},
      {"mlock_secrets", s.mlock_secrets},
  };
}

void from_json(const json& j, SecurityConfig& s) {
  SecurityConfig defaults;
  s.auto_lock_seconds       = j.value("auto_lock_seconds", defaults.auto_lock_seconds);
  s.clear_clipboard_seconds = j.value("clear_clipboard_seconds", defaults.clear_clipboard_seconds);
  s.lock_on_suspend         = j.value("lock_on_suspend", defaults.lock_on_suspend);
  s.mlock_secrets           = j.value("mlock_secrets", defaults.mlock_secrets);
}

// --- VaultConfig ------------------------------------------------------------

void to_json(json& j, const VaultConfig& v) {
  j = json{
      {"directory", v.directory},
      {"default_vault", v.default_vault},
      {"auto_unlock", v.auto_unlock},
  };
}

void from_json(const json& j, VaultConfig& v) {
  VaultConfig defaults;
  v.directory     = j.value("directory", defaults.directory);
  v.default_vault = j.value("default_vault", defaults.default_vault);
  v.auto_unlock   = j.value("auto_unlock", defaults.auto_unlock);
}

// --- CliConfig --------------------------------------------------------------

void to_json(json& j, const CliConfig& c) {
  j = json{
      {"color", c.color},
      {"confirm_before_delete", c.confirm_before_delete},
      {"clipboard_copy_default", c.clipboard_copy_default},
  };
}

void from_json(const json& j, CliConfig& c) {
  CliConfig defaults;
  c.color                  = j.value("color", defaults.color);
  c.confirm_before_delete  = j.value("confirm_before_delete", defaults.confirm_before_delete);
  c.clipboard_copy_default = j.value("clipboard_copy_default", defaults.clipboard_copy_default);
}

// --- IntegrationConfig ------------------------------------------------------

void to_json(json& j, const IntegrationConfig& i) {
  j = json{
      {"browser_native_host", i.browser_native_host},
      {"allowed_extensions", i.allowed_extensions},
  };
}

void from_json(const json& j, IntegrationConfig& i) {
  IntegrationConfig defaults;
  i.browser_native_host = j.value("browser_native_host", defaults.browser_native_host);
  if (j.contains("allowed_extensions") && j["allowed_extensions"].is_array()) {
    i.allowed_extensions = j["allowed_extensions"].get<std::vector<std::string>>();
  } else {
    i.allowed_extensions = defaults.allowed_extensions;
  }
}

// --- Config (top level) -----------------------------------------------------

void to_json(json& j, const Config& cfg) {
  j = json{
      {"security", cfg.security},
      {"vault", cfg.vault},
      {"cli", cfg.cli},
      {"integration", cfg.integration},
  };
}

void from_json(const json& j, Config& cfg) {
  Config defaults;
  if (j.contains("security") && j["security"].is_object()) {
    cfg.security = j["security"].get<SecurityConfig>();
  } else {
    cfg.security = defaults.security;
  }
  if (j.contains("vault") && j["vault"].is_object()) {
    cfg.vault = j["vault"].get<VaultConfig>();
  } else {
    cfg.vault = defaults.vault;
  }
  if (j.contains("cli") && j["cli"].is_object()) {
    cfg.cli = j["cli"].get<CliConfig>();
  } else {
    cfg.cli = defaults.cli;
  }
  if (j.contains("integration") && j["integration"].is_object()) {
    cfg.integration = j["integration"].get<IntegrationConfig>();
  } else {
    cfg.integration = defaults.integration;
  }
}

// ============================================================================
// Path helpers
// ============================================================================

// Expands a leading '~' to the user's home directory. This is a convenience
// for config files written by humans; no other shell expansion is performed.
static std::filesystem::path expand_tilde(const std::string& raw) {
  if (raw.empty() || raw[0] != '~') {
    return std::filesystem::path(raw);
  }

  std::filesystem::path home;
#if defined(_WIN32)
  if (const char* profile = std::getenv("USERPROFILE")) {
    home = profile;
  } else {
    home = "C:\\";
  }
#else
  if (const char* h = std::getenv("HOME")) {
    home = h;
  } else {
    home = "/tmp";
  }
#endif

  // raw == "~"    → just home
  // raw == "~/foo" → home / "foo"
  if (raw.size() == 1) {
    return home;
  }
  // Skip the '~' and any immediately following separator.
  std::string_view rest(raw);
  rest.remove_prefix(1);
  if (!rest.empty() && (rest[0] == '/' || rest[0] == '\\')) {
    rest.remove_prefix(1);
  }
  return home / std::filesystem::path(rest);
}

std::filesystem::path default_config_path() {
  std::filesystem::path dir;

#if defined(_WIN32)
  if (const char* appdata = std::getenv("APPDATA")) {
    dir = std::filesystem::path(appdata) / "pwledger";
  } else if (const char* profile = std::getenv("USERPROFILE")) {
    dir = std::filesystem::path(profile) / "AppData" / "Roaming" / "pwledger";
  } else {
    dir = std::filesystem::current_path() / ".pwledger";
  }
#elif defined(__APPLE__)
  if (const char* home = std::getenv("HOME")) {
    dir = std::filesystem::path(home) / "Library" / "Application Support" / "pwledger";
  } else {
    dir = std::filesystem::current_path() / ".pwledger";
  }
#else
  // Linux / Unix — XDG Base Directory Specification
  if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg) {
    dir = std::filesystem::path(xdg) / "pwledger";
  } else if (const char* home = std::getenv("HOME")) {
    dir = std::filesystem::path(home) / ".config" / "pwledger";
  } else {
    dir = std::filesystem::current_path() / ".pwledger";
  }
#endif

  return dir / "config.json";
}

// ============================================================================
// Load / save
// ============================================================================

Config load_config(const std::filesystem::path& path) {
  if (!std::filesystem::exists(path)) {
    return Config{};  // Missing file → all defaults
  }

  std::ifstream ifs(path);
  if (!ifs.is_open()) {
    std::cerr << "Warning: could not open config file: " << path << "\n";
    return Config{};
  }

  json j;
  try {
    ifs >> j;
  } catch (const json::parse_error& e) {
    throw std::runtime_error("Failed to parse config file " + path.string() + ": " + e.what());
  }

  Config cfg = j.get<Config>();

  // Expand tilde in vault directory if the user specified one.
  if (!cfg.vault.directory.empty()) {
    cfg.vault.directory = expand_tilde(cfg.vault.directory).string();
  }

  return cfg;
}

Config load_config() { return load_config(default_config_path()); }

void save_config(const Config& cfg, const std::filesystem::path& path) {
  std::filesystem::create_directories(path.parent_path());

  std::ofstream ofs(path);
  if (!ofs.is_open()) {
    throw std::runtime_error("Failed to open config file for writing: " + path.string());
  }

  json j = cfg;
  ofs << j.dump(2) << '\n';  // Pretty-printed with 2-space indent
}

void save_default_config(const Config& cfg) { save_config(cfg, default_config_path()); }

}  // namespace pwledger
