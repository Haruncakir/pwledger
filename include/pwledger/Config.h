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

#ifndef PWLEDGER_CONFIG_H
#define PWLEDGER_CONFIG_H

#include <filesystem>
#include <string>
#include <vector>

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This header defines the user-facing configuration schema for pwledger.
// Configuration is stored as a JSON file at a platform-specific location:
//
//   Linux:   $XDG_CONFIG_HOME/pwledger/config.json
//            (fallback: ~/.config/pwledger/config.json)
//   macOS:   ~/Library/Application Support/pwledger/config.json
//   Windows: %APPDATA%\pwledger\config.json
//
// MERGE SEMANTICS
// ---------------
// When loading, only the keys present in the JSON file override the compiled
// defaults. Missing keys retain their default values. This means a minimal
// config file like  {"cli": {"color": false}}  is valid and only disables
// color while leaving every other setting at its default.
//
// PATH CONVENTIONS
// ----------------
// The vault directory in VaultConfig may be empty (meaning "use the platform
// default from VaultPath.h") or a user-supplied path. The tilde character (~)
// at the start of a path is expanded to $HOME / %USERPROFILE% at load time.
//
// ============================================================================

namespace pwledger {

// ----------------------------------------------------------------------------
// SecurityConfig
// ----------------------------------------------------------------------------
// Controls security-related behavior such as auto-lock timeouts and memory
// locking. These settings affect both the CLI and the native messaging host.
struct SecurityConfig {
  int  auto_lock_seconds       = 300;   // Idle timeout before auto-lock (0 = disabled)
  int  clear_clipboard_seconds = 20;    // Seconds before clipboard auto-clear (0 = disabled)
  bool lock_on_suspend         = true;  // Lock vault when the OS suspends
  bool mlock_secrets           = true;  // Use mlock/VirtualLock on secret memory
};

// ----------------------------------------------------------------------------
// VaultConfig
// ----------------------------------------------------------------------------
// Overrides for vault file location. An empty directory string means "use the
// platform default" (see VaultPath.h).
struct VaultConfig {
  std::string directory     = "";          // Override vault directory (empty = platform default)
  std::string default_vault = "vault.dat"; // Vault filename within the directory
  bool        auto_unlock   = false;       // Reserved for future use
};

// ----------------------------------------------------------------------------
// CliConfig
// ----------------------------------------------------------------------------
// Settings that affect the interactive CLI experience.
struct CliConfig {
  bool color                  = true;  // Enable ANSI color output
  bool confirm_before_delete  = true;  // Prompt for confirmation on delete
  bool clipboard_copy_default = true;  // Copy to clipboard by default on 'get'
};

// ----------------------------------------------------------------------------
// IntegrationConfig
// ----------------------------------------------------------------------------
// Settings for browser extension / native messaging host integration.
struct IntegrationConfig {
  bool                     browser_native_host = true;  // Enable the native host
  std::vector<std::string> allowed_extensions;          // Allowed browser extension origins
};

// ----------------------------------------------------------------------------
// Config
// ----------------------------------------------------------------------------
// Top-level configuration aggregate. Default-constructed Config contains all
// compiled defaults; load_config() merges the on-disk JSON over these defaults.
struct Config {
  SecurityConfig    security;
  VaultConfig       vault;
  CliConfig         cli;
  IntegrationConfig integration;
};

// ============================================================================
// Free functions
// ============================================================================

// Returns the platform-specific path for config.json. See DESIGN NOTES above.
std::filesystem::path default_config_path();

// Loads configuration from the default platform path. If the file does not
// exist, returns a default-constructed Config (no error). If the file exists
// but contains invalid JSON, throws std::runtime_error.
Config load_config();

// Loads configuration from an explicit path. Same error semantics as above.
Config load_config(const std::filesystem::path& path);

// Saves configuration to the default platform path, creating parent
// directories if necessary.
void save_default_config(const Config& cfg);

// Saves configuration to an explicit path, creating parent directories if
// necessary.
void save_config(const Config& cfg, const std::filesystem::path& path);

}  // namespace pwledger

#endif  // PWLEDGER_CONFIG_H
