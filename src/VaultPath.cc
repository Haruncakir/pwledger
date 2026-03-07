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

#include <pwledger/VaultPath.h>

namespace pwledger {

// Cross-platform helper to resolve the default vault directory and file path.
//
// Linux: $XDG_DATA_HOME/pwledger or ~/.local/share/pwledger
// macOS: ~/Library/Application Support/pwledger
// Windows: %LOCALAPPDATA%\pwledger or %USERPROFILE%\AppData\Local\pwledger

std::filesystem::path default_vault_dir() {
  std::filesystem::path dir;

#if defined(_WIN32)
  if (const char* local_appdata = std::getenv("LOCALAPPDATA")) {
    dir = std::filesystem::path(local_appdata) / "pwledger";
  } else if (const char* user_profile = std::getenv("USERPROFILE")) {
    dir = std::filesystem::path(user_profile) / "AppData" / "Local" / "pwledger";
  } else {
    // Fallback if environment is totally broken
    dir = std::filesystem::current_path() / ".pwledger";
  }
#elif defined(__APPLE__)
  if (const char* home = std::getenv("HOME")) {
    dir = std::filesystem::path(home) / "Library" / "Application Support" / "pwledger";
  } else {
    dir = std::filesystem::current_path() / ".pwledger";
  }
#else
  // Linux / Unix (XDG Base Directory Specification)
  if (const char* xdg_data_home = std::getenv("XDG_DATA_HOME"); xdg_data_home && *xdg_data_home) {
    dir = std::filesystem::path(xdg_data_home) / "pwledger";
  } else if (const char* home = std::getenv("HOME")) {
    dir = std::filesystem::path(home) / ".local" / "share" / "pwledger";
  } else {
    dir = std::filesystem::current_path() / ".pwledger";
  }
#endif

  return dir;
}

std::filesystem::path default_vault_path() {
  return default_vault_dir() / "vault.dat";
}

// Ensures the vault directory exists, creating it with restrictive permissions
// if it does not. Throws std::filesystem::filesystem_error on failure.
void ensure_vault_dir_exists() {
  std::filesystem::path dir = default_vault_dir();
  if (!std::filesystem::exists(dir)) {
    // Create with owner-only access (rwx------)
    std::filesystem::create_directories(dir);
    std::filesystem::permissions(
        dir,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write | std::filesystem::perms::owner_exec,
        std::filesystem::perm_options::replace);
  }
}

}  // namespace pwledger
