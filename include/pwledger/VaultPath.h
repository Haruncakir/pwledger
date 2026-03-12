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

#ifndef PWLEDGER_VAULTPATH_H
#define PWLEDGER_VAULTPATH_H

#include <cstdlib>
#include <filesystem>
#include <string>


namespace pwledger {

// Forward declaration to avoid pulling in Config.h from every translation unit.
struct VaultConfig;

// ----------------------------------------------------------------------------
// VaultPath
// ----------------------------------------------------------------------------
// Cross-platform helper to resolve the default vault directory and file path.
//
// Linux: $XDG_DATA_HOME/pwledger or ~/.local/share/pwledger
// macOS: ~/Library/Application Support/pwledger
// Windows: %LOCALAPPDATA%\pwledger or %USERPROFILE%\AppData\Local\pwledger

std::filesystem::path default_vault_dir();

std::filesystem::path default_vault_path();

// Config-aware overloads. If VaultConfig::directory is non-empty, it is used
// as the vault directory (tilde expansion is expected to have been applied by
// load_config). Otherwise, falls through to the platform default.
std::filesystem::path resolve_vault_dir(const VaultConfig& cfg);
std::filesystem::path resolve_vault_path(const VaultConfig& cfg);

// Ensures the vault directory exists, creating it with restrictive permissions
// if it does not. Throws std::filesystem::filesystem_error on failure.
void ensure_vault_dir_exists();
void ensure_vault_dir_exists(const std::filesystem::path& dir);

}  // namespace pwledger

#endif  // PWLEDGER_VAULTPATH_H
