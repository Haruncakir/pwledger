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

#include "AppState.h"
#include "CommandLoop.h"
#include "SecretIO.h"

#include <pwledger/Config.h>
#include <pwledger/ProcessHardening.h>
#include <pwledger/Secret.h>
#include <pwledger/VaultIO.h>
#include <pwledger/VaultPath.h>

#include <cstring>
#include <iostream>
#include <span>

#include <sodium.h>

// ============================================================================
// Entry point
// ============================================================================

int main() {
  // Process hardening must happen before any Secret is constructed.
  // See harden_process() and "KNOWN LIMITATIONS" in Secret.h.
  pwledger::harden_process();

  // sodium_init must be called once before any Secret is constructed.
  // Returns 0 on success, 1 if already initialized, -1 on failure.
  if (sodium_init() < 0) {
    std::cerr << "Fatal: libsodium initialization failed.\n";
    return 1;
  }

  pwledger::AppState state;

  // Load user configuration (missing file -> defaults).
  try {
    state.config = pwledger::load_config();
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to load config: " << e.what()
              << ". Using defaults.\n";
  }

  try {
    auto vault_dir = pwledger::resolve_vault_dir(state.config.vault);
    pwledger::ensure_vault_dir_exists(vault_dir);
    state.vault_path = pwledger::resolve_vault_path(state.config.vault);
  } catch (const std::exception& e) {
    std::cerr << "Fatal: Failed to create vault directory: " << e.what() << '\n';
    return 1;
  }

  if (pwledger::VaultIO::vault_exists(state.vault_path)) {
    std::cout << "Found existing vault at " << state.vault_path << "\n";
    bool loaded = false;
    // Allow up to 3 attempts
    for (int attempts = 0; attempts < 3; ++attempts) {
      pwledger::Secret pwd(256);
      pwledger::prompt_secret("Master password", pwd, 256);
      try {
        pwd.with_read_access([&](std::span<const char> buf) {
          std::size_t len = ::strnlen(buf.data(), buf.size());
          pwledger::PrimaryTable t = pwledger::VaultIO::load_vault(state.vault_path, std::string_view(buf.data(), len));
          state.table = std::move(t);
        });
        state.master_password = std::move(pwd);
        loaded = true;
        std::cout << "Vault loaded successfully (" << state.table.size() << " entries).\n";
        break;
      } catch (const std::exception& e) {
        std::cout << "Failed to decrypt vault: " << e.what() << "\n";
      }
    }
    if (!loaded) {
      std::cerr << "Fatal: Too many failed decryption attempts.\n";
      return 1;
    }
  } else {
    std::cout << "No existing vault found at " << state.vault_path << ".\n";
    std::cout << "Creating a new vault.\n";
    pwledger::Secret pwd(256);
    pwledger::prompt_secret("Set master password", pwd, 256, /*confirm=*/true);
    state.master_password = std::move(pwd);
    pwledger::save_vault_safe(state);
    std::cout << "Vault created.\n";
  }

  pwledger::run_command_loop(state);

  // Final save on graceful exit
  pwledger::save_vault_safe(state);
  // Secret::~Secret, which calls sodium_free, zeroing and releasing every
  // sodium-hardened allocation before the process exits.
  return 0;
}
