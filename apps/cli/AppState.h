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

#ifndef PWLEDGER_CLI_APP_STATE_H
#define PWLEDGER_CLI_APP_STATE_H

#include <pwledger/Config.h>
#include <pwledger/PrimaryTable.h>
#include <pwledger/Secret.h>

#include <filesystem>

namespace pwledger {

// State passed to all CLI commands.
struct AppState {
  pwledger::Config config;
  pwledger::PrimaryTable table;
  pwledger::Secret master_password{1};  // placeholder until initialized
  std::filesystem::path vault_path;
};

}  // namespace pwledger

#endif  // PWLEDGER_CLI_APP_STATE_H
