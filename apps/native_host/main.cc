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

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This is the Native Messaging host for pwledger. It communicates with a
// browser extension via the Chrome/Firefox Native Messaging protocol:
// each message is prefixed with a 4-byte little-endian uint32 length,
// followed by a UTF-8 JSON payload.
//
// See the module headers for detailed design notes on:
//   - Security model and password handling (CommandHandlers.h)
//   - Message framing and size limits (NativeMessaging.h)
//   - Dispatch table and auto-lock (MessageLoop.h)
//
// ============================================================================

// On Windows, stdin/stdout must be switched to binary mode before any I/O.
#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#endif

#include "MessageLoop.h"

#include <pwledger/Config.h>
#include <pwledger/ProcessHardening.h>

#include <iostream>

#include <sodium.h>

// ============================================================================
// Entry point
// ============================================================================

int main() {
  // On Windows, stdin/stdout must be switched to binary mode before any I/O.
  // This must be done before sodium_init and before the message loop to
  // prevent text-mode translation of the raw length prefix bytes.
#ifdef _WIN32
  _setmode(_fileno(stdin),  _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif

  // Process hardening before any Secret is constructed.
  // See ProcessHardening.h and Secret.h "KNOWN LIMITATIONS".
  pwledger::harden_process();

  // sodium_init must be called once before any Secret is constructed.
  // Returns 0 on success, 1 if already initialized, -1 on failure.
  if (sodium_init() < 0) {
    std::cerr << "Fatal: libsodium initialization failed\n";
    return 1;
  }

  // Load user configuration (missing file -> defaults).
  pwledger::Config cfg;
  try {
    cfg = pwledger::load_config();
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to load config: " << e.what()
              << ". Using defaults.\n";
  }

  pwledger::run_message_loop(cfg);
  return 0;
}
