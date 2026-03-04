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

#include <pwledger/Clipboard.h>
#include <pwledger/PrimaryTable.h>
#include <pwledger/ProcessHardening.h>
#include <pwledger/Secret.h>

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This file will become the native messaging host for the pwledger browser
// extension. Native messaging is the standard mechanism for browser
// extensions (Chrome, Firefox, Edge) to communicate with a local application
// over stdin/stdout using length-prefixed JSON messages.
//
// ARCHITECTURE (PLANNED)
// ----------------------
//
//   Browser extension  <-->  Native Messaging Host  <-->  pwledger core
//   (JavaScript)             (this binary)               (Secret, PrimaryTable)
//
// The host process is launched by the browser on demand (one instance per
// browser profile). Communication follows the WebExtensions native messaging
// protocol:
//   1. The browser sends a 4-byte little-endian message length, followed by
//      the JSON payload.
//   2. The host reads the message, processes the request, and responds in
//      the same format.
//   3. When the extension disconnects, stdin reaches EOF and the host exits.
//
// SECURITY CONSIDERATIONS
// -----------------------
// - The host must validate the browser's origin via the native messaging
//   manifest's "allowed_origins" field (set during installation).
// - All secret material stays in sodium-hardened memory; the host never
//   sends plaintext secrets to the extension. Instead, it fills form fields
//   directly or copies to the clipboard with a timed auto-clear.
// - The host must inherit the same process-hardening measures as the CLI
//   (harden_process, no core dumps, no debugger attachment).
//
// REGISTRATION
// ------------
// A JSON manifest file must be installed at a browser-specific location to
// register this binary:
//   Chrome (Linux): ~/.config/google-chrome/NativeMessagingHosts/
//   Firefox (Linux): ~/.mozilla/native-messaging-hosts/
//   Chrome (Windows): HKCU\Software\Google\Chrome\NativeMessagingHosts
//
// TODO(#issue-N): implement the stdin/stdout message loop.
// TODO(#issue-N): implement the JSON request/response protocol.
// TODO(#issue-N): create the installation script for manifest registration.
//
// ============================================================================

int main() {
  // Apply the same process hardening as the CLI before touching any secrets.
  pwledger::harden_process();

  // sodium_init must be called once before any Secret is constructed.
  if (sodium_init() < 0) {
    return 1;
  }

  // Stub: native messaging host not yet implemented.
  // See DESIGN NOTES above for the planned architecture.
  return 0;
}
