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

#ifndef PWLEDGER_CLIPBOARD_H
#define PWLEDGER_CLIPBOARD_H

#include <string_view>

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This header provides the public clipboard interface. It is intentionally
// decoupled from the data model (SecretEntry, Secret): the clipboard module's
// responsibility is writing and clearing raw bytes in the OS clipboard. The
// caller is responsible for opening an access guard on a Secret and passing
// the resulting span as a string_view. This inversion keeps the dependency
// graph acyclic and avoids pulling the entire data model into every
// translation unit that needs clipboard access.
//
// SECURITY NOTE
// -------------
// Clipboard operations are inherently insecure: other processes running under
// the same user session can read the clipboard at any time. Providing this
// feature is a usability concession. Callers should invoke clipboard_clear()
// as soon as the secret is no longer needed. Auto-clear after a configurable
// timeout is handled by ClipboardTimer.
//
// FAILURE MODEL
// -------------
// Both functions are noexcept. Platform API failures are logged to stderr
// and treated as best-effort: a clipboard failure must not interrupt normal
// application flow or expose a secret via an error path.
//
// ============================================================================

namespace pwledger {

// ----------------------------------------------------------------------------
// clipboard_write
// ----------------------------------------------------------------------------
// Writes `text` to the system clipboard. On Linux, requires xclip or xsel
// to be installed. On macOS, uses pbcopy. On Windows, uses the Win32
// OpenClipboard / SetClipboardData API.
//
// `text` must remain valid for the duration of this call. It is not retained.
void clipboard_write(std::string_view text) noexcept;

// ----------------------------------------------------------------------------
// clipboard_clear
// ----------------------------------------------------------------------------
// Overwrites the system clipboard with an empty string, removing any
// previously written secret. Should be called as soon as the user has
// finished using the copied secret.
void clipboard_clear() noexcept;

}  // namespace pwledger

#endif  // PWLEDGER_CLIPBOARD_H
