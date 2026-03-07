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

#ifndef PWLEDGER_PROCESSHARDENING_H
#define PWLEDGER_PROCESSHARDENING_H

// ============================================================================
// DESIGN NOTES
// ============================================================================
//
// This header provides process-level security hardening applied once at
// startup, before any Secret is constructed. The mitigations here reduce the
// risk of sensitive data leaking through core dumps or debugger attachment.
// They are not a substitute for OS-level hardening (seccomp, AppArmor,
// SELinux, Hardened Runtime) but serve as a useful first layer for a CLI
// application and catch accidental misuse (e.g., running under a debugger
// in production).
//
// FAILURE MODEL
// -------------
// harden_process() is noexcept and best-effort. Platform API failures are
// logged to stderr but are not fatal: a system that disallows these calls
// (e.g., a container with a restrictive seccomp profile) should still run
// the application normally. The intent is to detect and warn, not to abort.
//
// CALL ORDER
// ----------
// harden_process() must be called before any pwledger::Secret is constructed.
// On Linux, prctl(PR_SET_DUMPABLE, 0) only affects memory allocated after
// the call; secrets allocated before it may still appear in a core dump.
// See also: Secret.h "KNOWN LIMITATIONS".
//
// ============================================================================

namespace pwledger {

// ----------------------------------------------------------------------------
// harden_process
// ----------------------------------------------------------------------------
// Applies all available process hardening for the current platform. Must be
// called once at process startup, before any Secret is constructed.
// See "CALL ORDER" and "FAILURE MODEL" above.
void harden_process() noexcept;

}  // namespace pwledger

#endif  // PWLEDGER_PROCESSHARDENING_H
