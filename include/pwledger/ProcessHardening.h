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

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

namespace pwledger {

// ----------------------------------------------------------------------------
// harden_process
// ----------------------------------------------------------------------------
// Best-effort process hardening applied once at startup, before any Secret
// is constructed. These mitigations reduce the risk of sensitive data leaking
// through core dumps or debugger attachment. They are not a substitute for
// OS-level hardening (seccomp, AppArmor, SELinux) but serve as a first layer
// for a CLI application.
//
// None of these calls are fatal on failure; a system that disallows them
// (e.g., a container with limited capabilities) should still run normally.
void harden_process() noexcept;

}  // namespace pwledger

#endif  // PWLEDGER_PROCESSHARDENING_H
