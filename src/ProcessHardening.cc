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

#include <pwledger/ProcessHardening.h>

#include <iostream>

#ifdef __linux__
#  include <sys/prctl.h>
#  include <sys/resource.h>
#endif

#ifdef __APPLE__
// TODO(#issue-N): import macOS Hardened Runtime entitlement check headers
// once macOS is a supported target. Candidate APIs:
//   - SecTaskCopyValueForEntitlement (check for
//     com.apple.security.cs.allow-unsigned-executable-memory)
//   - PT_DENY_ATTACH via ptrace to resist debugger attachment at the syscall
//     level (note: this is an advisory check, not a hard enforcement)
#endif

#ifdef _WIN32
// TODO(#issue-N): import Windows anti-debug headers once Windows is a
// supported target. Candidate APIs:
//   - IsDebuggerPresent / CheckRemoteDebuggerPresent (advisory; easily
//     bypassed, but catches accidental debugging in production)
//   - SetUnhandledExceptionFilter to suppress crash dialogs that may expose
//     register state and stack contents
#endif

namespace pwledger {

void harden_process() noexcept {
#ifdef __linux__
  // -------------------------------------------------------------------------
  // Disable core dumps
  // -------------------------------------------------------------------------
  // prctl(PR_SET_DUMPABLE, 0) prevents the kernel from writing a core file
  // on crash, which would otherwise contain all of the process's memory —
  // including any secrets held in sodium-allocated pages. This call affects
  // memory allocated *after* it is made; it must be called before any Secret
  // is constructed (see "CALL ORDER" in ProcessHardening.h).
  //
  // prctl can fail if the calling process is in a container with a seccomp
  // profile that blocks PR_SET_DUMPABLE (e.g., some Docker configurations).
  // We log the failure and continue rather than aborting: the application
  // remains functional, just with reduced hardening.
  if (prctl(PR_SET_DUMPABLE, 0) != 0) {
    std::cerr << "Warning: prctl(PR_SET_DUMPABLE, 0) failed; "
                 "core dumps may capture secrets\n";
  }

  // setrlimit(RLIMIT_CORE, {0, 0}) provides a belt-and-suspenders layer on
  // top of prctl: it sets the maximum core file size to zero via the resource
  // limit mechanism, which applies independently of dumpability flags and
  // persists across fork/exec if the child does not explicitly raise the
  // limit. This is not redundant with prctl: a child process can restore
  // dumpability via prctl(PR_SET_DUMPABLE, 1), but it cannot raise the hard
  // limit of RLIMIT_CORE beyond what the parent set, unless it has
  // CAP_SYS_RESOURCE.
  //
  // Both soft and hard limits are set to 0. Setting only the soft limit
  // would allow the process to raise it back to the hard limit later.
  const rlimit no_core{0, 0};
  if (setrlimit(RLIMIT_CORE, &no_core) != 0) {
    std::cerr << "Warning: setrlimit(RLIMIT_CORE, {0,0}) failed; "
                 "core file size limit not enforced\n";
  }
#endif

#ifdef __APPLE__
  // TODO(#issue-N): implement macOS hardening. See includes above for
  // candidate APIs. At minimum, log a warning in debug builds if the
  // process is running under lldb or Instruments.
#endif

#ifdef _WIN32
  // TODO(#issue-N): implement Windows hardening. See includes above for
  // candidate APIs.
#endif
}

}  // namespace pwledger
