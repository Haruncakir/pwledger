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

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

namespace pwledger {

void harden_process() noexcept {
#ifdef __linux__
  // Prevent core dumps from capturing in-memory secrets.
  // Must be called before any Secret is constructed (see Secret.h).
  prctl(PR_SET_DUMPABLE, 0);

  // Belt-and-suspenders: also set the core dump size limit to zero via
  // setrlimit, which applies even if prctl is overridden by a child process.
  const struct rlimit no_core {
    0, 0
  };
  setrlimit(RLIMIT_CORE, &no_core);
#endif
  // TODO(#issue-N): add macOS Hardened Runtime check and Windows
  // IsDebuggerPresent mitigation once those platforms are targeted.
}

}  // namespace pwledger
