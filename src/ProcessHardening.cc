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
