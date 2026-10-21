# PWLedger Engineering Quality Constraints (CONSTRAINTS.md)

**Initiative**: PWLedger Hardening & Refactoring Quality Bar  
**Enforcement**: Pre-Commit, Pull Request / CI, and Nightly Gates  
**Status**: ACTIVE CONTRACT — Agents and contributors may not weaken any threshold below.

---

## 1. Quality Gates by Execution Cost

| Gate | Max Latency | Trigger | Scope & Checks | Threshold |
|---|---|---|---|---|
| **Gate 1: Local / Pre-Commit** | < 30 sec | Pre-commit / local edit loop | Formatting, basic compiler warnings-as-errors (`pwledger_core`, `pwledger-cli`, `pwledger-host`), unit test suite. | **0 warnings, 0 test failures** |
| **Gate 2: CI Matrix (PR / Branch)** | < 8 min | Every push / PR across OS matrix | Multi-compiler builds (GCC, Clang, MSVC), `PWLEDGER_ENABLE_SANITIZERS=ON`, `clang-tidy`, `cppcheck`, binary hardening audit, compatibility fixture verification. | **100% passing, 0 defects** |
| **Gate 3: Nightly / Security Audit** | < 30 min | Scheduled nightly / release tag | Full test run with ASan+UBSan+LSan on Linux, code coverage report, extension linting. | **0 memory leaks, 0 UB, ≥ 85% branch coverage on core/host** |

*Note on Coverage*: The ≥ 85% branch coverage requirement applies strictly to `pwledger_core` and `apps/native_host` business and cryptographic logic. Platform-specific terminal, clipboard, and low-level OS process calls are excluded. Coverage enforcement begins in Phase 4 (Test Suite).

---

## 2. Hardening & Compiler Quality Floor

### 2.1 Minimum Tooling Requirements
- **CMake**: Minimum version **3.21** (required for CMakePresets schema v3, MSVC `/external:` system header isolation, and uniform `SYSTEM` include directory properties).
- **C++ Standard**: ISO C++20 across all targets.

### 2.2 Warnings as Errors (Mandatory)
Every target in the repository (`pwledger_core`, `pwledger-cli`, `pwledger-host`, and test binaries) must build with warnings-as-errors enabled across all supported toolchains:

- **GCC / Clang**:
  `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wsign-conversion -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual -Wnull-dereference -Wdouble-promotion -Wformat=2`
- **MSVC**:
  `/W4 /WX /permissive- /w14242 /w14254 /w14263 /w14265 /w14287 /we4289 /w14296 /w14311 /w14545 /w14546 /w14547 /w14549 /w14555 /w14619 /w14640 /w14826 /w14905 /w14906 /w14928`

### 2.3 External & Third-Party Header Isolation (SYSTEM Includes)
Third-party dependencies (`libsodium`, `nlohmann/json`, GoogleTest) must be treated as `SYSTEM` includes in CMake:
- GCC / Clang: `target_include_directories(... SYSTEM ...)`
- MSVC: `/external:I` and `/external:W0` (supported in CMake 3.21+)
This prevents third-party code from triggering strict warning flags (`-Wconversion`, `-Wold-style-cast`) while keeping `-Werror` / `/WX` strictly enforced on all pwledger code. If warnings fire from macro expansions inside pwledger files, pwledger code must be adapted; compiler flags must never be lowered.

### 2.4 Binary Security Hardening Flags (Enforced in Built Executables)

Hardening flags must be verified in the final built binaries using platform-specific audit scripts (`tools/audit_hardening.sh` / `tools/audit_hardening.ps1`) that exit non-zero if any required mitigation is missing:

#### Linux (ELF Binaries)
Verified via `checksec --file=bin/pwledger-cli` or `readelf`:
- **RELRO**: Full RELRO (`-Wl,-z,relro,-z,now`)
- **Stack Canary**: Enabled (`-fstack-protector-strong` or `-fstack-protector-all`)
- **NX**: Non-executable stack enabled (`-Wl,-z,noexecstack`)
- **PIE**: Position Independent Executable (`-fPIE -pie`)
- **Fortify Source**: Source hardening enabled (`_FORTIFY_SOURCE=3` where supported with optimization, fallback to `_FORTIFY_SOURCE=2`; never at `-O0`). Audit script reports applied level.
- **RPATH / RUNPATH**: No insecure search paths.

#### Windows (PE Binaries - MSVC)
Verified via `dumpbin /headers bin\pwledger-cli.exe` and `dumpbin /loadconfig`:
- **Dynamic Base (ASLR)**: `/DYNAMICBASE`
- **High Entropy VA (64-bit ASLR)**: `/HIGHENTROPYVA`
- **NX Compatible (DEP)**: `/NXCOMPAT`
- **Control Flow Guard (CFG)**: `/guard:cf`
- **Buffer Security Check**: `/GS`
- **Safe Structured Exception Handling**: `/SAFESEH` (x86) / Default 64-bit exception tables

#### macOS (Mach-O Binaries)
Verified via `otool -hv` and symbol lookup:
- **PIE**: Position Independent Executable (`otool -hv` confirms `PIE` flag)
- **Stack Canary**: Verified via `nm -u bin/pwledger-cli | grep ___stack_chk`
*(Note: macOS does not support `-z` flags or ELF `NOEXECSTACK`; no non-existent checks are invented).*

---

## 3. Sanitizer & Dynamic Analysis Standards

When built with `-DPWLEDGER_ENABLE_SANITIZERS=ON`, binaries must adhere to the platform-specific sanitizer matrix:

| Platform | Compiler | Supported Sanitizers | Invariants & Requirements |
|---|---|---|---|
| **Linux** | GCC / Clang | **ASan + UBSan + LSan** | 0 address faults, 0 undefined behavior, 0 memory leaks. |
| **macOS** | Apple Clang | **ASan + UBSan** | 0 address faults, 0 undefined behavior. (LSan is unsupported on macOS). |
| **Windows** | MSVC 2022 | **ASan (`/fsanitize=address`)** | Requires dynamic CRT (`/MD` or `/MDd`). Must disable `/RTC*` runtime checks, `/INCREMENTAL` linking, and `/ZI`. (UBSan and LSan are unsupported on MSVC). |
| **Windows** | MinGW GCC | **Build + CTest Only** | MinGW-w64 GCC does not distribute `libasan`/`libubsan`. Sanitizers are disabled for MinGW toolchains. |

---

## 4. Static Analysis Standards

### 4.1 Clang-Tidy
All C++ files must pass `clang-tidy` with zero warnings using a committed `.clang-tidy` configuration at the repository root:
- Checks include: `bugprone-*`, `cert-*`, `clang-analyzer-*`, `cppcoreguidelines-*`, `misc-*`, `modernize-*`, `performance-*`, `readability-*`.
- Every disabled check in `.clang-tidy` must have a one-line comment next to it providing technical justification.
- Wholesale disabling of entire families (`bugprone-*`, `cert-*`, `clang-analyzer-*`) is prohibited.
- Inline suppressions (`// NOLINT`) are strictly forbidden.

### 4.2 Cppcheck
All C++ files must pass `cppcheck` with zero defects:
```bash
cppcheck --enable=warning,style,performance,portability --error-exitcode=1 --suppressions-list=cppcheck-suppressions.txt src/ include/ apps/
```
- A committed `cppcheck-suppressions.txt` file is maintained where every suppression rule has a documented justification.
- Inline suppressions (`--inline-suppr`) are forbidden.

---

## 5. Secret Lifetime & Memory Invariants

1. **No Secrets on Unhardened Heap**:
   - Master passwords, derived keys, and decrypted credentials must never be assigned to `std::string`, `std::vector`, or raw heap allocations.
   - Any serialization or decryption buffer handling plaintext vault data must use `pwledger::SecureBuffer` backed by `sodium_malloc()`.
2. **Deterministic Zeroing**:
   - Every secret buffer must be wiped with `sodium_memzero()` before memory is unlocked or freed.
3. **No Secret Material in Logs or Stderr**:
   - Log outputs, assertion messages, and exception strings must never format or embed secret payloads. Only metadata (e.g. UUID, title, domain) may appear in diagnostics.

---

## 6. Backward Compatibility & Test Fixture Invariants

1. **V1 Format Compatibility**:
   - The repository maintains a frozen test asset `tests/fixtures/v1_original_vault.pwl` generated by the original codebase at the baseline commit.
   - Every build and CI run must execute `TestVaultCompatibility` confirming that `v1_original_vault.pwl` decrypts, deserializes, and verifies against expected credentials.
2. **Native Messaging Contract**:
   - Incoming JSON schema and outgoing JSON response schema for `ping`, `unlock`, `lock`, `init_vault`, `search`, `copy`, `clip_clear`, `get_credentials` must remain 100% backward-compatible with the WebExtension.

---

## 7. Anti-Regression & Ratchet Rules

Agents and developers are strictly forbidden from weakening this bar:
1. **No `// NOLINT`**: Suppressing linter warnings with inline comments is prohibited. Fix the underlying code.
2. **No `#pragma warning(disable)`**: Disabling compiler warnings in source code or CMake files is prohibited.
3. **No Skipped Tests**: Marking tests as disabled (`DISABLED_TestName`), commenting out assertions, or deleting tests to pass CI is a contract violation.
4. **No Weakening of Thresholds**: Lowering warning levels, disabling `/GS`, removing ASan flags, or increasing permissible error counts in `CONSTRAINTS.md` is forbidden.

---

## Change Log (Approved Quality Bar Amendments)

- **2026-10-21 (Amendment 1: Drop MSan)**: Dropped MemorySanitizer (MSan) from Gate 3. *Justification*: MSan requires an instrumented C++ standard library (`libc++`) and an MSan-instrumented `libsodium`. Standard distribution packages cause false-positive memory read traps. ASan + UBSan + LSan provide robust dynamic memory verification without custom runtime rebuilds.
- **2026-10-21 (Amendment 2: Drop Valgrind & Redefine Gate 3)**: Dropped Valgrind from Gate 3. *Justification*: `sodium_malloc` uses `mmap`/`VirtualAlloc` with `mprotect(PROT_NONE)` guard pages, triggering false positives and crashes in Valgrind. Valgrind is completely redundant with ASan + LSan. Gate 3 is redefined to require full ASan+UBSan+LSan on Linux, branch coverage (≥85% on core/host in Phase 4), and extension linting.
- **2026-10-21 (Amendment 3: Platform Sanitizer Matrix)**: Defined realistic per-platform sanitizer matrix. *Justification*: Verified that MinGW-w64 GCC does not ship `libasan` (`cannot find -lasan`). Verified MSVC ASan limitations (requires dynamic CRT `/MD`, incompatible with `/RTC*` and `/INCREMENTAL`). Verified that macOS does not support LSan.
- **2026-10-21 (Amendment 4: OS Hardening Verification)**: Defined platform-specific binary hardening checks. *Justification*: Linux uses ELF `checksec`; Windows PE uses `dumpbin /headers` and `dumpbin /loadconfig` for CFG; macOS uses `otool -hv` (PIE) and `nm -u` for stack canary (`PAGEZERO`/`NOEXECSTACK` do not apply on modern Mach-O).
- **2026-10-21 (Amendment 5: `_FORTIFY_SOURCE` Standards)**: Added CMake feature probe for `_FORTIFY_SOURCE=3` with fallback to `=2`, disabled at `-O0`. *Justification*: `_FORTIFY_SOURCE=3` requires GCC ≥ 12 / glibc ≥ 2.34 and compiler optimization. Not applicable to MSVC or MinGW.
- **2026-10-21 (Amendment 6: SYSTEM Include Properties)**: Mandated `SYSTEM` include flags (`target_include_directories(... SYSTEM ...)` and MSVC `/external:I /external:W0`). *Justification*: Prevents third-party header warnings from polluting strict project warning flags.
- **2026-10-21 (Amendment 7: Static Analysis Rules)**: Mandated committed `.clang-tidy` and `cppcheck-suppressions.txt` with per-rule justification comments. Removed `--inline-suppr` and `--enable=all`. *Justification*: Enforces the zero-inline-suppression policy at the configuration level.
- **2026-10-21 (Amendment 8: CMake 3.21 Minimum)**: Raised minimum CMake version to 3.21. *Justification*: Required for CMakePresets schema v3 and MSVC `/external:` system include handling.
