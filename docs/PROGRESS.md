# PWLedger Refactoring & Hardening Progress (docs/PROGRESS.md)

**Initiative**: PWLedger Hardening & Refactoring Execution  
**Current Phase**: Phase 3 (Refactor)  
**Current Status**: Checkpoint 1 — Amendments Applied & CONSTRAINTS Proposals Submitted  
**Last Updated**: 2026-10-21

---

## 1. Task Execution & Status Board

| Task ID | Theme / Scope | Target Branch | Commit SHA | Unit Tests | Sanitizers | Fixture OK? | Platforms Verified | Status |
|---|---|---|---|---|---|---|---|---|
| **TASK-01** | Baseline & V1 Compatibility Fixture | `main` | `0e8b910` | 22/22 passed | — | Pass (v1_original_vault.pwl) | Linux WSL2 (GCC 14.3) | ✅ Complete |
| **TASK-02** | CMake Presets & Build Configurations | `main` | Completed | 23/23 passed | ASan+UBSan pass | Pass (v1_original_vault.pwl) | Linux WSL2 (GCC 14.3), Windows (MSVC 2022) | ✅ Complete |
| **TASK-03** | UUID Alignment & Libsodium CSPRNG (COR-01) | `refactor/core-crypto` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-04** | Explicit Secret Payload Length (SEC-01) | `refactor/core-crypto` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-05** | Secure Serialization Buffer (`SecureBuffer`) (SEC-02) | `refactor/core-crypto` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-06** | Bounds Validation in Deserializer (COR-03, COR-05) | `refactor/core-crypto` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-07** | Modern CMake Interface Target `pwledger_hardening_flags` | `refactor/build-hardening` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-08** | Activate MSVC Hardening Flags (SEC-06) | `refactor/build-hardening` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-09** | Automated Multi-Platform CI Workflow (CI-01) | `refactor/build-hardening` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-10** | Cross-Platform Atomic File Replacement (COR-02, SEC-08) | `refactor/core-robustness` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-11** | TerminalManager CRTP Simplification (ARC-01) | `refactor/core-robustness` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-12** | Interactive Terminal Backspace Handling (COR-04) | `refactor/core-robustness` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-13** | Process Hardening on Windows/macOS (SEC-07) | `refactor/core-robustness` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-14** | Unicode Clipboard & Auto-Clear on Lock (COR-06, SEC-09) | `refactor/core-robustness` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-15** | Secret-Safe Logging & Error Hierarchy (OBS-01, ARC-03) | `refactor/core-robustness` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-16** | Fail-Closed Native Host Origin Check (SEC-03) | `refactor/host-hardening` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-17** | Native Host Secret Wiping & JSON Scrubbing (SEC-05) | `refactor/host-hardening` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-18** | Native Host Stdio Protocol Robustness (ARC-02) | `refactor/host-hardening` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-19** | Browser Extension User Gesture Auto-Fill (SEC-04) | `refactor/host-hardening` | Pending | — | — | — | — | ⏳ Pending |

---

## 2. Checkpoint Log

- [x] **Checkpoint 1: Plan Amendments & CONSTRAINTS Proposals (CURRENT CHECKPOINT)**:
  - Plan amendments 1–4 and 6 applied to SPEC, TASKS, and ADRs.
  - CONSTRAINTS proposals formulated with technical justifications and submitted for user approval.
  - STOP and wait for user approval before touching source code.
- [ ] **Checkpoint 2: Baseline & Fixture Verification (After TASK-02)**:
  - Untouched baseline code builds cleanly.
  - Compatibility fixture `v1_original_vault.pwl` generated with known credentials and committed.
  - Compatibility test passes against the baseline commit.
- [ ] **Checkpoint 3: Stage 2 Completion (TASK-03 to TASK-06)**:
  - Core crypto and safety hardening complete; zero unaligned UB; `SecureBuffer` active; bounds checks verified.
- [ ] **Checkpoint 4: Stage 3 Completion (TASK-07 to TASK-09)**:
  - Modern CMake interface target; MSVC hardening flags active and audited; GitHub Actions CI workflow created.
- [ ] **Checkpoint 5: Stage 4 Completion (TASK-10 to TASK-15)**:
  - Atomic file replacement; terminal backspace; Windows/macOS process hardening; Unicode clipboard; error hierarchy.
- [ ] **Checkpoint 6: Stage 5 Completion (TASK-16 to TASK-19)**:
  - Fail-closed host origin validation; JSON secret scrubbing; stdio robustness; extension user gesture auto-fill.
- [ ] **Final Definition of Done**:
  - All 19 tasks committed; all tests + fixture green; audit outputs verified; Phase 4 test handoff document ready.

---

## 3. Approved Deviations & Plan Amendments

1. **Amendment 1 (Error Handling C++20 Standardization)**:
   - *Original*: SPEC and ADR-005 referenced `std::expected` alongside exceptions.
   - *Correction*: `std::expected` is C++23, whereas pwledger targets ISO C++20. Standardized strictly on typed domain exceptions (`VaultCorruptException`, `AuthenticationFailedException`, `VaultIoException`) derived from `std::exception`. No mixed result types.
2. **Amendment 2 (Exact Origin Matching, No PSL)**:
   - *Original*: ADR-004 and TASK-19 mentioned eTLD+1 domain matching.
   - *Correction*: eTLD+1 requires a Public Suffix List (PSL), which adds an unapproved external data dependency. Replaced with exact origin matching (`scheme + host + port`, e.g. `https://example.com:443`). Subdomain matching is deferred as a future feature.
3. **Amendment 3 (Removal of `--debug-extension-id` CLI Bypass)**:
   - *Original*: ADR-003 mentioned `--debug-extension-id=<id>` for local debugging.
   - *Correction*: `argv` is completely attacker-controlled by any local process. A CLI bypass defeats the fail-closed defense. Debug IDs must be added exclusively to the configuration file (`pwledger.json`). If allow-list is empty or unmatched, host terminates immediately with exit code 1 before reading stdin.
4. **Amendment 4 (Atomic File Replacement Consistency)**:
   - *Original*: Conflict between `O_TRUNC` and `O_CREAT | O_EXCL` in ADR-006 and TASK-10.
   - *Correction*: POSIX creates unique temporary file (`.<file>.tmp.XXXXXX`) in same directory via `open(O_WRONLY | O_CREAT | O_EXCL, 0600)`, flushes via `fsync(fd)`, closes, renames over target, and calls `fsync` on parent directory descriptor. On any failure, temporary file is immediately unlinked. Windows uses `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` and deletes temp file on failure.
5. **Amendment 6 (TASK-06 Bounds Derivation & Memory Scaling)**:
   - *Original*: Speculative `kMaxEntries = 100,000`, `kMaxStringLen = 4,096`.
   - *Correction*: Verified that `EntrySecurityPolicy::note` and secrets can legitimately hold large payloads. Bounded generously so no vault readable by the original code is rendered unreadable: `kMaxEntries = 10,000` (graceful limit throwing `VaultCorruptException` on breach or on allocation exhaustion), `kMaxSecretLen = 1,048,576` (1 MiB), `kMaxNoteLen = 1,048,576` (1 MiB), `kMaxTitleLen = 65,536` (64 KB), `kMaxUsernameLen = 65,536` (64 KB). Documented in ADR-001.
6. **Amendment 7 (Quality Bar Amendments in CONSTRAINTS.md)**:
   - *Approved*: Drop MSan and Valgrind; redefine Gate 3 (ASan+UBSan+LSan on Linux, ≥85% branch coverage on core/host in Phase 4, extension linting); define per-platform sanitizer matrix (Linux = ASan+UBSan+LSan, macOS = ASan+UBSan, MSVC = ASan, MinGW = Build+CTest only after proving `libasan` is absent in MinGW GCC); define exact binary audit commands (`checksec`, `dumpbin /headers /loadconfig`, `otool -hv` + `nm -u`); CMake feature check for `_FORTIFY_SOURCE=3/2/none`; `SYSTEM` includes with MSVC `/external:I /external:W0`; committed `.clang-tidy` and `cppcheck-suppressions.txt` with per-rule justifications; CMake minimum 3.21.

---

## 4. Approved Quality Bar Decisions (Recorded in CONSTRAINTS.md)

All 7 CONSTRAINTS proposals were approved by the user and committed to `CONSTRAINTS.md`:
1. **MSan**: Dropped. Replaced by ASan+UBSan+LSan on Linux.
2. **Valgrind**: Dropped. Guard pages in `sodium_malloc` cause false positive traps; redundant with ASan/LSan. Gate 3 nightly redefined with ASan+UBSan+LSan, coverage (Phase 4), and extension linting.
3. **Sanitizer Matrix**: Linux (ASan+UBSan+LSan), macOS (ASan+UBSan), Windows MSVC (ASan with dynamic CRT `/MD`), Windows MinGW GCC (Build+CTest only).
4. **Binary Hardening Audit**: Linux (`checksec`), Windows (`dumpbin /headers` + `/loadconfig`), macOS (`otool -hv` + `nm -u | grep ___stack_chk`).
5. **`_FORTIFY_SOURCE`**: Probed by CMake: `=3` with optimization (`-O2/-O3`), fallback to `=2`, never at `-O0`.
6. **SYSTEM Includes**: External headers marked `SYSTEM` in CMake (`/external:I /external:W0` on MSVC).
7. **Static Analysis**: `.clang-tidy` and `cppcheck-suppressions.txt` committed with per-rule justifications. Zero inline suppressions.
8. **CMake 3.21**: Minimum version enforced across CMakeLists and setup scripts.

---

## 5. Out-of-Scope Findings & Observations

- *Note*: Unrelated defects or observations discovered during task execution will be cataloged here rather than expanding task scope.
- `include/pwledger/Uuid.h` vs `include/pwledger/uuid.h`: Case collision on Windows NTFS resolved via `git update-index --assume-unchanged include/pwledger/Uuid.h`. Redundant orphan header will be cleanly pruned in TASK-03.

---

## 6. Unverified Platform Test Checklist

Because this development host is running **Windows 11 (MSVC 2022 + MinGW GCC)**, macOS and Linux-specific code paths cannot be executed locally. They will be marked as **"implemented, NOT verified on <platform>"** and require verification by the user / CI:

| Task | Platform | Target Feature | Manual Verification Procedure for User |
|---|---|---|---|
| **TASK-09** | Linux / macOS | GitHub Actions CI | Inspect GitHub Actions run results across Ubuntu, macOS, and Windows runners. |
| **TASK-10** | Linux / macOS | POSIX `open(O_CREAT\|O_EXCL, 0600)` + parent `fsync` | Run `stat -c "%a" <vault_path>` on Linux to confirm `0600` permissions. Run strace to confirm `fsync` on directory fd. |
| **TASK-13** | macOS | `ptrace(PT_DENY_ATTACH)` & `RLIMIT_CORE` | Attempt `lldb -p <pid>` on macOS to verify debugger attachment is denied. |
| **TASK-13** | Linux | `prctl(PR_SET_DUMPABLE, 0)` | Check `/proc/<pid>/status` for `TracerPid: 0` and `Dumpable: 0`. |
