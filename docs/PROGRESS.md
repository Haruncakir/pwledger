# PWLedger Refactoring & Hardening Progress (docs/PROGRESS.md)

**Initiative**: PWLedger Hardening & Refactoring Execution  
**Current Phase**: Phase 3 (Refactor)  
**Current Status**: Checkpoint 1 — Amendments Applied & CONSTRAINTS Proposals Submitted  
**Last Updated**: 2026-10-21

---

## 1. Task Execution & Status Board

| Task ID | Theme / Scope | Target Branch | Commit SHA | Unit Tests | Sanitizers | Fixture OK? | Platforms Verified | Status |
|---|---|---|---|---|---|---|---|---|
| **TASK-01** | Baseline & V1 Compatibility Fixture | `main` | Pending | — | — | — | — | ⏳ Pending |
| **TASK-02** | CMake Presets & Build Configurations | `main` | Pending | — | — | — | — | ⏳ Pending |
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
   - *Original*: Speculative `kMaxEntries = 100,000`.
   - *Correction*: Verified against libsodium documentation: each `sodium_malloc()` consumes 3 pages (12 KB virtual address space) enclosed by guard pages. On default Linux systems, `vm.max_map_count` is 65,530; 100,000 allocations would fail with `ENOMEM` around entry #21,800 and trigger `std::abort()`. Bounded `kMaxEntries = 10,000` (consuming 30,000 VMAs, safely under 65,530), `kMaxSecretLen = 65,536` (64 KB for long keys/notes), and `kMaxStringLen = 4,096`. Documented in ADR-001.

---

## 4. Pending CONSTRAINTS.md Proposals (Awaiting User Approval)

The following 7 amendments to `CONSTRAINTS.md` have been submitted to the user with full technical justification (Amendment 5):
1. **MSan**: Propose dropping MSan in favor of ASan+UBSan because MSan requires an instrumented `libc++` and `libsodium`.
2. **Valgrind**: Propose dropping Valgrind because it conflicts with `sodium_malloc` page-table guard pages and is redundant with ASan/LSan.
3. **Per-Platform Sanitizer Matrix**: Define exact platform support: Linux (ASan+UBSan+LSan), macOS (ASan+UBSan), Windows MSVC (ASan), Windows MinGW (ASan+UBSan).
4. **Platform Hardening Audit Commands**: Define ELF (`checksec`), PE (`dumpbin /headers`), and Mach-O (`otool`).
5. **`_FORTIFY_SOURCE=3` Fallback**: CMake check to use `=3` if supported with optimization; fallback to `=2`; omit in unoptimized Debug (`-O0`).
6. **SYSTEM Include Directories**: Mark libsodium, nlohmann/json, and GoogleTest as `SYSTEM` includes in CMake so `-Wconversion` and `-Wold-style-cast` do not fire on external headers.
7. **Curated `.clang-tidy` File**: Commit `.clang-tidy` at root with an explicit, justified disabled check list; enforce zero inline `// NOLINT`.

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
