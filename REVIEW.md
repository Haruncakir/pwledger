# PWLedger Comprehensive Architecture & Security Review (Phase 1)

Date: 2026-10-21  
Author: Senior C++ / Security Reviewer  
Status: **Pending User Approval (Phase 1 Complete - No Code Changes Made)**

---

## Executive Summary

**pwledger** is an offline-first password vault written in C++20 utilizing libsodium for secure memory allocation (`sodium_malloc`), page locking (`mlock`), guard pages, and `NOACCESS` memory protection via hardware page tables (`mprotect`). The ecosystem comprises:
1. **`pwledger_core`**: The foundational cryptographic, serialization, and storage engine.
2. **`pwledger-cli`**: An interactive terminal CRUD interface with terminal echo suppression and auto-clearing clipboard integration.
3. **`pwledger-host`**: A Native Messaging stdio host communicating with Chrome and Firefox browser extensions.
4. **`extension/`**: A WebExtension (MV2) providing vault searching, clipboard copying, and form auto-fill.
5. **`tests/`**: GoogleTest test suite covering Secret, Config, and Vault serialization/encryption round-trips.

While the conceptual security posture (leveraging `sodium_malloc`, `mprotect`, and `sodium_memzero`) is strong in intent, **the implementation suffers from critical security vulnerabilities, secret leaks into unhardened heap memory, potential denial of service / crashes on corrupt input, undefined behavior from unaligned pointer casts, and severe architectural omissions (e.g. MSVC security flags are completely disabled in practice, and extension ID verification is never performed).**

---

## Phase 0: Orientation & Architecture Summary

### Component Inventory & Mapping

```
pwledger/
├── CMakeLists.txt                    # Top-level build configuration
├── cmake/
│   ├── FindSodium.cmake             # Custom libsodium package locator
│   ├── PwledgerCompilerMSVC.cmake   # MSVC compiler/linker flags (UNREFERENCED FUNCTION)
│   ├── PwledgerCompilerUnix.cmake   # GCC/Clang flags & architecture optimizations
│   └── toolchains/
│       └── mingw-w64-x86_64.cmake   # MinGW cross-compilation toolchain definition
├── include/pwledger/
│   ├── Secret.h                     # Hardened RAII memory container (sodium_malloc/mprotect)
│   ├── SecretEntry.h                # In-memory entry aggregate (metadata + secrets)
│   ├── PrimaryTable.h               # std::unordered_map<Uuid, SecretEntry> alias
│   ├── EntryMetadata.h              # Timestamps (created, modified, used)
│   ├── EntrySecurityPolicy.h        # Policy metadata (score, 2FA, expiry, notes)
│   ├── VaultCrypto.h                # Argon2id KDF + XChaCha20-Poly1305 AEAD
│   ├── VaultSerializer.h            # Binary V1 vault wire format serializer/deserializer
│   ├── VaultIO.h                    # High-level file load/save with atomic swap
│   ├── VaultPath.h                  # Cross-platform default directory & file path resolver
│   ├── Config.h                     # JSON configuration model (nlohmann::json)
│   ├── ProcessHardening.h           # Process-level dump & core disablement (Linux only)
│   ├── TerminalManager.h            # CRTP terminal echo/canonical mode controller
│   ├── Clipboard.h                  # OS clipboard read/write/clear abstraction
│   ├── ClipboardTimer.h             # Background thread auto-clear timer
│   └── uuid.h                       # 128-bit RFC 4122 UUID v4 parser/formatter/generator
├── src/
│   ├── CMakeLists.txt               # Builds pwledger_core STATIC library
│   ├── Secret.cc, SecretEntry.cc, uuid.cc, VaultCrypto.cc, VaultIO.cc, VaultPath.cc,
│   │   VaultSerializer.cc, Config.cc, ProcessHardening.cc, TerminalManager.cc, Clipboard.cc
├── apps/
│   ├── CMakeLists.txt               # Builds pwledger-cli and pwledger-host
│   ├── cli/                         # CLI app: AppState, CommandLoop, Display, EntryOps, SecretIO, main.cc
│   └── native_host/                 # Native messaging host: NativeMessaging, CommandHandlers, MessageLoop, main.cc
├── extension/                       # WebExtension: manifest.json, background.js, content.js, popup/
├── setup/                           # Automated installation: setup.sh (Linux/macOS), setup.ps1 (Windows)
└── tests/                           # GoogleTest suite: test_secret.cc, test_config.cc, test_vault.cc
```

### End-to-End Data Flow

1. **Vault Persistence Flow**:
   `PrimaryTable` (in-memory entries) ➔ `VaultSerializer::serialize()` (produces plaintext binary payload) ➔ `VaultCrypto::encrypt_vault()` (Argon2id KDF key derivation + XChaCha20-Poly1305 AEAD encryption with random 16-byte salt and 24-byte nonce) ➔ `VaultIO::save_vault()` (writes to `<path>.tmp` ➔ permissions 0600 ➔ rename over `<path>`).
2. **CLI Interactive Flow**:
   `main.cc` ➔ `harden_process()` ➔ `sodium_init()` ➔ `load_config()` ➔ unlock/create vault ➔ `run_command_loop()` ➔ stdin interactive command prompt with echo suppression (`TerminalManager`) ➔ CRUD on `PrimaryTable` ➔ auto-save on modification.
3. **Native Messaging Flow**:
   Browser extension popup/content-script ➔ Chrome/Firefox native messaging pipe (stdio) ➔ `pwledger-host` (reads 4-byte LE length + JSON payload) ➔ `MessageLoop` dispatch ➔ in-memory `PrimaryTable` query ➔ JSON response (4-byte LE length + JSON).

---

## Phase 1: Review Findings by Axis

### Findings Table

| ID | Severity | Axis | File & Line | Summary |
|---|---|---|---|---|
| **SEC-01** | **Critical** | Security | `src/VaultSerializer.cc:44` | **Secret Truncation / Data Loss**: Plaintext secret length is calculated via `::strnlen(buf.data(), buf.size())`. Binary passwords with `\0` are silently truncated; secrets without trailing `\0` leak uninitialized buffer bytes. |
| **SEC-02** | **Critical** | Security | `src/VaultIO.cc:31,91`, `src/VaultCrypto.cc:85` | **Plaintext Secret Leaks in Unprotected Heap Vector**: Entire decrypted vault is stored in `std::vector<uint8_t>` on standard process heap without `mlock`, guard pages, or reallocation zeroing. |
| **SEC-03** | **Critical** | Security | `apps/native_host/main.cc:54`, `include/pwledger/Config.h:94` | **Extension ID Allow-Listing Completely Bypassed**: Command-line arguments passed by browser (`argv[1]` / `argv[2]`) are ignored; `IntegrationConfig::allowed_extensions` is never validated. Host must parse Chrome (`argv[1] = chrome-extension://<id>/`, ignoring `--parent-window=<n>`) and Firefox (`argv[1]` = manifest path, `argv[2]` = add-on ID), normalize, and fail closed if empty or unmatched. |
| **SEC-04** | **Critical** | Security | `extension/background.js:48-79`, `extension/content.js:327-351` | **Insecure Auto-Fill Credential Extraction**: Content script queries vault for passwords without user interaction on page load; `background.js` trusts unverified `message.url` from content script rather than browser-verified `sender.tab.url`. Vulnerable to silent exfiltration by malicious subframes (`all_frames`). |
| **SEC-05** | **Major** | Security | `apps/native_host/CommandHandlers.cc:64,243`, `apps/native_host/MessageLoop.cc:116` | **Master Password & Plaintext Credentials Persist in JSON Parser Heap**: `nlohmann::json` and `read_message()` string buffers retain copies of passwords in unzeroed heap. |
| **SEC-06** | **Major** | Security | `cmake/PwledgerCompilerMSVC.cmake:148` | **MSVC Security Hardening Flags Completely Dead**: `apply_pwledger_compile_options_to_target` is defined but never called in any CMakeLists.txt. MSVC builds lack `/GS`, `/sdl`, `/guard:cf`, `/NXCOMPAT`, `/DYNAMICBASE`. |
| **COR-01** | **Major** | Correctness | `include/pwledger/uuid.h:129` | **Undefined Behavior (Unaligned Pointer Dereference)**: `std::hash<Uuid>` casts `uint8_t*` (align 1) to `uint64_t*` (align 8) and dereferences `p[0]`, `p[1]`. Standard UB under ISO C++; faults (SIGBUS) on strict-alignment targets (ARMv7, SPARC) and under `-fsanitize=alignment`; executes with unaligned load on x86_64. Downgraded from Critical to Major. |
| **COR-02** | **Major** | Correctness | `src/VaultIO.cc:64` | **Atomic Save Fails on Windows**: `std::filesystem::rename(temp_path, path)` fails on Windows when target file already exists (`ERROR_ALREADY_EXISTS`), preventing vault saves. |
| **COR-03** | **Major** | Correctness | `src/VaultSerializer.cc:81-125` | **Fatal Crash on Malformed / Untrusted Vault File**: `deserialize` does not validate sanity bounds on `secret_len` or `salt_len`. Excessive length causes `Secret::allocate` ➔ `sodium_malloc` failure ➔ `std::abort()`. |
| **COR-04** | **Major** | Correctness | `apps/cli/SecretIO.cc:66`, `src/TerminalManager.cc:49,93` | **Backspace Key Corrupts Passwords During Terminal Input**: Disabling canonical mode without handling `\b` (`0x08`) and `\x7f` appends backspace characters directly into password buffer. |
| **COR-05** | **Minor** | Correctness | `src/VaultSerializer.cc:200,209,224` | **Potential Arithmetic Overflow in Read Helpers**: `pos + len > size` can wrap if `size_t` is 32-bit; should use `len > size - pos`. |
| **COR-06** | **Minor** | Correctness | `src/Clipboard.cc:145` | **Windows Clipboard Lacks Unicode Support**: Windows clipboard write uses `CF_TEXT` instead of `CF_UNICODETEXT`, corrupting non-ASCII credentials. |
| **ARC-01** | **Major** | Architecture | `include/pwledger/TerminalManager.h:98-187` | **Over-Engineered CRTP & Concept Hierarchy**: CRTP base + concept + platform subclasses for a single RAII class with `#ifdef` implementations adds ~150 lines of dead complexity. |
| **ARC-02** | **Minor** | Architecture | `apps/native_host/MessageLoop.cc:60-93` | **Redundant Dispatch Trampolines**: 8 boilerplate trampoline functions wrap handler calls that could be uniform or directly dispatched. |
| **ARC-03** | **Minor** | Architecture | `include/pwledger/Secret.h:139` | **Zombie Code (SecureAllocator Stub)**: Unimplemented allocator stub with no call sites. |
| **ARC-04** | **Minor** | Architecture | `CMakeLists.txt:69-73` | **Zombie CMake Variables**: `TOP_DIR`, `PWLEDGER_DIR`, `PWLEDGER_DIR_PREFIXES`, `PWLEDGER_DIR_REGEX_ESCAPED` are unused artifacts. |
| **SEC-07** | **Major** | Security | `src/ProcessHardening.cc:86,92` | **Incomplete Process Hardening on Windows and macOS**: `harden_process()` is a no-op on non-Linux platforms; Windows anti-debugging and dump suppression are unimplemented. |
| **SEC-08** | **Minor** | Security | `src/VaultIO.cc:48-63` | **Permissive File Creation Race Window**: Vault temp file created with default umask; permissions tightened only after file is closed and before rename. |
| **SEC-09** | **Minor** | Security | `src/ClipboardTimer.h:88-99` | **Lock Command Does Not Invalidate Clipboard**: Native host `handle_lock` clears memory table but leaves pending secrets in clipboard and active timer uncancelled. |
| **CI-01** | **Major** | Automation | `.github/` | **Zero Automated CI Workflows**: No GitHub Actions pipeline exists. No multi-compiler, sanitizer, or test automation across Linux/macOS/Windows. |
| **OBS-01** | **Minor** | Observability | Throughout | **Unstructured Stderr Logging**: Error reporting uses ad-hoc `std::cerr` without levels, timestamps, or sanitization guarantees. |

---

## Deep Dive: Doubt-Driven Development Analysis

For each Critical and Major finding, we execute the mandatory review protocol:  
**CLAIM ➔ EXTRACT ➔ DOUBT ➔ RECONCILE ➔ STOP**.

---

### Case 1: Secret Truncation via `strnlen` (SEC-01)
- **CLAIM**: Using `::strnlen(buf.data(), buf.size())` to determine secret length causes truncation of passwords containing null bytes and risks reading garbage when trailing null is missing.
- **EXTRACT**:
  In `src/VaultSerializer.cc:44`:
  ```cpp
  entry.plaintext_secret.with_read_access([&](std::span<const char> buf) {
    std::size_t len = ::strnlen(buf.data(), buf.size());
    write_u32(out, static_cast<std::uint32_t>(len));
    write_bytes(out, reinterpret_cast<const std::uint8_t*>(buf.data()), len);
  });
  ```
  In `apps/cli/SecretIO.cc:72`:
  ```cpp
  buf[written] = '\0';
  ```
- **DOUBT**: Does pwledger only support ASCII passwords where `\0` is exclusively a terminator? If `SecretEntry` was intended only for C-strings, is `strnlen` acceptable?
- **RECONCILE**: `Secret.h` lines 280-284 explicitly state: *"secrets may be passwords, private keys, API tokens, or raw binary data. None of these can be assumed to be null-terminated, UTF-8, or even printable."* By using `strnlen`, any binary token or password containing `0x00` is permanently truncated upon save. Furthermore, `SecretEntry` does not store an explicit length, forcing every component (`Display.cc`, `CommandLoop.cc`, `CommandHandlers.cc`) to guess the length via `strnlen`.
- **STOP**: Confirmed Critical. `SecretEntry` must track exact payload size (or `Secret` must support active size vs capacity), and serialization must write exact payload bytes.

---

### Case 2: Plaintext Secrets in Standard Heap Vector (SEC-02)
- **CLAIM**: `VaultSerializer::serialize()` and `VaultCrypto::decrypt_vault()` place full unencrypted vault tables into `std::vector<uint8_t>`, violating the core security guarantee that secrets reside solely in hardened memory.
- **EXTRACT**:
  In `src/VaultSerializer.cc:26`:
  ```cpp
  std::vector<std::uint8_t> VaultSerializer::serialize(const PrimaryTable& table);
  ```
  In `src/VaultIO.cc:31-41`:
  ```cpp
  std::vector<std::uint8_t> plaintext = VaultSerializer::serialize(table);
  std::vector<std::uint8_t> ciphertext = VaultCrypto::encrypt_vault(password, plaintext);
  sodium_memzero(plaintext.data(), plaintext.size());
  ```
- **DOUBT**: `VaultIO.cc` explicitly calls `sodium_memzero(plaintext.data(), plaintext.size())` right after encryption. Is this not sufficient?
- **RECONCILE**: No, it is insufficient for three reasons:
  1. If `std::vector` reallocates during `serialize()` (as entries are appended), the previous buffer is freed to the general heap without zeroing.
  2. The memory allocated by standard `std::vector` is swappable to disk, readable in core dumps, and lacks guard pages.
  3. If an exception occurs before `sodium_memzero` (e.g. `encrypt_vault` failure), the vector's default deallocator releases plaintext into the heap free-list without wiping.
- **STOP**: Confirmed Critical. Vault plaintext serialization/deserialization buffers must use secure page-locked memory with custom wiping deallocators.

---

### Case 3: Extension ID Validation Missing (SEC-03)
- **CLAIM**: The Native Messaging host does not validate the calling browser extension origin, allowing any local process or rogue extension to connect and query secrets.
- **EXTRACT**:
  `apps/native_host/main.cc:54`:
  ```cpp
  int main() {
    ...
    pwledger::run_message_loop(cfg);
  }
  ```
- **DOUBT**: Does the browser OS native messaging manifest (`pwledger.json` / `pwledger-chrome.json`) already restrict access at the browser boundary?
- **RECONCILE**: While Chrome and Firefox consult the registration manifest before spawning the host, `pwledger-host` is a standard standalone executable. Any unprivileged process running under the user account can launch `pwledger-host` over standard pipes. Furthermore:
  - **Chrome/Chromium**: Launches the host passing `argv[1]` = `chrome-extension://<extension_id>/`. On Windows, Chrome also passes `--parent-window=<HWND>` as an additional command-line parameter. The host must not confuse `--parent-window` with the extension origin.
  - **Firefox**: Launches the host passing `argv[1]` = absolute path to the native messaging manifest, and `argv[2]` = the extension ID (e.g., `pwledger@example.com` or UUID).
  - `pwledger-host` declares `int main()` without arguments and completely ignores all `argv` inputs.
  - While `Config.h` defines `IntegrationConfig::allowed_extensions`, it is never validated.
  - **Policy Decision**: The host must scan all `argv` arguments, filter out `--parent-window=...`, detect Chrome or Firefox origin formats, normalize the extension ID, and compare against `IntegrationConfig::allowed_extensions`. If `allowed_extensions` is empty or no match is found, the host must **fail closed**: refuse to serve, log a diagnostic to `std::cerr` instructing how to configure `allowed_extensions`, and terminate immediately with a non-zero exit code.
  - **Defense-in-Depth Clarification**: Because any local process can spawn `pwledger-host` with arbitrary spoofed `argv` arguments, `argv` validation is defense in depth against accidental or unauthorized browser extensions, not an absolute barrier against a malicious local process.
- **STOP**: Confirmed Critical. Host must parse `argc/argv`, fail closed if allow-list is empty or unmatched, and setup scripts must populate `allowed_extensions`.

---

### Case 4: Insecure Content-Script Auto-Fill (SEC-04)
- **CLAIM**: Credentials are automatically requested and filled into web pages without user authorization, and content scripts in iframes can spoof origins to exfiltrate credentials.
- **EXTRACT**:
  In `extension/background.js:54`:
  ```javascript
  hostname = new URL(message.url).hostname;
  ```
  In `extension/content.js:342`:
  ```javascript
  if (entries.length === 1) {
    // Single match — auto-fill immediately
    requestAndFill(entries[0].uuid);
  }
  ```
- **DOUBT**: Many password managers auto-fill logins on page load. Is this not standard functionality? And does `sender.tab.url` in MV2 prevent spoofing?
- **RECONCILE**: Modern security standards for password managers strictly forbid auto-filling credentials without user interaction because malicious pages or ads can embed invisible dummy password fields to harvest auto-filled credentials silently. Furthermore:
  - In WebExtensions Manifest V2: `chrome.runtime.onMessage.addListener((message, sender, sendResponse) => ...)` provides `sender.tab.url` and `sender.frameId`.
  - When `"all_frames": true` is specified in `manifest.json`, the content script executes inside third-party advertising or nested iframes. An untrusted iframe sending a message will have `sender.frameId !== 0`.
  - Currently, `background.js` trusts `message.url` provided directly in the JSON message body by the content script, ignoring `sender.tab.url`.
  - **Policy Decision**:
    1. Default behavior requires an explicit user gesture (popup interaction or clicking an in-field badge). Auto-fill on load is disabled by default.
    2. Add an opt-in `integration.autofill_on_load` configuration option (default `false`).
    3. Content script injection is restricted to top frame only (`"all_frames": false`), and `background.js` asserts `sender.frameId === 0`.
    4. Origin matching in `background.js` must strictly use browser-verified `sender.tab.url` and match against the full registrable origin (eTLD+1), never substring or raw `message.url`.
- **STOP**: Confirmed Critical. Auto-fill defaults to user-gesture required, validates `sender.tab.url`, and enforces top-frame isolation.

---

### Case 5: Unaligned Pointer Dereference in UUID Hash (COR-01)
- **CLAIM**: `std::hash<pwledger::Uuid>` commits an unaligned 64-bit pointer dereference, causing undefined behavior and hardware faults on strict-alignment CPUs.
- **EXTRACT**:
  In `include/pwledger/uuid.h:129`:
  ```cpp
  const std::uint64_t* p = reinterpret_cast<const std::uint64_t*>(uuid.bytes.data());
  return std::hash<std::uint64_t>{}(p[0]) ^ (std::hash<std::uint64_t>{}(p[1]) << 1);
  ```
- **DOUBT**: `uuid.bytes` is inside `struct Uuid`. Is this really a Critical vulnerability if it runs on x86-64 without crashing?
- **RECONCILE**: `struct Uuid { std::array<uint8_t, 16> bytes; };` has an alignment of `alignof(uint8_t) == 1`. When placed in packed structures, byte buffers, or on stack frames, its address can be odd. C++ standard (§6.7.6 [basic.align] and §7.6.1.10 [expr.reinterpret.cast]) explicitly specifies that casting a pointer to a type with stricter alignment requirements and dereferencing it is undefined behavior.
  - On strict-alignment architectures (e.g. ARMv7, SPARC) or under `-fsanitize=alignment`, this triggers an immediate fault (`SIGBUS` or runtime sanitizer abort).
  - On x86_64 and modern ARM64 (AArch64) with unaligned loads enabled by the OS kernel, the CPU hardware tolerates unaligned 64-bit loads (with a potential cache-line split penalty) without crashing.
  - Therefore, while it is definite standard UB and breaks portability and sanitizer runs, it does not cause an immediate crash or exploitable memory corruption on modern desktop x86_64.
  - **Severity Downgrade**: Downgraded from **Critical** to **Major**. Fix must use `std::memcpy` or safe endian-independent loads into `uint64_t`.
- **STOP**: Confirmed Major bug. Must be resolved cleanly with `std::memcpy`.

---

### Case 6: MSVC Compiler Options Dead (SEC-06)
- **CLAIM**: The comprehensive security and optimization flags in `cmake/PwledgerCompilerMSVC.cmake` are never applied to any binary.
- **EXTRACT**:
  `cmake/PwledgerCompilerMSVC.cmake:148`:
  ```cmake
  function(apply_pwledger_compile_options_to_target THETARGET)
  ```
  Neither `CMakeLists.txt`, `src/CMakeLists.txt`, nor `apps/CMakeLists.txt` calls `apply_pwledger_compile_options_to_target`.
- **DOUBT**: Does `include(PwledgerCompilerMSVC)` apply flags globally via directory properties?
- **RECONCILE**: The file sets only `MSVC_FAVORED_ARCHITECTURE` and cache options globally. All compile options, warning levels, warning suppressions, `/GS`, `/sdl`, and linker options are encapsulated strictly inside `function(apply_pwledger_compile_options_to_target)`. Because this function is never invoked, MSVC builds run with plain default compiler flags.
- **STOP**: Confirmed Major. Target properties must be cleanly applied to all targets or refactored into a modern CMake interface library (`pwledger_compiler_flags`).

---

## Source-Driven Verification & Citations

1. **libsodium Memory Locking & Wiping**:
   - *Source*: [libsodium official docs — Securing memory](https://doc.libsodium.org/memory_management)
   - *Doc Rule*: `sodium_malloc()` locks pages, adds guard pages before and after, fills allocation with canary `0xdb`, and sets access to `PROT_READ | PROT_WRITE`. `sodium_mprotect_noaccess()` makes pages inaccessible. `sodium_free()` zeroes the memory before unlocking and returning to OS.
   - *Verification in Code*: `Secret::allocate` and `Secret::~Secret` adhere to libsodium primitives, but `Secret::zeroize` needlessly calls `mprotect_readwrite` and `memzero` before `mprotect_noaccess`.
2. **libsodium AEAD XChaCha20-Poly1305**:
   - *Source*: [libsodium official docs — Authenticated Encryption (XChaCha20-Poly1305 IETF)](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
   - *Doc Rule*: Key must be `crypto_aead_xchacha20poly1305_ietf_KEYBYTES` (32 bytes). Nonce must be `crypto_aead_xchacha20poly1305_ietf_NPUBBYTES` (24 bytes). Tag is `crypto_aead_xchacha20poly1305_ietf_ABYTES` (16 bytes).
   - *Verification in Code*: `VaultCrypto.h` constants match libsodium definitions exactly (`kSaltBytes=16`, `kNonceBytes=24`, `kKeyBytes=32`, `kTagBytes=16`).
3. **Chrome & Firefox Native Messaging Protocol**:
   - *Source*: [MDN WebExtensions Native Messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging) & [Google Chrome Extensions — Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
   - *Official Limits*:
     - **Chrome**: Host -> Browser: maximum message size is 1 MB (1,048,576 bytes). Browser -> Host: maximum message size is 4 GB (4,294,967,295 bytes, 32-bit unsigned int in native byte order).
     - **Firefox**: Host -> Browser: maximum message size is 1 MB (1,048,576 bytes). Browser -> Host: maximum message size is 1 MB (1,048,576 bytes).
   - *Command-line Arguments*:
     - **Chrome**: Passes `argv[1]` = `chrome-extension://<extension_id>/`. On Windows, Chrome also appends `--parent-window=<HWND>`.
     - **Firefox**: Passes `argv[1]` = path to the native messaging JSON manifest, and `argv[2]` = add-on ID (e.g., `pwledger@example.com` or UUID).
   - *Verification in Code*: `NativeMessaging.cc` enforces `kMaxMessageBytes = 1024 * 1024` (1 MB), which complies safely with Firefox's strict 1 MB ceiling and Chrome's host-to-browser limit. `apps/native_host/main.cc` currently ignores all `argv` arguments entirely.
4. **nlohmann/json**:
   - *Source*: [nlohmann/json documentation](https://json.nlohmann.me/api/basic_json/)
   - *Doc Rule*: `j.value(key, default_val)` throws `json::type_error` (302) if key exists but type does not match `default_val`'s type.
   - *Verification in Code*: `req.value("password", "")` in `handle_unlock` throws if `"password"` is passed as a non-string JSON type.

---

## Code Simplification & Chesterton's Fence

Applying Chesterton's Fence ("Do not remove an abstraction until you understand why it was built"):

1. **`TerminalManager` CRTP Base**:
   - *Why it was built*: Designed as a template base to enforce compile-time interfaces via `TerminalManagerDerivable` concept across Windows and Unix platforms.
   - *Why it should be simplified*: Only one platform is ever compiled in any single compilation unit. The base class has a no-op destructor and provides zero code reuse. A single concrete class `TerminalManager` with pimpl or `#ifdef` private platform data preserves the exact RAII guarantees while removing 120 lines of template/concept boilerplate.
2. **`MessageLoop.cc` Trampoline Functions**:
   - *Why it was built*: To match an all-encompassing `Handler` function pointer signature taking `(req, state, table, cfg, id)`.
   - *Why it should be simplified*: Handlers can directly accept the uniform context or be called cleanly via lambdas inside the dispatch map.
3. **`uuid.cc` custom mt19937 PRNG**:
   - *Why it was built*: To generate UUIDs without pulling in external UUID dependencies.
   - *Why it should be simplified*: The project already links `libsodium`. `randombytes_buf()` is cryptographically secure, already in memory, and reduces `Uuid::generate()` from 20 lines of PRNG boilerplate to a secure 5-line implementation.

---

## Browser Extension Review (Frontend & Security)

1. **Auto-fill Injection Vulnerability**:
   `content.js` scans visible password fields and immediately queries credentials for the current page hostname. If a single match exists, it immediately writes the credentials into the input fields. This allows silent credential scraping.
   *Fix*: Auto-fill must only occur when explicitly triggered by the user via the popup UI or clicking the password field badge.
2. **Tab URL Spoofing**:
   `background.js` handles `"page_loaded"` by parsing `message.url` sent from `content.js`. A malicious frame or subresource script running in a tab can post `{command: "page_loaded", url: "https://mybank.com"}`.
   *Fix*: `background.js` must verify `sender.tab.url` instead of trusting `message.url`.
3. **Manifest Permissions**:
   `manifest.json` requests `<all_urls>` content script injection. While needed for generic auto-fill, `all_frames: false` should be explicitly set so credentials are not auto-injected into untrusted third-party advertising iframes.

---

## Proposed Refactoring Themes

We propose organizing Phase 3 into four focused, incremental refactoring themes:

### Theme 1: Core Type Safety, Buffer Lifecycle & Cryptography Hardening
- **Task 1.1**: Fix `Uuid` unaligned pointer dereference in `std::hash<Uuid>` and replace `mt19937` with `libsodium` CSPRNG.
- **Task 1.2**: Extend `SecretEntry` / `Secret` with explicit payload length handling, eliminating all `strnlen` calls and truncation bugs.
- **Task 1.3**: Harden `VaultSerializer::deserialize` with strict validation bounds (`kMaxEntries`, `kMaxSecretLen`, `kMaxStringLen`) preventing integer overflows and abort crashes.
- **Task 1.4**: Introduce a secure memory buffer for serialization/encryption to prevent plaintext password leakage into the general heap.
- **Task 1.5**: Harden `VaultIO::save_vault` with robust atomic replacement (handling Windows `MoveFileExW` / `replace_existing`), `fsync`, and restrictive initial file creation permissions.

### Theme 2: Build System Modernization & Hardening Flags Activation
- **Task 2.1**: Refactor CMake compiler configuration into clean interface target `pwledger_hardening_flags`.
- **Task 2.2**: Activate and verify all MSVC hardening flags (`/GS`, `/sdl`, `/guard:cf`, `/NXCOMPAT`, `/DYNAMICBASE`) on Windows.
- **Task 2.3**: Remove unused CMake variables and clean up target include paths.
- **Task 2.4**: Establish automated CI workflow (`.github/workflows/ci.yml`) covering Linux, macOS, and Windows with unit tests and sanitizers.

### Theme 3: Code Simplification & Module Boundaries
- **Task 3.1**: Simplify `TerminalManager`: eliminate CRTP template hierarchy and concept in favor of a clean, direct RAII class.
- **Task 3.2**: Implement terminal backspace/delete handling in `read_secret_from_stdin` so typing corrections do not corrupt passwords.
- **Task 3.3**: Remove zombie code (`SecureAllocator` stub) and unneeded dispatch trampolines in `MessageLoop.cc`.
- **Task 3.4**: Clean up error semantics: establish clear distinction between fatal contract violations and user-recoverable errors.

### Theme 4: Native Messaging Host & Browser Extension Hardening
- **Task 4.1**: Implement fail-closed `argv` extension ID and origin validation in `pwledger-host` matching `IntegrationConfig::allowed_extensions` (handling both Chrome origin format with `--parent-window` filter and Firefox manifest/ID arguments).
- **Task 4.2**: Sanitize native messaging secret handling: wipe temporary std::string buffers and memory holding credentials.
- **Task 4.3**: Fix `ClipboardTimer` lifecycle: cancel clipboard timer on vault lock and support Unicode (`CF_UNICODETEXT`) on Windows.
- **Task 4.4**: Secure browser extension: switch auto-fill to require explicit user action (opt-in `integration.autofill_on_load`), restrict content script to top frame (`all_frames: false`), and validate `sender.tab.url` in `background.js`.

---

## Verification Plan for Phase 3 & 4

1. **Build Presets Verification**:
   - Windows MSVC (RelWithDebInfo + Debug with `/fsanitize=address`)
   - MinGW GCC 14.2 (with `-fsanitize=address,undefined`)
   - Linux / macOS in CI matrix
2. **Behavioral Invariant Preservation**:
   - Vault V1 binary format (`PWL\0`, version 1) remains 100% round-trip compatible with existing test cases.
   - Native messaging JSON protocol remains fully compatible with extension commands (`ping`, `unlock`, `lock`, `init_vault`, `search`, `copy`, `clip_clear`, `get_credentials`).
   - Public CLI commands remain identical.
3. **Failing Tests First (Phase 4)**:
   - For every bug identified above (e.g. secret containing `\0`, corrupt payload length, unaligned UUID hash, extension ID check), write the failing test case before implementing fixes.

---

## Approved User Decisions & Architectural Direction

1. **Vault File Format Compatibility**:
   - **V1 format remains byte-compatible.** There is **no format version bump**. Existing vaults must load completely unchanged.
   - Writing exact secret length is natively supported because the V1 binary format already length-prefixes secrets with 32-bit integers.
   - Older vaults may already contain `strnlen`-truncated secrets created by the original code. As these cannot be algorithmically recovered, this is formally documented as a known limitation in ADR-002.
   - A compatibility fixture (a vault generated by the original code) will be committed as a persistent test asset that all refactored code must successfully open and decrypt.
2. **Git Repository Setup**:
   - Repository initialized with `git init`, clean `.gitignore` committed, and baseline commit `5cf5990` created on `main`.
   - Phase 3 will use `refactor/<theme>` branches with atomic, buildable commits (~100 lines each).
3. **Auto-Fill Policy**:
   - Default: Require explicit user gesture (popup action or field badge click).
   - Opt-in configuration: `integration.autofill_on_load` (default `false`).
   - Browser extension enforces `"all_frames": false`, verifies `sender.tab.url`, asserts `sender.frameId === 0`, and matches against full registrable origins.
4. **Native Messaging Host Origin Validation**:
   - Scan all `argv` arguments, strip `--parent-window=...`, handle Chrome `chrome-extension://<id>/` and Firefox manifest path / ID forms.
   - Fail closed if `allowed_extensions` is empty or no match is found. Print clear diagnostic to `std::cerr` instructing the user how to configure it.
   - Update `setup/` scripts to register and configure extension IDs.
5. **Platform Scope**:
   - Linux, macOS, Windows MSVC, MinGW cross-compilation remain fully supported.
