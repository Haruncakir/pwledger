# pwledger

A professional-grade, offline-first password vault built in modern C++20. Secrets are stored exclusively in [libsodium](https://doc.libsodium.org/)-hardened memory with hardware-enforced access protection (`mprotect` / `mlock`). No cloud, no telemetry, no network traffic.

## Features

- **Hardened memory**: all secrets reside in `sodium_malloc` pages with guard regions, canaries, and `NOACCESS` protection between uses
- **RAII guards**: scoped `with_read_access` / `with_write_access` API that temporarily unlocks memory and re-locks on scope exit
- **Process hardening**: core dump suppression (`prctl`, `setrlimit`), anti-debugger hints
- **Cross-platform**: Linux, macOS, and Windows (MSVC) support
- **CLI interface**: interactive CRUD with echo-suppressed input, clipboard integration, and constant-time confirmation
- **Browser extension**: native messaging host for Firefox

## Prerequisites

| Dependency | Minimum Version | Purpose |
|------------|-----------------|---------|
| **CMake** | 3.15 | Build system |
| **C++ compiler** | C++20 (GCC 11+, Clang 14+, MSVC 19.29+) | Language standard |
| **libsodium** | 1.0.18 | Cryptographic primitives and hardened allocator |
| **GoogleTest** | *(fetched automatically)* | Test framework |
| **nlohmann/json** | *(fetched automatically)* | JSON parsing for the native messaging host |

### Installing libsodium

```bash
# Ubuntu / Debian
sudo apt install libsodium-dev

# macOS (Homebrew)
brew install libsodium

# Windows (vcpkg)
vcpkg install libsodium
```

## Building

```bash
# Configure (from project root)
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build
cmake --build build -j$(nproc)

# Run tests
cd build && ctest --output-on-failure
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `PWLEDGER_ENABLE_SECURITY_HARDENING` | `ON` | Stack protection, PIE, RELRO, `_FORTIFY_SOURCE` |
| `PWLEDGER_ENABLE_SANITIZERS` | `OFF` | AddressSanitizer + UBSan (Debug builds only) |
| `PWLEDGER_ENABLE_STATIC_ANALYSIS` | `OFF` | Static analysis tool integration |
| `PWLEDGER_BUILD_TESTS` | `ON` | Build the GoogleTest test suite |

## Usage

### CLI

```bash
./build/apps/pwledger-cli
```

Available commands: `add`, `get`, `update`, `delete`, `list`, `copy`, `clip-clear`, `help`, `quit`.

### Browser Extension (Firefox)

The repository includes a Firefox browser extension that communicates with the `pwledger-host` native messaging host. Installation requires registering the native host manifest with Firefox, which involves placing the `pwledger.json` file in a specific directory or registry key depending on your Operating System.

First, update the `"path"` inside `extension/pwledger.json` to point your built `pwledger-host` executable. Ensure the executable has run permissions (Linux/macOS/WSL).
*(e.g., `"path": "/home/user/passwordledger/build/apps/native_host/pwledger-host"` or `"path": "C:\\path\\to\\pwledger-host.exe"`)*

1. **Install Native Host Manifest**

   **Linux / WSL:**
   ```bash
   mkdir -p ~/.mozilla/native-messaging-hosts
   cp extension/pwledger.json ~/.mozilla/native-messaging-hosts/
   ```

   **macOS:**
   ```bash
   mkdir -p ~/Library/Application\ Support/Mozilla/NativeMessagingHosts
   cp extension/pwledger.json ~/Library/Application\ Support/Mozilla/NativeMessagingHosts/
   ```

   **Windows:**
   1. Open the Registry Editor (`regedit`).
   2. Navigate to `HKEY_CURRENT_USER\SOFTWARE\Mozilla\NativeMessagingHosts\pwledger`. (Create the `NativeMessagingHosts` and `pwledger` keys if they do not exist).
   3. Set the default value of the `pwledger` key to the absolute path of your modified `pwledger.json` file (e.g., `C:\path\to\passwordledger\extension\pwledger.json`).

2. **Load the Extension**
   - Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
   - Click **"Load Temporary Add-on..."**
   - Select `extension/manifest.json` from this repository

The extension can unlock your vault, search entries, and securely copy secrets to your clipboard.


## Security Model

- **Memory**: `sodium_malloc` → `mlock` + guard pages + canaries. Buffers are in `NOACCESS` (hardware-enforced) except inside scoped access guards.
- **Destruction**: `sodium_free` zeroes before releasing. No dangling plaintext.
- **Process**: core dumps disabled, stack protector, PIE/ASLR, RELRO, `_FORTIFY_SOURCE=2`.
- **Clipboard**: best-effort clear-after-use (manual `clip-clear` command; auto-clear timer planned).
- **Persistence**: currently in-memory only. Planned: Argon2id KDF → XChaCha20-Poly1305 encrypted file.

## License

MIT — see [LICENSE](LICENSE).
