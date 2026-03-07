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

The repository includes a Firefox browser extension that communicates with the `pwledger-host` native messaging host.

1. **Install Native Host Manifest**
   ```bash
   mkdir -p ~/.mozilla/native-messaging-hosts
   
   # Update the "path" in extension/pwledger.json to point to your build directory's pwledger-host before copying:
   # "path": "/home/your_user/path/to/passwordledger/build/apps/native_host/pwledger-host"
   
   cp extension/pwledger.json ~/.mozilla/native-messaging-hosts/
   ```

2. **Load the Extension**
   - Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
   - Click **"Load Temporary Add-on..."**
   - Select `extension/manifest.json` from this repository

The extension can unlock your vault, search entries, and securely copy secrets to your clipboard.

## Architecture

```
include/pwledger/
  Secret.h            # RAII container for sensitive byte buffers (sodium_malloc)
  TerminalManager.h   # Cross-platform echo suppression (CRTP + platform impls)

apps/
  cli/main.cc         # CLI entry point, CRUD, clipboard, command loop
  native_host/main.cc # Browser extension native messaging host (Firefox)

src/                  # Core library (header-only for now)
tests/                # GoogleTest suite
cmake/                # FindSodium, compiler flag modules
```

## Security Model

- **Memory**: `sodium_malloc` → `mlock` + guard pages + canaries. Buffers are in `NOACCESS` (hardware-enforced) except inside scoped access guards.
- **Destruction**: `sodium_free` zeroes before releasing. No dangling plaintext.
- **Process**: core dumps disabled, stack protector, PIE/ASLR, RELRO, `_FORTIFY_SOURCE=2`.
- **Clipboard**: best-effort clear-after-use (manual `clip-clear` command; auto-clear timer planned).
- **Persistence**: currently in-memory only. Planned: Argon2id KDF → XChaCha20-Poly1305 encrypted file.

## License

MIT — see [LICENSE](LICENSE).
