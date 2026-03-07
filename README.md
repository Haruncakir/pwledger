# pwledger

A professional-grade, offline-first password vault built in modern C++20. Secrets are stored exclusively in [libsodium](https://doc.libsodium.org/)-hardened memory with hardware-enforced access protection (`mprotect` / `mlock`). No cloud, no telemetry, no network traffic.

---

## Table of Contents

- [Features](#features)
- [Security Model](#security-model)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [CLI Usage](#cli-usage)
- [Browser Extension](#browser-extension)
  - [How It Works](#how-it-works)
  - [Building the Native Host](#building-the-native-host)
  - [Registering the Native Host Manifest](#registering-the-native-host-manifest)
    - [Linux and WSL](#linux-and-wsl)
    - [macOS](#macos)
    - [Windows](#windows)
  - [Loading the Extension in Firefox](#loading-the-extension-in-firefox)
  - [Verifying the Connection](#verifying-the-connection)
  - [Troubleshooting](#troubleshooting)
- [Deploying from WSL to Windows](#deploying-from-wsl-to-windows)
  - [Why a Separate Build is Required](#why-a-separate-build-is-required)
  - [Step 1 — Install Windows Build Dependencies](#step-1--install-windows-build-dependencies)
  - [Step 2 — Build the Windows Native Host](#step-2--build-the-windows-native-host)
  - [Step 3 — Copy the Binary to Windows](#step-3--copy-the-binary-to-windows)
  - [Step 4 — Register the Manifest and Load the Extension](#step-4--register-the-manifest-and-load-the-extension)
  - [Dependency Checklist](#dependency-checklist)
  - [Common Mistakes](#common-mistakes)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

- **Hardened memory** — all secrets reside in `sodium_malloc` pages with guard regions, canaries, and `NOACCESS` protection between uses; no secret ever touches ordinary heap memory
- **RAII access guards** — scoped `with_read_access` / `with_write_access` API unlocks memory temporarily and re-locks on scope exit, even through exceptions
- **Process hardening** — core dump suppression via `prctl(PR_SET_DUMPABLE, 0)` and `setrlimit(RLIMIT_CORE, {0,0})`; anti-debugger hints on all supported platforms
- **Constant-time operations** — password confirmation uses `sodium_memcmp`; no timing side-channels on secret comparison
- **Cross-platform** — Linux, macOS, and Windows (MSVC) supported
- **CLI interface** — interactive CRUD with echo-suppressed input, clipboard integration, and scoped secret lifetimes
- **Browser extension** — Firefox native messaging host for vault access from the browser

---

## Security Model

Understanding the security boundaries is important before deploying pwledger.

### Memory Protection

Secrets are allocated via `sodium_malloc`, which:
- calls `mlock` to prevent the pages from being swapped to disk
- places inaccessible guard pages before and after the allocation to catch overflows
- fills the allocation with a canary pattern to detect underflows
- sets the allocation to `NOACCESS` (hardware-enforced via `mprotect`) immediately after construction

The buffer is only readable or writable inside an active `with_read_access` / `with_write_access` scope. Any attempt to read or write the buffer outside a guard triggers a segfault rather than a silent memory exposure.

On destruction, `sodium_free` calls `sodium_memzero` (a compiler-barrier-protected wipe) before releasing the page. No plaintext secret lingers in freed memory.

### Process Hardening

At startup, before any secret is constructed, pwledger calls:

- `prctl(PR_SET_DUMPABLE, 0)` — prevents the kernel from writing a core file on crash, which would otherwise contain all in-memory secrets
- `setrlimit(RLIMIT_CORE, {0, 0})` — sets the core file size limit to zero independently of dumpability, covering child processes that re-enable dumpability via `prctl`

These are best-effort: containers with restrictive seccomp profiles may block `prctl`. A warning is printed to stderr if either call fails; the application continues.

### Clipboard

Clipboard operations are an inherent security concession. Any process running under the same user session can read the clipboard. pwledger minimizes exposure by:
- writing to the clipboard through a scoped `with_read_access` guard (the buffer is immediately re-locked after the write)
- providing a `clip-clear` command and a browser extension button to overwrite the clipboard as soon as the secret is no longer needed

An automatic clear-after-timeout is planned but not yet implemented.

### Persistence

The vault is currently **in-memory only**. No data is written to disk in the current release. Encrypted persistence (Argon2id KDF → XChaCha20-Poly1305) is planned; see [Roadmap](#roadmap).

### Native Messaging Host (Browser Extension)

The native messaging host communicates with the browser over stdin/stdout using the [Chrome/Firefox Native Messaging protocol](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging). The security implications are:

- The host process runs with the same OS user privileges as the browser
- The browser enforces that only extensions with a matching extension ID can communicate with the host (declared in the manifest `allowed_extensions` field)
- The master password is transmitted in plaintext over the JSON message; there is no additional in-transit encryption beyond the OS pipe
- Exposure of the password in transit is minimized by zeroing the intermediary `std::string` immediately after use, but the JSON parser may retain internal copies

---

## Prerequisites

| Dependency | Minimum Version | Purpose |
|---|---|---|
| **CMake** | 3.15 | Build system |
| **C++ compiler** | C++20 (GCC 11+, Clang 14+, MSVC 19.29+) | Language standard |
| **libsodium** | 1.0.18 | Cryptographic primitives and hardened allocator |
| **GoogleTest** | *(fetched automatically)* | Unit test framework |
| **nlohmann/json** | *(fetched automatically)* | JSON for the native messaging host |

### Installing libsodium

**Ubuntu / Debian**
```bash
sudo apt install libsodium-dev
```

**macOS (Homebrew)**
```bash
brew install libsodium
```

**Windows (vcpkg)**
```bash
vcpkg install libsodium
```

**Windows (manual)**

Download the prebuilt binaries from the [libsodium releases page](https://download.libsodium.org/libsodium/releases/) and set `CMAKE_PREFIX_PATH` to the extracted directory when configuring CMake.

---

## Building

All commands are run from the repository root.

```bash
# Configure
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build all targets
cmake --build build -j$(nproc)

# Run tests
cd build && ctest --output-on-failure
```

### CMake Options

| Option | Default | Description |
|---|---|---|
| `PWLEDGER_ENABLE_SECURITY_HARDENING` | `ON` | Stack protector, PIE, RELRO, `_FORTIFY_SOURCE=2` |
| `PWLEDGER_ENABLE_SANITIZERS` | `OFF` | AddressSanitizer + UBSan (Debug builds only) |
| `PWLEDGER_ENABLE_STATIC_ANALYSIS` | `OFF` | clang-tidy / cppcheck integration |
| `PWLEDGER_BUILD_TESTS` | `ON` | Build the GoogleTest suite |

### Build Outputs

| Binary | Location | Description |
|---|---|---|
| `pwledger-cli` | `build/apps/pwledger-cli` | Interactive CLI |
| `pwledger-host` | `build/apps/native_host/pwledger-host` | Firefox native messaging host |
| Test suite | `build/tests/` | GoogleTest binaries |

---

## CLI Usage

```bash
./build/apps/pwledger-cli
```

The CLI presents an interactive prompt. Type `help` to list available commands.

| Command | Description |
|---|---|
| `add` | Add a new credential entry |
| `get` | Display an entry (secret length shown, value never printed) |
| `update` | Replace the secret for an existing entry |
| `delete` | Remove an entry permanently |
| `list` | List all entries with metadata |
| `copy` | Copy an entry's secret to the clipboard |
| `clip-clear` | Overwrite the clipboard with an empty string |
| `help` | Show available commands |
| `quit` | Exit the CLI (all secrets zeroed and freed on exit) |

**Input handling**: when any command prompts for a secret, terminal echo is suppressed via `TerminalManager` (RAII-backed `tcsetattr` on POSIX, `SetConsoleMode` on Windows). The terminal is restored to its original state on scope exit, including on exception.

---

## Browser Extension

The browser extension provides vault search and clipboard copy from Firefox. It communicates with the `pwledger-host` process using the [Native Messaging protocol](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging).

### How It Works

```
Firefox Extension  ──stdin/stdout──►  pwledger-host (native process)
      │                                        │
  popup UI                           reads vault, copies to clipboard
```

The extension sends JSON commands (unlock, search, copy, lock) over a pipe to the native host. The host holds the in-memory vault for the duration of the browser session and auto-locks when the pipe closes (i.e., when the browser exits or the extension is disabled).

### Building the Native Host

The native host is built alongside the rest of the project. Ensure you have run the full build as described in [Building](#building).

After a successful build, note the absolute path to the host binary — you will need it in the next step:

```
build/apps/native_host/pwledger-host          # Linux / macOS
build\apps\native_host\pwledger-host.exe      # Windows
```

### Registering the Native Host Manifest

The `extension/pwledger.json` manifest tells Firefox where to find the `pwledger-host` binary and which extension IDs are permitted to communicate with it. You must:

1. Edit `extension/pwledger.json` and set the `"path"` field to the **absolute path** of your built `pwledger-host` binary.
2. Copy the manifest to the platform-specific location Firefox expects.

> **Important**: the path must be absolute. Relative paths are not supported by Firefox's native messaging implementation.

#### Linux and WSL

```bash
# Create the native messaging hosts directory if it does not exist
mkdir -p ~/.mozilla/native-messaging-hosts

# Copy the manifest
cp extension/pwledger.json ~/.mozilla/native-messaging-hosts/

# Verify the path in the manifest points to your binary
cat ~/.mozilla/native-messaging-hosts/pwledger.json
```

**WSL users**: Firefox runs on the Windows host, not inside the WSL Linux environment. A Linux ELF binary built inside WSL cannot be executed directly by Windows Firefox. You must build a native Windows executable (`.exe`) and register it with the Windows-side Firefox. See [Deploying from WSL to Windows](#deploying-from-wsl-to-windows) for the full procedure.

#### macOS

```bash
# Create the directory if it does not exist
mkdir -p ~/Library/Application\ Support/Mozilla/NativeMessagingHosts

# Copy the manifest
cp extension/pwledger.json \
   ~/Library/Application\ Support/Mozilla/NativeMessagingHosts/

# Verify
cat ~/Library/Application\ Support/Mozilla/NativeMessagingHosts/pwledger.json
```

The `pwledger-host` binary must be executable:

```bash
chmod +x /absolute/path/to/pwledger-host
```

If macOS Gatekeeper blocks the binary on first launch (unsigned binary warning), run the following once to clear the quarantine flag:

```bash
xattr -d com.apple.quarantine /absolute/path/to/pwledger-host
```

#### Windows

Firefox reads the native host manifest path from the Windows Registry.

**Using PowerShell (recommended)**

Open PowerShell as your regular user (administrator is not required):

```powershell
# Set the path to your manifest file (edit this line)
$manifestPath = "C:\absolute\path\to\extension\pwledger.json"

# Create the registry key and set the default value
New-Item -Path "HKCU:\SOFTWARE\Mozilla\NativeMessagingHosts\pwledger" -Force
Set-ItemProperty `
    -Path "HKCU:\SOFTWARE\Mozilla\NativeMessagingHosts\pwledger" `
    -Name "(Default)" `
    -Value $manifestPath
```

**Using the Registry Editor (manual)**

1. Open **Registry Editor** (`Win + R` → `regedit` → Enter).
2. Navigate to `HKEY_CURRENT_USER\SOFTWARE\Mozilla\NativeMessagingHosts`.
   - If the `NativeMessagingHosts` key does not exist, right-click `Mozilla` → **New → Key** and name it `NativeMessagingHosts`.
3. Right-click `NativeMessagingHosts` → **New → Key** → name it `pwledger`.
4. Click the `pwledger` key. In the right pane, double-click the `(Default)` value.
5. Set the value data to the absolute path of your `pwledger.json` manifest file (e.g., `C:\Users\you\passwordledger\extension\pwledger.json`).
6. Click **OK**.

Inside `extension/pwledger.json`, set the `"path"` field to the absolute path of the `pwledger-host.exe` binary:

```json
{
  "name": "pwledger",
  "description": "pwledger native messaging host",
  "path": "C:\\absolute\\path\\to\\pwledger-host.exe",
  "type": "stdio",
  "allowed_extensions": ["pwledger@example.com"]
}
```

> **Note**: Windows paths in JSON must use double backslashes (`\\`) or forward slashes (`/`).

### Loading the Extension in Firefox

1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2. Click **"Load Temporary Add-on..."**.
3. Navigate to the `extension/` directory in this repository and select `manifest.json`.
4. The pwledger icon should appear in the Firefox toolbar.

> **Temporary add-ons** are removed when Firefox closes. For a persistent installation, the extension must be signed by Mozilla or Firefox must be configured with `xpinstall.signatures.required = false` in `about:config` (development use only).

### Verifying the Connection

After loading the extension, click the pwledger toolbar icon. The popup should display a connection status. If the vault is not yet initialized, you will see a prompt to unlock or create a vault.

To confirm the native host is reachable, open the Firefox DevTools console on the extension's background page (`about:debugging` → inspect the extension) and check for any native messaging errors.

### Troubleshooting

**The extension shows "Native host not found" or "Host not found"**

- Verify the manifest file exists at the exact path Firefox expects (see platform instructions above).
- Verify the `"path"` inside the manifest points to the correct absolute path of `pwledger-host` (or `pwledger-host.exe`).
- On Linux/macOS, verify the binary is executable: `ls -l /path/to/pwledger-host`.
- The manifest filename on disk must match the `"name"` field inside the JSON exactly: `pwledger.json` for name `"pwledger"`.
- Restart Firefox after making changes to the registry (Windows) or manifest file.

**The extension loads but the popup shows no response**

- Check the Firefox DevTools console on the background page for `NativeMessaging` errors.
- Run `pwledger-host` directly from a terminal to confirm it starts without errors. It will block waiting for stdin input; that is normal. Press `Ctrl-C` to exit.
- On macOS, check that the quarantine attribute has been cleared (see [macOS](#macos) above).

**On Windows: "Access is denied" or "The system cannot find the file"**

- Confirm the registry key is under `HKEY_CURRENT_USER` (not `HKEY_LOCAL_MACHINE`), which does not require administrator rights.
- Confirm backslashes are doubled in the JSON path string.
- Confirm the binary path does not contain spaces without quoting issues; using forward slashes avoids this.

**Logs**

The native host writes warnings and errors to stderr. Firefox captures stderr from the native host and surfaces it in the DevTools console of the extension's background page under the `NativeMessaging` category.

---

## Deploying from WSL to Windows

This section covers the case where the project is developed and built inside WSL (Windows Subsystem for Linux) and the browser extension's native host needs to run under Windows Firefox.

### Why a Separate Build is Required

WSL provides a Linux kernel environment. Binaries compiled inside WSL are ELF executables targeting the Linux ABI. Windows Firefox spawns native Windows processes via the Win32 API — it cannot execute a Linux ELF binary, even inside WSL 2. This means:

- The `pwledger-host` binary you built inside WSL **cannot** be registered with or launched by Windows Firefox.
- You need a separate **Windows PE32+ executable** (`.exe`) compiled against the Windows CRT and Win32 APIs.
- The CLI (`pwledger-cli`) can continue to run inside WSL for development and testing. Only `pwledger-host` needs to be a Windows binary for the browser extension to work.

There are two ways to produce the Windows executable:

| Approach | Toolchain | Where it runs |
|---|---|---|
| **Cross-compile inside WSL** | MinGW-w64 (`x86_64-w64-mingw32-g++`) | Build in WSL, output is a `.exe` |
| **Native Windows build** | MSVC or LLVM/Clang via Visual Studio | Build in a Windows terminal (PowerShell / cmd) |

The cross-compilation approach is more convenient for a WSL-first workflow and is covered in detail below. The native Windows build follows the standard [Building](#building) instructions run from a Windows terminal with MSVC or a Windows CMake/Clang installation.

---

### Step 1 — Install Windows Build Dependencies

#### Inside WSL: cross-compilation with MinGW-w64

Install the MinGW-w64 cross-compiler and CMake inside your WSL distribution:

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install cmake mingw-w64 mingw-w64-tools
```

Install the Windows build of libsodium. MinGW-w64 requires the MinGW-compatible static or shared library, not the MSVC `.lib`. Download the prebuilt MinGW binaries from the [libsodium releases page](https://download.libsodium.org/libsodium/releases/) — look for a filename of the form `libsodium-X.Y.Z-mingw.tar.gz`.

```bash
# Example — adjust the version number to the latest release
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-mingw.tar.gz
tar -xf libsodium-1.0.18-mingw.tar.gz

# The archive contains win32 and win64 subdirectories. Use win64 for a
# 64-bit target (x86_64-w64-mingw32).
# Note the path — you will pass it to CMake as CMAKE_PREFIX_PATH below.
ls libsodium-win64/
```

> **Important**: do not use the `libsodium-dev` package installed via `apt` for the Windows cross-build. That package contains Linux `.so` libraries and Linux headers. The MinGW cross-compiler must link against the MinGW-compatible Windows `.a` / `.dll.a` files from the tarball above.

#### On Windows: native build with MSVC

If you prefer to build natively on Windows, install:

- [Visual Studio 2022](https://visualstudio.microsoft.com/) with the **Desktop development with C++** workload (includes MSVC 19.29+ and CMake)
- [vcpkg](https://vcpkg.io/) for libsodium: `vcpkg install libsodium:x64-windows`
- Or download libsodium MSVC prebuilts from the [releases page](https://download.libsodium.org/libsodium/releases/) — look for `libsodium-X.Y.Z-msvc.zip`

---

### Step 2 — Build the Windows Native Host

#### Cross-compiling inside WSL

A CMake toolchain file is required to tell CMake to use the MinGW-w64 cross-compiler instead of the host GCC. Create `cmake/toolchains/mingw-w64-x86_64.cmake` in the repository root if it does not already exist:

```cmake
# cmake/toolchains/mingw-w64-x86_64.cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
```

Configure and build, pointing CMake at the MinGW libsodium you extracted in Step 1:

```bash
cmake -B build-windows \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_PREFIX_PATH=/absolute/wsl/path/to/libsodium-win64 \
    -DPWLEDGER_BUILD_TESTS=OFF

cmake --build build-windows --target pwledger-host -j$(nproc)
```

`PWLEDGER_BUILD_TESTS=OFF` skips fetching and building GoogleTest for the Windows target, which is not needed for the native host deployment.

The output binary will be at:

```
build-windows/apps/native_host/pwledger-host.exe
```

Verify it is a valid Windows PE executable:

```bash
file build-windows/apps/native_host/pwledger-host.exe
# Expected output: PE32+ executable (console) x86-64, for MS Windows
```

#### Native build on Windows

From a **Developer PowerShell for VS 2022** or a terminal with MSVC in `PATH`:

```powershell
cmake -B build `
    -DCMAKE_BUILD_TYPE=RelWithDebInfo `
    -DCMAKE_TOOLCHAIN_FILE="C:\path\to\vcpkg\scripts\buildsystems\vcpkg.cmake" `
    -DPWLEDGER_BUILD_TESTS=OFF

cmake --build build --target pwledger-host
```

---

### Step 3 — Copy the Binary to Windows

If you cross-compiled inside WSL, copy the `.exe` to a stable Windows-side directory. Avoid placing it inside the WSL filesystem path (`\\wsl$\...`) — Windows can access files there, but the path is long and fragile. Copy it to a plain Windows path instead:

```bash
# From inside WSL — adjust the Windows username and destination
cp build-windows/apps/native_host/pwledger-host.exe \
   /mnt/c/Users/<YourWindowsUsername>/pwledger/pwledger-host.exe
```

The destination directory (`C:\Users\<YourWindowsUsername>\pwledger\`) must exist before copying. Create it from PowerShell if needed:

```powershell
New-Item -ItemType Directory -Path "C:\Users\$env:USERNAME\pwledger" -Force
```

> **Do not place the binary on a network drive, a removable drive, or a path that requires elevation to read.** Firefox spawns the native host as the current user; if the binary is inaccessible to that user, the spawn will silently fail.

#### Runtime DLL dependencies

If you compiled with MinGW-w64, the resulting `.exe` may dynamically link against MinGW runtime DLLs (`libstdc++-6.dll`, `libgcc_s_seh-1.dll`, `libwinpthread-1.dll`). These are not present on a standard Windows installation.

Check what the binary depends on before copying:

```bash
# Inside WSL
x86_64-w64-mingw32-objdump -p build-windows/apps/native_host/pwledger-host.exe \
    | grep "DLL Name"
```

If MinGW DLLs appear in the output, either:

**Option A — Copy the DLLs alongside the binary (simplest)**

```bash
# Locate the DLLs in the MinGW sysroot
ls /usr/lib/gcc/x86_64-w64-mingw32/*/
ls /usr/x86_64-w64-mingw32/lib/

# Copy the required DLLs to the same directory as the .exe
cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll \
   /mnt/c/Users/<YourWindowsUsername>/pwledger/
# Repeat for libstdc++-6.dll and libgcc_s_seh-1.dll if present
```

Firefox launches the native host with its own working directory, which may not be the binary's directory. Set `PATH` to include the binary directory, or use Option B.

**Option B — Link statically (recommended for distribution)**

Rebuild with static linking flags to produce a fully self-contained `.exe` with no external DLL dependencies:

```bash
cmake -B build-windows \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_PREFIX_PATH=/absolute/wsl/path/to/libsodium-win64 \
    -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++" \
    -DPWLEDGER_BUILD_TESTS=OFF

cmake --build build-windows --target pwledger-host -j$(nproc)
```

Verify the resulting binary has no MinGW DLL dependencies:

```bash
x86_64-w64-mingw32-objdump -p build-windows/apps/native_host/pwledger-host.exe \
    | grep "DLL Name"
# Should show only Windows system DLLs: KERNEL32.dll, msvcrt.dll, etc.
```

> **libsodium static linking**: the MinGW prebuilt tarball provides both `libsodium.a` (static) and `libsodium.dll.a` (import library for the DLL). When building with `-static`, CMake will prefer `libsodium.a` automatically if you set `CMAKE_PREFIX_PATH` to the MinGW libsodium directory. Verify by checking that `libsodium.dll` does not appear in the `objdump` output.

---

### Step 4 — Register the Manifest and Load the Extension

With the `.exe` on a stable Windows path, follow the [Windows](#windows) registration instructions. The only WSL-specific consideration is that you must edit `extension/pwledger.json` from the Windows side (or from WSL with a Windows path) and ensure the `"path"` field is a Windows absolute path:

```json
{
  "name": "pwledger",
  "description": "pwledger native messaging host",
  "path": "C:\\Users\\YourUsername\\pwledger\\pwledger-host.exe",
  "type": "stdio",
  "allowed_extensions": ["pwledger@example.com"]
}
```

Copy the manifest from WSL to the Windows-side Firefox directory:

```bash
# From inside WSL
cp extension/pwledger.json \
   /mnt/c/Users/<YourWindowsUsername>/AppData/Roaming/Mozilla/NativeMessagingHosts/pwledger.json
```

Then register the registry key as described in [Windows](#windows) and load the extension in Firefox as described in [Loading the Extension in Firefox](#loading-the-extension-in-firefox).

---

### Dependency Checklist

Before testing the browser extension on Windows after a WSL build, verify each item:

- [ ] `pwledger-host.exe` is a PE32+ executable (`file` output or Task Manager → Details tab shows the correct architecture)
- [ ] The binary is on a Windows-native path (not `\\wsl$\...`)
- [ ] No MinGW runtime DLLs are missing (run `pwledger-host.exe` directly in PowerShell to check for DLL load errors)
- [ ] `extension/pwledger.json` contains a Windows absolute path with double backslashes (or forward slashes)
- [ ] The manifest is in `%APPDATA%\Mozilla\NativeMessagingHosts\pwledger.json`
- [ ] The registry key `HKCU\SOFTWARE\Mozilla\NativeMessagingHosts\pwledger` points to the manifest file
- [ ] Firefox has been restarted after the registry change
- [ ] The extension has been reloaded in `about:debugging` after Firefox restart

---

### Common Mistakes

**Using the WSL-built Linux binary with Windows Firefox**

The Linux ELF binary will not execute on Windows. Firefox will report "host not found" or silently fail to spawn the process. Always use `file pwledger-host.exe` to confirm the binary is a Windows PE executable before registering it.

**Pointing the manifest path at the WSL filesystem (`\\wsl$\...`)**

Firefox resolves the native host path using standard Win32 `CreateProcess`. Paths under `\\wsl$\` may be inaccessible to `CreateProcess` depending on the Windows build version and WSL configuration. Always copy the binary to a plain Windows path under `C:\` before registering.

**Mixing libsodium ABIs**

The MinGW-w64 cross-compiled binary must link against the MinGW-compatible libsodium (from the MinGW tarball). Linking against the MSVC `.lib` from the MSVC prebuilt zip will fail at link time due to ABI incompatibility. Similarly, the MSVC-compiled binary must use the MSVC libsodium. Do not mix them.

**Forgetting to rebuild after source changes**

If you modify any `.cpp` or `.h` files inside WSL and want the Windows binary to reflect those changes, you must re-run the cross-compile build (`cmake --build build-windows --target pwledger-host`) and copy the updated `.exe` to Windows again. The Windows binary is not automatically updated when you build the Linux targets.

---

- **No persistence**: the vault is in-memory only and is lost when the CLI exits or the browser closes. Encrypted disk persistence is planned.
- **No automatic clipboard clear**: the `clip-clear` command and browser extension button must be used manually. An auto-clear timer is planned.
- **Master password in transit (browser extension)**: the unlock command sends the master password as a plaintext JSON string over the native messaging pipe. The exposure window is minimized by zeroing the intermediary buffer immediately after use, but the JSON parser may retain internal copies.
- **Temporary extension only**: the Firefox extension is unsigned and must be reloaded after each browser restart.
- **Single-user, single-process**: the vault has no concurrent access protection. Do not run the CLI and the browser extension simultaneously against the same vault.

---

## Roadmap

- [ ] Encrypted persistence (Argon2id KDF → XChaCha20-Poly1305 file)
- [ ] Automatic clipboard clear after configurable timeout
- [ ] Chrome / Chromium support for the browser extension
- [ ] Extension signing for persistent Firefox installation
- [ ] Vault export / import
- [ ] Password strength scoring (zxcvbn integration)
- [ ] Password reuse detection across entries

---

## License

MIT — see [LICENSE](LICENSE).
