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

On WSL, Firefox runs on the Windows host, not inside WSL. Use the [Windows](#windows) instructions instead, and set the path to the Windows-side binary.

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

## Known Limitations

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
