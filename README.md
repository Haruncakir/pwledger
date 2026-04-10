# 🔐 pwledger

A professional-grade, offline-first password vault built in modern C++20. Secrets are stored exclusively in [libsodium](https://doc.libsodium.org/)-hardened memory with hardware-enforced access protection (`mprotect` / `mlock`). No cloud, no telemetry, no network traffic.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
  - [Linux / WSL](#-linux--wsl)
  - [macOS](#-macos)
  - [Windows (Native)](#-windows-native)
  - [WSL → Windows (Cross-Compile)](#-wsl--windows-cross-compile)
- [CLI Usage](#cli-usage)
- [Browser Extension](#browser-extension)
  - [How It Works](#how-it-works)
  - [Auto-Fill](#auto-fill)
  - [Setting Up the Native Host](#setting-up-the-native-host)
    - [Firefox — Linux / WSL](#firefox--linux--wsl)
    - [Firefox — macOS](#firefox--macos)
    - [Firefox — Windows](#firefox--windows)
    - [Chrome / Chromium — Linux](#chrome--chromium--linux)
    - [Chrome / Chromium — macOS](#chrome--chromium--macos)
    - [Chrome / Chromium — Windows](#chrome--chromium--windows)
  - [Loading the Extension](#loading-the-extension)
  - [Verifying the Connection](#verifying-the-connection)
  - [Troubleshooting](#troubleshooting)
  - [Signing & Distribution](#signing--distribution)
- [Build Options](#build-options)
- [Security Model](#security-model)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| | |
|---|---|
| 🛡️ **Hardened memory** | All secrets live in `sodium_malloc` pages with guard regions, canaries, and `NOACCESS` protection between uses |
| 🔒 **RAII access guards** | Scoped `with_read_access` / `with_write_access` unlocks memory temporarily and re-locks on scope exit |
| 🧱 **Process hardening** | Core dump suppression, anti-debug hints, PIE, RELRO, stack protectors |
| ⏱️ **Constant-time ops** | Password confirmation uses `sodium_memcmp` — no timing side-channels |
| 🖥️ **Cross-platform** | Linux, macOS, and Windows (MSVC / MinGW) |
| ⌨️ **CLI interface** | Interactive CRUD with echo-suppressed input and clipboard integration |
| 🌐 **Browser extension** | Firefox & Chrome/Chromium native messaging with **auto-fill** — credentials are injected directly into login forms |

---

## Quick Start

Pick the guide that matches your setup. Each one takes you from a fresh clone to a working build.

### 🐧 Linux / WSL

> **Prerequisites:** GCC 11+ (or Clang 14+), CMake 3.15+, libsodium 1.0.18+

**Option A — Automated setup (recommended)**

```bash
git clone https://github.com/user/passwordledger.git
cd passwordledger

# Installs dependencies, configures, builds, and runs tests
./setup/setup.sh
```

The setup script auto-detects your distro (Ubuntu/Debian, Arch, Fedora, openSUSE) and installs everything for you.

**Option B — Manual setup**

1. **Install dependencies**

   ```bash
   # Ubuntu / Debian
   sudo apt update
   sudo apt install build-essential cmake ninja-build pkg-config libsodium-dev

   # Arch Linux
   sudo pacman -S base-devel cmake ninja pkg-config libsodium

   # Fedora / RHEL
   sudo dnf install gcc gcc-c++ cmake ninja-build pkgconfig libsodium-devel
   ```

2. **Build**

   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
   cmake --build build -j$(nproc)
   ```

3. **Run tests**

   ```bash
   cd build && ctest --output-on-failure
   ```

4. **Launch the CLI**

   ```bash
   ./build/apps/pwledger-cli
   ```

---

### 🍎 macOS

> **Prerequisites:** Xcode Command Line Tools (or Clang 14+), CMake 3.15+, Homebrew

**Option A — Automated setup**

```bash
git clone https://github.com/user/passwordledger.git
cd passwordledger
./setup/setup.sh
```

**Option B — Manual setup**

1. **Install dependencies**

   ```bash
   xcode-select --install   # if not already installed
   brew install cmake ninja pkg-config libsodium
   ```

2. **Build**

   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
   cmake --build build -j$(sysctl -n hw.logicalcpu)
   ```

3. **Run tests**

   ```bash
   cd build && ctest --output-on-failure
   ```

4. **Launch the CLI**

   ```bash
   ./build/apps/pwledger-cli
   ```

---

### 🪟 Windows (Native)

> **Prerequisites:** Visual Studio 2022 with **Desktop development with C++**, CMake, Git

**Option A — Automated setup (recommended)**

Open a **Developer PowerShell for VS 2022** and run:

```powershell
git clone https://github.com/user/passwordledger.git
cd passwordledger

# Installs libsodium via vcpkg, configures, builds, runs tests
.\setup\setup.ps1
```

**Option B — Manual setup**

1. **Install libsodium** (choose one method)

   ```powershell
   # Method 1: vcpkg (recommended)
   git clone https://github.com/microsoft/vcpkg.git C:\tools\vcpkg
   C:\tools\vcpkg\bootstrap-vcpkg.bat
   C:\tools\vcpkg\vcpkg.exe install libsodium:x64-windows-static

   # Method 2: Prebuilt download
   # Download from https://download.libsodium.org/libsodium/releases/
   # Extract and note the path for CMAKE_PREFIX_PATH below
   ```

2. **Build** (from Developer PowerShell for VS 2022)

   ```powershell
   # With vcpkg:
   cmake -B build `
       -DCMAKE_BUILD_TYPE=RelWithDebInfo `
       -DCMAKE_TOOLCHAIN_FILE="C:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake" `
       -DVCPKG_TARGET_TRIPLET=x64-windows-static

   # With manual libsodium:
   # cmake -B build `
   #     -DCMAKE_BUILD_TYPE=RelWithDebInfo `
   #     -DCMAKE_PREFIX_PATH="C:\path\to\libsodium"

   cmake --build build --parallel
   ```

3. **Run tests**

   ```powershell
   cd build
   ctest --output-on-failure
   ```

4. **Launch the CLI**

   ```powershell
   .\build\apps\pwledger-cli.exe
   ```

---

### 🔀 WSL → Windows (Cross-Compile)

If you develop inside WSL but need the browser extension to work with **Windows Firefox**, you need a Windows `.exe`. A Linux ELF binary cannot be launched by Windows Firefox.

**Option A — Automated**

```bash
# From inside WSL
./setup/setup.sh --cross-windows
```

This downloads the MinGW libsodium, cross-compiles `pwledger-host.exe`, and (if possible) copies it to your Windows user directory automatically.

**Option B — Manual**

1. **Install MinGW-w64**

   ```bash
   sudo apt install mingw-w64 mingw-w64-tools
   ```

2. **Download MinGW libsodium**

   ```bash
   wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-mingw.tar.gz
   tar -xf libsodium-1.0.18-mingw.tar.gz
   ```

   > ⚠️ Do **not** use the `libsodium-dev` apt package for cross-compilation. It contains Linux `.so` files. You need the MinGW `.a` files from the tarball above.

3. **Cross-compile**

   ```bash
   cmake -B build-windows \
       -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake \
       -DCMAKE_BUILD_TYPE=RelWithDebInfo \
       -DCMAKE_PREFIX_PATH=$(pwd)/libsodium-win64 \
       -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++" \
       -DPWLEDGER_BUILD_TESTS=OFF

   cmake --build build-windows --target pwledger-host -j$(nproc)
   ```

4. **Copy to Windows**

   ```bash
   # Create the destination directory
   mkdir -p /mnt/c/Users/<YourUsername>/pwledger

   # Copy the .exe
   cp build-windows/apps/native_host/pwledger-host.exe \
      /mnt/c/Users/<YourUsername>/pwledger/
   ```

5. **Verify** the binary is a valid Windows PE executable:

   ```bash
   file build-windows/apps/native_host/pwledger-host.exe
   # Expected: PE32+ executable (console) x86-64, for MS Windows
   ```

---

## Build Outputs

After a successful build, you'll have:

| Binary | Path | Description |
|---|---|---|
| `pwledger-cli` | `build/apps/pwledger-cli` | Interactive CLI password manager |
| `pwledger-host` | `build/apps/native_host/pwledger-host` | Firefox native messaging host |
| Test suite | `build/tests/` | GoogleTest binaries |

> On Windows, all binaries have a `.exe` extension.

---

## CLI Usage

```bash
./build/apps/pwledger-cli
```

The CLI presents an interactive prompt. Type `help` to see available commands:

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
| `quit` | Exit (all secrets zeroed and freed) |

> 💡 When prompted for a secret, terminal echo is suppressed automatically so nothing is visible on screen.

---

## Browser Extension

The browser extension integrates pwledger with Firefox. It lets you search your vault, copy passwords, and **automatically fill login forms** on websites.

### How It Works

```
┌─────────────────────┐          ┌──────────────────────┐
│  Firefox Extension   │  stdin/  │   pwledger-host      │
│                      │◄────────►│   (native process)   │
│  • Popup UI          │  stdout  │                      │
│  • Content Script    │          │  • Reads vault       │
│    (auto-fill)       │          │  • Returns creds     │
└─────────────────────┘          └──────────────────────┘
```

The extension sends JSON commands (`unlock`, `search`, `copy`, `lock`, `get_credentials`) over a pipe to the native host. The host holds the in-memory vault for the duration of the browser session and auto-locks when the pipe closes.

### Auto-Fill

When you navigate to a login page:

1. The **content script** detects password fields on the page
2. It extracts the page's hostname (e.g., `github.com`) and queries the vault
3. **Single match** → credentials are filled immediately into the username and password fields
4. **Multiple matches** → a small picker overlay appears near the password field for you to choose
5. You can also click **Fill** from the popup on any entry to fill the active page

The auto-fill works with most login forms, including those built with React, Angular, and Vue (it uses native input setters and dispatches proper DOM events).

### Setting Up the Native Host

There are two parts: (1) register the native host manifest so your browser can find `pwledger-host`, and (2) load the extension.

> **Key difference:** Firefox uses `allowed_extensions` in the manifest with extension IDs. Chrome uses `allowed_origins` with the format `chrome-extension://EXTENSION_ID/`. Use `extension/pwledger.json` for Firefox and `extension/pwledger-chrome.json` for Chrome.

#### Firefox — Linux / WSL

```bash
# 1. Create the native messaging hosts directory
mkdir -p ~/.mozilla/native-messaging-hosts

# 2. Edit extension/pwledger.json — set "path" to the ABSOLUTE path of pwledger-host
#    Example: "/home/you/passwordledger/build/apps/native_host/pwledger-host"

# 3. Copy the manifest
cp extension/pwledger.json ~/.mozilla/native-messaging-hosts/

# 4. Verify
cat ~/.mozilla/native-messaging-hosts/pwledger.json
```

Or use the setup script:

```bash
./setup/setup.sh --register-extension
```

> ⚠️ **WSL users:** If your Firefox runs on **Windows** (not inside WSL), the Linux binary won't work. You need a Windows `.exe` — see [WSL → Windows (Cross-Compile)](#-wsl--windows-cross-compile) and the [Firefox — Windows](#firefox--windows) registration below.

#### Firefox — macOS

```bash
# 1. Create the directory
mkdir -p ~/Library/Application\ Support/Mozilla/NativeMessagingHosts

# 2. Edit extension/pwledger.json — set "path" to the absolute path of pwledger-host

# 3. Copy the manifest
cp extension/pwledger.json \
   ~/Library/Application\ Support/Mozilla/NativeMessagingHosts/

# 4. Make the binary executable and clear Gatekeeper quarantine
chmod +x /path/to/pwledger-host
xattr -d com.apple.quarantine /path/to/pwledger-host
```

#### Firefox — Windows

Firefox reads the native host manifest path from the Windows Registry.

1. **Edit `extension\pwledger.json`** — set `"path"` to the absolute Windows path of `pwledger-host.exe`:

   ```json
   {
     "name": "pwledger",
     "description": "Password Ledger Native Host",
     "path": "C:\\Users\\you\\pwledger\\pwledger-host.exe",
     "type": "stdio",
     "allowed_extensions": ["pwledger@harun.dev"]
   }
   ```

   > Use double backslashes (`\\`) or forward slashes (`/`) for paths in JSON.

2. **Copy the manifest** to Firefox's expected location:

   ```powershell
   New-Item -ItemType Directory `
       -Path "$env:APPDATA\Mozilla\NativeMessagingHosts" -Force

   Copy-Item extension\pwledger.json `
       "$env:APPDATA\Mozilla\NativeMessagingHosts\pwledger.json"
   ```

3. **Set the registry key** (no admin required):

   ```powershell
   New-Item -Path "HKCU:\SOFTWARE\Mozilla\NativeMessagingHosts\pwledger" -Force
   Set-ItemProperty `
       -Path "HKCU:\SOFTWARE\Mozilla\NativeMessagingHosts\pwledger" `
       -Name "(Default)" `
       -Value "$env:APPDATA\Mozilla\NativeMessagingHosts\pwledger.json"
   ```

Or use the setup script from Developer PowerShell:

```powershell
.\setup\setup.ps1 -RegisterExtension
```

#### Chrome / Chromium — Linux

```bash
# 1. Create the native messaging hosts directory
#    For Chrome:
mkdir -p ~/.config/google-chrome/NativeMessagingHosts
#    For Chromium:
# mkdir -p ~/.config/chromium/NativeMessagingHosts

# 2. Edit extension/pwledger-chrome.json:
#    - Set "path" to the ABSOLUTE path of pwledger-host
#    - Set your extension's ID in "allowed_origins"
#      (find it at chrome://extensions after loading the extension)

# 3. Copy the manifest
cp extension/pwledger-chrome.json \
   ~/.config/google-chrome/NativeMessagingHosts/pwledger.json

# 4. Verify
cat ~/.config/google-chrome/NativeMessagingHosts/pwledger.json
```

> 💡 **Finding your extension ID:** Load the extension first (see [Loading the Extension](#loading-the-extension)), then copy the ID from `chrome://extensions`. Update `allowed_origins` to `["chrome-extension://YOUR_ID_HERE/"]` — the trailing slash is required.

#### Chrome / Chromium — macOS

```bash
# 1. Create the directory
#    For Chrome:
mkdir -p ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts
#    For Chromium:
# mkdir -p ~/Library/Application\ Support/Chromium/NativeMessagingHosts

# 2. Edit extension/pwledger-chrome.json (set path and allowed_origins)

# 3. Copy the manifest
cp extension/pwledger-chrome.json \
   ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/pwledger.json

# 4. Clear Gatekeeper quarantine
chmod +x /path/to/pwledger-host
xattr -d com.apple.quarantine /path/to/pwledger-host
```

#### Chrome / Chromium — Windows

Chrome reads the native host manifest path from the Windows Registry, similar to Firefox but under a different key.

1. **Edit `extension\pwledger-chrome.json`** — set `"path"` and `"allowed_origins"`:

   ```json
   {
     "name": "pwledger",
     "description": "Password Ledger Native Host",
     "path": "C:\\Users\\you\\pwledger\\pwledger-host.exe",
     "type": "stdio",
     "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID_HERE/"]
   }
   ```

2. **Copy the manifest** and **set the registry key**:

   ```powershell
   # Create the directory
   New-Item -ItemType Directory `
       -Path "$env:APPDATA\Google\Chrome\NativeMessagingHosts" -Force

   # Copy the manifest
   Copy-Item extension\pwledger-chrome.json `
       "$env:APPDATA\Google\Chrome\NativeMessagingHosts\pwledger.json"

   # Registry key (Chrome)
   New-Item -Path "HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\pwledger" -Force
   Set-ItemProperty `
       -Path "HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\pwledger" `
       -Name "(Default)" `
       -Value "$env:APPDATA\Google\Chrome\NativeMessagingHosts\pwledger.json"
   ```

### Loading the Extension

#### Firefox

1. Open Firefox → navigate to `about:debugging#/runtime/this-firefox`
2. Click **"Load Temporary Add-on..."**
3. Navigate to the `extension/` directory and select `manifest.json`
4. The 🔐 pwledger icon appears in the toolbar

> ℹ️ Temporary add-ons are removed when Firefox closes. For persistent installation, the extension must be signed by Mozilla, or set `xpinstall.signatures.required = false` in `about:config` (development only).

#### Chrome / Chromium

1. Open Chrome → navigate to `chrome://extensions`
2. Enable **"Developer mode"** (toggle in the top-right corner)
3. Click **"Load unpacked"**
4. Select the `extension/` directory in this repository
5. The 🔐 pwledger icon appears in the toolbar (you may need to pin it)
6. **Copy the extension ID** from the card and update `allowed_origins` in `pwledger-chrome.json`

> ℹ️ After updating `allowed_origins`, restart Chrome for the native host to be recognized.

### Verifying the Connection

1. Click the pwledger toolbar icon
2. You should see a password prompt (or the vault screen if already unlocked)
3. To debug: open `about:debugging` → inspect the extension → check the console for `NativeMessaging` errors

### Troubleshooting

<details>
<summary><strong>"Native host not found" / "Host not found"</strong></summary>

- The manifest file must exist at the exact path your browser expects (see platform instructions above)
- The `"path"` inside the manifest must be an **absolute path** to `pwledger-host` (or `.exe`)
- On Linux/macOS: verify the binary is executable (`chmod +x`)
- The manifest filename on disk must match the `"name"` field exactly: `pwledger.json` → `"pwledger"`
- **Chrome:** verify `allowed_origins` contains your extension ID with a trailing slash
- **Firefox:** verify `allowed_extensions` contains `pwledger@harun.dev`
- **Restart your browser** after any manifest or registry changes
</details>

<details>
<summary><strong>Popup shows no response</strong></summary>

- Check DevTools console on the extension's background page for errors
- Run `pwledger-host` directly in a terminal — it should block on stdin (that's normal, Ctrl-C to exit)
- macOS: clear the quarantine attribute (`xattr -d com.apple.quarantine ...`)
</details>

<details>
<summary><strong>Windows: "Access is denied" or "File not found"</strong></summary>

- Registry key must be under `HKEY_CURRENT_USER` (not `HKEY_LOCAL_MACHINE`)
- Double-check backslashes are doubled in JSON paths
- Don't place the binary on a network drive or a path requiring elevation
</details>

<details>
<summary><strong>Auto-fill not working on a page</strong></summary>

- The vault must be **unlocked** first (click the extension icon and unlock)
- The page's hostname must match your entry's `primary_key` (e.g., entry `github.com` matches `https://github.com/login`)
- The page must have a `<input type="password">` field
- Some pages with complex shadow DOM structures may not be detected — use the popup's **Fill** button as a fallback
</details>

### Signing & Distribution

By default the extension must be reloaded after every browser restart. To install it permanently, it needs to be **signed** (Firefox) or **published** (Chrome Web Store).

#### Prerequisites

```bash
# Install web-ext globally (or use npx)
npm install -g web-ext
```

#### Packaging

The included script creates clean `.zip` files for both stores:

```bash
chmod +x package-extension.sh
./package-extension.sh
```

This produces:

| Output | Purpose |
|---|---|
| `dist/pwledger-<version>-firefox.zip` | Upload to AMO or pass to `web-ext sign` |
| `dist/pwledger-<version>-chrome.zip` | Upload to Chrome Web Store |

#### Firefox — Self-Distributed Signing (Recommended for Personal Use)

Mozilla allows you to sign extensions for **self-distribution** without publishing them publicly. The signed `.xpi` can be installed permanently.

1. **Get API credentials** from [addons.mozilla.org/developers/addon/api/key/](https://addons.mozilla.org/developers/addon/api/key/)

2. **Sign the extension:**

   ```bash
   export WEB_EXT_API_KEY="your-jwt-issuer"
   export WEB_EXT_API_SECRET="your-jwt-secret"

   ./package-extension.sh --sign-firefox --channel unlisted
   ```

3. **Install the signed .xpi:**
   - Open Firefox → `about:addons`
   - Click the gear icon → **"Install Add-on From File…"**
   - Select `dist/pwledger-<version>-firefox.xpi`
   - The extension persists across restarts ✅

#### Firefox — Public AMO Listing

1. Go to [addons.mozilla.org/developers/addon/submit/](https://addons.mozilla.org/developers/addon/submit/)
2. Upload `dist/pwledger-<version>-firefox.zip`
3. Follow the review process (may take 1–7 days)

#### Chrome Web Store

1. Pay the one-time [$5 developer registration fee](https://chrome.google.com/webstore/devconsole)
2. Go to the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
3. Click **"New item"** → upload `dist/pwledger-<version>-chrome.zip`
4. Fill in the store listing details and submit for review

#### Quick Reference: web-ext Commands

```bash
# Run extension in a temporary Firefox profile for testing
npx web-ext run --source-dir=./extension

# Lint the extension for AMO policy compliance
npx web-ext lint --source-dir=./extension

# Build a .zip without signing
npx web-ext build --source-dir=./extension --artifacts-dir=./dist --overwrite-dest
```

---

## Build Options

| CMake Option | Default | Description |
|---|---|---|
| `PWLEDGER_ENABLE_SECURITY_HARDENING` | `ON` | Stack protector, PIE, RELRO, `_FORTIFY_SOURCE=2` |
| `PWLEDGER_ENABLE_SANITIZERS` | `OFF` | AddressSanitizer + UBSan (Debug builds only) |
| `PWLEDGER_ENABLE_STATIC_ANALYSIS` | `OFF` | clang-tidy / cppcheck integration |
| `PWLEDGER_BUILD_TESTS` | `ON` | Build the GoogleTest suite |

```bash
# Example: Debug build with sanitizers
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DPWLEDGER_ENABLE_SANITIZERS=ON
cmake --build build -j$(nproc)
```

---

## Security Model

<details>
<summary><strong>Memory Protection</strong></summary>

Secrets are allocated via `sodium_malloc`, which:
- Calls `mlock` to prevent pages from being swapped to disk
- Places inaccessible guard pages before and after the allocation
- Fills the allocation with a canary pattern to detect underflows
- Sets the allocation to `NOACCESS` (hardware-enforced via `mprotect`)

The buffer is only readable or writable inside an active `with_read_access` / `with_write_access` scope. Any attempt to access the buffer outside a guard triggers a segfault.

On destruction, `sodium_free` calls `sodium_memzero` before releasing the page. No plaintext lingers in freed memory.
</details>

<details>
<summary><strong>Process Hardening</strong></summary>

At startup, before any secret is constructed:

- `prctl(PR_SET_DUMPABLE, 0)` — prevents core dumps that would contain secrets
- `setrlimit(RLIMIT_CORE, {0, 0})` — sets core file size to zero

These are best-effort: a warning is printed to stderr if either call fails.
</details>

<details>
<summary><strong>Clipboard</strong></summary>

Clipboard operations are an inherent security concession (any process under the same user can read it). pwledger minimizes exposure by:
- Writing through a scoped `with_read_access` guard (buffer re-locked immediately after)
- Providing `clip-clear` to overwrite the clipboard when done
</details>

<details>
<summary><strong>Native Messaging (Browser Extension)</strong></summary>

- The host process runs with the same OS user privileges as the browser
- Only extensions with a matching ID can communicate with the host
- The master password is transmitted in plaintext over the OS pipe (no additional encryption)
- Password strings are zeroed with `sodium_memzero` immediately after use
- Auto-fill credentials transit through the browser's internal messaging (same model as Bitwarden, 1Password)
</details>

---

## Known Limitations

- **Master password in transit** — sent as plaintext JSON over the native messaging pipe; intermediary buffers are zeroed but JSON parser may retain copies
- **Single-user, single-process** — no concurrent access protection; don't run CLI and extension against the same vault simultaneously
- **JSON parser copies** — nlohmann/json may retain internal copies of the password string during parsing; these are outside our zeroing reach

---

## Roadmap

- [x] Encrypted persistence (Argon2id KDF → XChaCha20-Poly1305)
- [x] Automatic clipboard clear after configurable timeout
- [x] Chrome / Chromium support
- [x] Extension signing for persistent installation
- [ ] Vault export / import
- [ ] Password strength scoring (zxcvbn)
- [ ] Password reuse detection
- [x] Auto-fill login forms from the browser extension

---

## License

MIT — see [LICENSE](LICENSE).
