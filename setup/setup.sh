#!/usr/bin/env bash
# =============================================================================
# setup.sh — pwledger build and installation setup
# Supports: Ubuntu/Debian, Arch Linux, Fedora/RHEL, macOS, WSL
#
# Usage:
#   ./setup.sh [OPTIONS]
#
# Options:
#   --build-type TYPE     CMake build type: Debug, Release, RelWithDebInfo
#                         (default: RelWithDebInfo)
#   --build-dir DIR       Build output directory (default: build)
#   --no-tests            Skip building the test suite
#   --sanitizers          Enable AddressSanitizer + UBSan (Debug only)
#   --static-analysis     Enable clang-tidy / cppcheck
#   --cross-windows       Cross-compile pwledger-host for Windows using
#                         MinGW-w64 (WSL / Linux only). Output goes to
#                         build-windows/. Requires MinGW-w64 to be installed.
#   --register-extension  Register the native host manifest with Firefox
#                         and install the extension for development use.
#   --skip-deps           Skip dependency installation (assume already done).
#   -h, --help            Show this help and exit.
#
# GoogleTest and nlohmann/json are fetched automatically by CMake
# (FetchContent). libsodium must be installed via the system package manager
# or vcpkg; this script installs it automatically where possible.
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
BUILD_TYPE="RelWithDebInfo"
BUILD_DIR="build"
BUILD_TESTS="ON"
SANITIZERS="OFF"
STATIC_ANALYSIS="OFF"
CROSS_WINDOWS="OFF"
REGISTER_EXTENSION="OFF"
SKIP_DEPS="OFF"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -----------------------------------------------------------------------------
# Colours (suppressed if not a tty)
# -----------------------------------------------------------------------------
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }
section() { echo -e "\n${BOLD}==> $*${RESET}"; }

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-type)        BUILD_TYPE="$2";       shift 2 ;;
    --build-dir)         BUILD_DIR="$2";        shift 2 ;;
    --no-tests)          BUILD_TESTS="OFF";     shift   ;;
    --sanitizers)        SANITIZERS="ON";       shift   ;;
    --static-analysis)   STATIC_ANALYSIS="ON";  shift   ;;
    --cross-windows)     CROSS_WINDOWS="ON";    shift   ;;
    --register-extension)REGISTER_EXTENSION="ON"; shift ;;
    --skip-deps)         SKIP_DEPS="ON";        shift   ;;
    -h|--help)
      sed -n '3,30p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) die "Unknown option: $1. Run with --help for usage." ;;
  esac
done

# -----------------------------------------------------------------------------
# Platform detection
# -----------------------------------------------------------------------------
section "Detecting platform"

OS="unknown"
DISTRO="unknown"
IS_WSL=0
IS_CROSS_COMPILE_TARGET=0   # set to 1 for the Windows cross-compile pass

if [[ "$OSTYPE" == "darwin"* ]]; then
  OS="macos"
elif [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "linux"* ]]; then
  OS="linux"
  if grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=1
    warn "Running inside WSL."
    warn "The Linux build will produce ELF binaries that Windows Firefox"
    warn "cannot execute. Use --cross-windows to also produce a Windows .exe"
    warn "for the native messaging host."
  fi
  if   command -v apt-get  &>/dev/null; then DISTRO="debian"
  elif command -v pacman   &>/dev/null; then DISTRO="arch"
  elif command -v dnf      &>/dev/null; then DISTRO="fedora"
  elif command -v zypper   &>/dev/null; then DISTRO="opensuse"
  else warn "Unknown Linux distribution; skipping automatic dependency install."
  fi
else
  die "Unsupported OS: $OSTYPE. Use setup.ps1 for native Windows."
fi

info "OS: ${OS}  distro: ${DISTRO}  WSL: ${IS_WSL}  cross-windows: ${CROSS_WINDOWS}"

# -----------------------------------------------------------------------------
# Dependency versions
# -----------------------------------------------------------------------------
LIBSODIUM_MIN_MAJOR=1
LIBSODIUM_MIN_MINOR=0
LIBSODIUM_MIN_PATCH=18
LIBSODIUM_VERSION_STR="${LIBSODIUM_MIN_MAJOR}.${LIBSODIUM_MIN_MINOR}.${LIBSODIUM_MIN_PATCH}"

CMAKE_MIN_MAJOR=3
CMAKE_MIN_MINOR=15
CMAKE_VERSION_STR="${CMAKE_MIN_MAJOR}.${CMAKE_MIN_MINOR}"

# -----------------------------------------------------------------------------
# Version comparison helper
# -----------------------------------------------------------------------------
version_ge() {
  # Returns 0 (true) if version $1 >= $2, both in X.Y.Z format
  local IFS=.
  local i ver1=($1) ver2=($2)
  for ((i=0; i<${#ver2[@]}; i++)); do
    if [[ -z "${ver1[i]:-}" ]];           then return 1; fi
    if (( ver1[i] > ver2[i] ));           then return 0; fi
    if (( ver1[i] < ver2[i] ));           then return 1; fi
  done
  return 0
}

# -----------------------------------------------------------------------------
# Check and install system dependencies
# -----------------------------------------------------------------------------
section "Checking dependencies"

install_deps_debian() {
  info "Installing dependencies via apt-get..."
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    libsodium-dev \
    git \
    curl \
    ca-certificates
  if [[ "${CROSS_WINDOWS}" == "ON" ]]; then
    info "Installing MinGW-w64 for Windows cross-compilation..."
    sudo apt-get install -y --no-install-recommends \
      mingw-w64 \
      mingw-w64-tools
  fi
}

install_deps_arch() {
  info "Installing dependencies via pacman..."
  sudo pacman -Sy --noconfirm --needed \
    base-devel cmake ninja pkg-config libsodium git curl ca-certificates
  if [[ "${CROSS_WINDOWS}" == "ON" ]]; then
    sudo pacman -Sy --noconfirm --needed mingw-w64-gcc
  fi
}

install_deps_fedora() {
  info "Installing dependencies via dnf..."
  sudo dnf install -y \
    gcc gcc-c++ cmake ninja-build pkgconfig libsodium-devel git curl
  if [[ "${CROSS_WINDOWS}" == "ON" ]]; then
    sudo dnf install -y mingw64-gcc mingw64-gcc-c++
  fi
}

install_deps_opensuse() {
  info "Installing dependencies via zypper..."
  sudo zypper install -y \
    gcc gcc-c++ cmake ninja pkg-config libsodium-devel git curl
  if [[ "${CROSS_WINDOWS}" == "ON" ]]; then
    sudo zypper install -y mingw64-cross-gcc mingw64-cross-gcc-c++
  fi
}

install_deps_macos() {
  if ! command -v brew &>/dev/null; then
    warn "Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL \
      https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi
  info "Installing dependencies via Homebrew..."
  brew install cmake ninja pkg-config libsodium git
}

if [[ "${SKIP_DEPS}" == "OFF" ]]; then
  case "${OS}:${DISTRO}" in
    linux:debian)   install_deps_debian  ;;
    linux:arch)     install_deps_arch    ;;
    linux:fedora)   install_deps_fedora  ;;
    linux:opensuse) install_deps_opensuse;;
    macos:*)        install_deps_macos   ;;
    linux:unknown)
      warn "Cannot install dependencies automatically on this distribution."
      warn "Please install manually: cmake (>=${CMAKE_VERSION_STR}), libsodium (>=${LIBSODIUM_VERSION_STR}), a C++20 compiler."
      ;;
  esac
else
  info "Skipping dependency installation (--skip-deps)."
fi

# -----------------------------------------------------------------------------
# Validate tool versions
# -----------------------------------------------------------------------------
section "Validating tool versions"

# CMake
if ! command -v cmake &>/dev/null; then
  die "cmake not found. Install cmake >= ${CMAKE_VERSION_STR} and re-run."
fi
CMAKE_VERSION_FOUND=$(cmake --version | head -1 | awk '{print $3}')
if ! version_ge "${CMAKE_VERSION_FOUND}" "${CMAKE_VERSION_STR}"; then
  die "cmake ${CMAKE_VERSION_FOUND} found; >= ${CMAKE_VERSION_STR} required."
fi
success "cmake ${CMAKE_VERSION_FOUND}"

# C++ compiler
CXX_CANDIDATE="${CXX:-}"
if [[ -z "${CXX_CANDIDATE}" ]]; then
  for cxx in g++ clang++ c++; do
    if command -v "${cxx}" &>/dev/null; then CXX_CANDIDATE="${cxx}"; break; fi
  done
fi
if [[ -z "${CXX_CANDIDATE}" ]]; then
  die "No C++20 compiler found. Install GCC 11+, Clang 14+, or set CXX."
fi
success "C++ compiler: ${CXX_CANDIDATE}"

# libsodium
if command -v pkg-config &>/dev/null && pkg-config --exists libsodium 2>/dev/null; then
  SODIUM_VERSION=$(pkg-config --modversion libsodium)
  if ! version_ge "${SODIUM_VERSION}" "${LIBSODIUM_VERSION_STR}"; then
    die "libsodium ${SODIUM_VERSION} found; >= ${LIBSODIUM_VERSION_STR} required."
  fi
  success "libsodium ${SODIUM_VERSION}"
else
  warn "pkg-config cannot find libsodium. CMake will attempt to locate it."
  warn "If the build fails, install libsodium-dev >= ${LIBSODIUM_VERSION_STR}."
fi

# -----------------------------------------------------------------------------
# Configure and build (Linux / macOS / WSL native target)
# -----------------------------------------------------------------------------
section "Configuring CMake (native target)"

cd "${SCRIPT_DIR}"

# Prefer Ninja if available; fall back to the default generator.
CMAKE_GENERATOR_FLAG=""
if command -v ninja &>/dev/null; then
  CMAKE_GENERATOR_FLAG="-G Ninja"
  info "Using Ninja generator"
fi

cmake -B "${BUILD_DIR}" \
  ${CMAKE_GENERATOR_FLAG} \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DPWLEDGER_BUILD_TESTS="${BUILD_TESTS}" \
  -DPWLEDGER_ENABLE_SANITIZERS="${SANITIZERS}" \
  -DPWLEDGER_ENABLE_STATIC_ANALYSIS="${STATIC_ANALYSIS}" \
  -DPWLEDGER_ENABLE_SECURITY_HARDENING="ON"

section "Building (native target)"

NPROC=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)
cmake --build "${BUILD_DIR}" --parallel "${NPROC}"
success "Native build complete: ${BUILD_DIR}/"

# -----------------------------------------------------------------------------
# Run tests
# -----------------------------------------------------------------------------
if [[ "${BUILD_TESTS}" == "ON" ]]; then
  section "Running tests"
  (cd "${BUILD_DIR}" && ctest --output-on-failure --parallel "${NPROC}")
  success "All tests passed"
fi

# -----------------------------------------------------------------------------
# Windows cross-compilation (WSL / Linux only)
# -----------------------------------------------------------------------------
if [[ "${CROSS_WINDOWS}" == "ON" ]]; then
  section "Windows cross-compilation (MinGW-w64)"

  MINGW_CXX="x86_64-w64-mingw32-g++"
  if ! command -v "${MINGW_CXX}" &>/dev/null; then
    die "MinGW-w64 not found (${MINGW_CXX}). Install mingw-w64 and re-run."
  fi
  success "MinGW-w64 compiler: ${MINGW_CXX}"

  # Locate the MinGW libsodium tarball. The setup script downloads it
  # automatically if not already present in the repository root or a
  # .deps/ cache directory.
  DEPS_DIR="${SCRIPT_DIR}/.deps"
  SODIUM_MINGW_DIR="${DEPS_DIR}/libsodium-win64"
  SODIUM_MINGW_VERSION="1.0.18"
  SODIUM_MINGW_ARCHIVE="${DEPS_DIR}/libsodium-${SODIUM_MINGW_VERSION}-mingw.tar.gz"
  SODIUM_MINGW_URL="https://download.libsodium.org/libsodium/releases/libsodium-${SODIUM_MINGW_VERSION}-mingw.tar.gz"

  mkdir -p "${DEPS_DIR}"

  if [[ ! -d "${SODIUM_MINGW_DIR}" ]]; then
    if [[ ! -f "${SODIUM_MINGW_ARCHIVE}" ]]; then
      info "Downloading libsodium MinGW prebuilt (${SODIUM_MINGW_VERSION})..."
      curl -fsSL --retry 3 --retry-delay 2 \
        -o "${SODIUM_MINGW_ARCHIVE}" "${SODIUM_MINGW_URL}" \
        || die "Failed to download libsodium MinGW archive from ${SODIUM_MINGW_URL}"
    else
      info "Using cached MinGW libsodium archive: ${SODIUM_MINGW_ARCHIVE}"
    fi

    info "Extracting MinGW libsodium..."
    tar -xf "${SODIUM_MINGW_ARCHIVE}" -C "${DEPS_DIR}"
    # The tarball extracts to libsodium-win32 and libsodium-win64 subdirs.
    if [[ ! -d "${SODIUM_MINGW_DIR}" ]]; then
      die "Expected ${SODIUM_MINGW_DIR} after extraction. Check tarball layout."
    fi
    success "MinGW libsodium extracted to ${SODIUM_MINGW_DIR}"
  else
    info "MinGW libsodium already present: ${SODIUM_MINGW_DIR}"
  fi

  # Verify the toolchain file exists; create a default one if not.
  TOOLCHAIN_FILE="${SCRIPT_DIR}/cmake/toolchains/mingw-w64-x86_64.cmake"
  if [[ ! -f "${TOOLCHAIN_FILE}" ]]; then
    warn "Toolchain file not found at ${TOOLCHAIN_FILE}. Creating default..."
    mkdir -p "$(dirname "${TOOLCHAIN_FILE}")"
    cat > "${TOOLCHAIN_FILE}" << 'EOF'
# cmake/toolchains/mingw-w64-x86_64.cmake
# MinGW-w64 cross-compilation toolchain for producing Windows PE64 executables
# from a Linux / WSL host. Used by setup.sh --cross-windows.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)

# Do not search the host sysroot for target libraries or headers.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF
    success "Toolchain file created: ${TOOLCHAIN_FILE}"
  fi

  WIN_BUILD_DIR="build-windows"
  info "Configuring CMake for Windows target..."

  cmake -B "${WIN_BUILD_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCMAKE_PREFIX_PATH="${SODIUM_MINGW_DIR}" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++" \
    -DPWLEDGER_BUILD_TESTS=OFF \
    -DPWLEDGER_ENABLE_SECURITY_HARDENING=OFF

  # Security hardening flags (-fstack-protector, PIE, RELRO) are disabled for
  # the cross-compiled target because the MinGW linker does not support all of
  # them, and the resulting binary runs under Windows whose own security model
  # (DEP, ASLR, CFG) provides equivalent or stronger mitigations.

  info "Building Windows target (pwledger-host only)..."
  cmake --build "${WIN_BUILD_DIR}" --target pwledger-host --parallel "${NPROC}"

  WIN_EXE="${WIN_BUILD_DIR}/apps/native_host/pwledger-host.exe"
  if [[ ! -f "${WIN_EXE}" ]]; then
    die "Expected output not found: ${WIN_EXE}"
  fi

  # Verify the output is a Windows PE executable, not an ELF binary.
  if command -v file &>/dev/null; then
    FILE_OUTPUT=$(file "${WIN_EXE}")
    if echo "${FILE_OUTPUT}" | grep -q "PE32+"; then
      success "Windows binary verified: ${WIN_EXE}"
      info "${FILE_OUTPUT}"
    else
      error "Output file does not appear to be a Windows PE binary:"
      error "${FILE_OUTPUT}"
      die "Cross-compilation produced an unexpected binary format."
    fi
  else
    success "Windows build complete: ${WIN_EXE}"
    warn "'file' command not available; cannot verify binary format."
  fi

  # Check for MinGW runtime DLL dependencies that would prevent the binary
  # from running on a clean Windows machine. With -static flags these should
  # not appear; warn if they do.
  if command -v x86_64-w64-mingw32-objdump &>/dev/null; then
    MINGW_DLLS=$(x86_64-w64-mingw32-objdump -p "${WIN_EXE}" \
      | grep "DLL Name" \
      | grep -iv "KERNEL32\|msvcrt\|ntdll\|USER32\|ADVAPI32\|SHELL32\|WS2_32" \
      || true)
    if [[ -n "${MINGW_DLLS}" ]]; then
      warn "The Windows binary depends on non-system DLLs:"
      warn "${MINGW_DLLS}"
      warn "These DLLs must be present on the target Windows machine."
      warn "Consider rebuilding with -static -static-libgcc -static-libstdc++"
      warn "or copy the listed DLLs alongside pwledger-host.exe."
    else
      success "No MinGW runtime DLL dependencies detected."
    fi
  fi

  # Offer to copy the binary to a Windows path if running in WSL.
  if [[ "${IS_WSL}" == "1" ]]; then
    WIN_USER=$(powershell.exe -NoProfile -Command \
      'Write-Host $env:USERNAME' 2>/dev/null | tr -d '\r' || true)
    if [[ -n "${WIN_USER}" ]]; then
      WIN_DEST="/mnt/c/Users/${WIN_USER}/pwledger"
      info "WSL detected. Copying Windows binary to ${WIN_DEST}..."
      mkdir -p "${WIN_DEST}"
      cp "${WIN_EXE}" "${WIN_DEST}/pwledger-host.exe"
      success "Copied to ${WIN_DEST}/pwledger-host.exe"
      info "Next: run setup.ps1 on the Windows side to register the manifest,"
      info "or follow the manual steps in README.md § Deploying from WSL to Windows."
    else
      warn "Could not determine Windows username. Copy the binary manually:"
      warn "  cp ${WIN_EXE} /mnt/c/Users/<YourUsername>/pwledger/pwledger-host.exe"
    fi
  fi
fi

# -----------------------------------------------------------------------------
# Register Firefox native host manifest (Linux / macOS)
# -----------------------------------------------------------------------------
if [[ "${REGISTER_EXTENSION}" == "ON" ]]; then
  section "Registering Firefox native host manifest"

  MANIFEST_SRC="${SCRIPT_DIR}/extension/pwledger.json"
  if [[ ! -f "${MANIFEST_SRC}" ]]; then
    die "Manifest not found: ${MANIFEST_SRC}"
  fi

  # Resolve the absolute path to the built native host binary.
  if [[ "${OS}" == "macos" ]]; then
    HOST_BIN="${SCRIPT_DIR}/${BUILD_DIR}/apps/native_host/pwledger-host"
    MANIFEST_DEST="${HOME}/Library/Application Support/Mozilla/NativeMessagingHosts/pwledger.json"
    mkdir -p "${HOME}/Library/Application Support/Mozilla/NativeMessagingHosts"
  else
    HOST_BIN="${SCRIPT_DIR}/${BUILD_DIR}/apps/native_host/pwledger-host"
    MANIFEST_DEST="${HOME}/.mozilla/native-messaging-hosts/pwledger.json"
    mkdir -p "${HOME}/.mozilla/native-messaging-hosts"
  fi

  if [[ ! -f "${HOST_BIN}" ]]; then
    die "Native host binary not found: ${HOST_BIN}. Build must succeed first."
  fi

  chmod +x "${HOST_BIN}"

  # Write the manifest with the resolved absolute binary path. We write a
  # fresh copy rather than copying extension/pwledger.json directly so that
  # the path is always correct regardless of where the repository is cloned.
  cat > "${MANIFEST_DEST}" << EOF
{
  "name": "pwledger",
  "description": "pwledger native messaging host",
  "path": "${HOST_BIN}",
  "type": "stdio",
  "allowed_extensions": ["pwledger@example.com"]
}
EOF

  success "Manifest written to ${MANIFEST_DEST}"
  info "Binary path in manifest: ${HOST_BIN}"

  if [[ "${OS}" == "macos" ]]; then
    # Clear the quarantine flag that Gatekeeper sets on binaries not from the
    # App Store or a notarized source. Without this, the binary silently fails
    # to launch when Firefox attempts to spawn it.
    xattr -d com.apple.quarantine "${HOST_BIN}" 2>/dev/null || true
    success "Cleared Gatekeeper quarantine flag on binary"
  fi

  info "Load the extension in Firefox:"
  info "  1. Navigate to about:debugging#/runtime/this-firefox"
  info "  2. Click 'Load Temporary Add-on...'"
  info "  3. Select: ${SCRIPT_DIR}/extension/manifest.json"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
section "Setup complete"

echo ""
echo -e "${BOLD}Build outputs:${RESET}"
echo "  CLI:         ${SCRIPT_DIR}/${BUILD_DIR}/apps/pwledger-cli"
echo "  Native host: ${SCRIPT_DIR}/${BUILD_DIR}/apps/native_host/pwledger-host"
if [[ "${CROSS_WINDOWS}" == "ON" ]]; then
  echo "  Windows .exe: ${SCRIPT_DIR}/build-windows/apps/native_host/pwledger-host.exe"
fi
echo ""
echo -e "${BOLD}Next steps:${RESET}"
if [[ "${REGISTER_EXTENSION}" == "OFF" ]]; then
  echo "  Register the Firefox native host manifest:"
  echo "    ./setup.sh --register-extension"
fi
if [[ "${IS_WSL}" == "1" && "${CROSS_WINDOWS}" == "OFF" ]]; then
  echo "  To build the Windows native host for Firefox:"
  echo "    ./setup.sh --cross-windows"
fi
echo "  See README.md for complete usage instructions."
echo ""
