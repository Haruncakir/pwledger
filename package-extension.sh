#!/usr/bin/env bash
# =============================================================================
# package-extension.sh — Build distributable extension packages
#
# Produces:
#   dist/pwledger-<version>-firefox.zip   — Ready for AMO upload or web-ext sign
#   dist/pwledger-<version>-chrome.zip    — Ready for Chrome Web Store upload
#   dist/pwledger-<version>-firefox.xpi   — Signed .xpi (if --sign-firefox)
#
# Prerequisites:
#   - Node.js + npm (for web-ext)
#   - web-ext: npm install -g web-ext  (or npx web-ext)
#
# Usage:
#   ./package-extension.sh [OPTIONS]
#
# Options:
#   --sign-firefox        Sign the Firefox extension via AMO API.
#                         Requires WEB_EXT_API_KEY and WEB_EXT_API_SECRET
#                         environment variables (from addons.mozilla.org).
#   --channel CHANNEL     AMO channel: "listed" (public) or "unlisted" (self-
#                         distributed). Default: unlisted.
#   -h, --help            Show this help and exit.
#
# Environment variables for signing:
#   WEB_EXT_API_KEY       AMO JWT issuer (from addons.mozilla.org/developers)
#   WEB_EXT_API_SECRET    AMO JWT secret
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="${SCRIPT_DIR}/extension"
DIST_DIR="${SCRIPT_DIR}/dist"
SIGN_FIREFOX="OFF"
CHANNEL="unlisted"

# ── Colours ──
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

# ── Argument parsing ──
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sign-firefox)   SIGN_FIREFOX="ON"; shift ;;
    --channel)        CHANNEL="$2"; shift 2 ;;
    -h|--help)
      sed -n '3,30p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) die "Unknown option: $1. Run with --help." ;;
  esac
done

# ── Read version from manifest.json ──
VERSION=$(grep -oP '"version"\s*:\s*"\K[^"]+' "${EXT_DIR}/manifest.json")
if [[ -z "${VERSION}" ]]; then
  die "Could not read version from manifest.json"
fi
info "Extension version: ${VERSION}"

# ── Ensure dist directory exists ──
mkdir -p "${DIST_DIR}"

# ── Files to include in the package ──
# Everything in extension/ except native host manifests and dev artifacts
INCLUDE_FILES=(
  manifest.json
  browser-polyfill.js
  background.js
  content.js
  content.css
  popup/popup.html
  popup/popup.css
  popup/popup.js
  icons/icon-16.svg
  icons/icon-48.svg
  icons/icon-128.svg
)

# ── Helper: create a zip from extension files ──
create_zip() {
  local output_path="$1"
  local extra_excludes=("${@:2}")

  rm -f "${output_path}"
  (
    cd "${EXT_DIR}"
    zip -r -9 "${output_path}" "${INCLUDE_FILES[@]}" \
      -x "*.DS_Store" -x "__MACOSX/*" "${extra_excludes[@]}"
  )
}

# =============================================================================
# Firefox package
# =============================================================================
section "Building Firefox package"

FIREFOX_ZIP="${DIST_DIR}/pwledger-${VERSION}-firefox.zip"
create_zip "${FIREFOX_ZIP}"
success "Firefox zip: ${FIREFOX_ZIP}"

# ── Sign with web-ext if requested ──
if [[ "${SIGN_FIREFOX}" == "ON" ]]; then
  section "Signing Firefox extension via AMO"

  if [[ -z "${WEB_EXT_API_KEY:-}" ]]; then
    die "WEB_EXT_API_KEY not set. Get yours from https://addons.mozilla.org/developers/addon/api/key/"
  fi
  if [[ -z "${WEB_EXT_API_SECRET:-}" ]]; then
    die "WEB_EXT_API_SECRET not set."
  fi

  # Check for web-ext
  WEB_EXT=""
  if command -v web-ext &>/dev/null; then
    WEB_EXT="web-ext"
  elif command -v npx &>/dev/null; then
    WEB_EXT="npx web-ext"
  else
    die "web-ext not found. Install it: npm install -g web-ext"
  fi

  info "Using: ${WEB_EXT}"
  info "Channel: ${CHANNEL}"

  ${WEB_EXT} sign \
    --source-dir="${EXT_DIR}" \
    --artifacts-dir="${DIST_DIR}" \
    --api-key="${WEB_EXT_API_KEY}" \
    --api-secret="${WEB_EXT_API_SECRET}" \
    --channel="${CHANNEL}" \
    --ignore-files="pwledger.json" "pwledger-chrome.json"

  # web-ext sign creates a .xpi file in the artifacts directory
  XPI_FILE=$(find "${DIST_DIR}" -name "*.xpi" -newer "${FIREFOX_ZIP}" | head -1)
  if [[ -n "${XPI_FILE}" ]]; then
    # Rename to a consistent name
    SIGNED_XPI="${DIST_DIR}/pwledger-${VERSION}-firefox.xpi"
    mv "${XPI_FILE}" "${SIGNED_XPI}"
    success "Signed XPI: ${SIGNED_XPI}"
    echo ""
    info "To install in Firefox:"
    info "  1. Open about:addons"
    info "  2. Click the gear icon → Install Add-on From File…"
    info "  3. Select: ${SIGNED_XPI}"
  else
    warn "No .xpi file found after signing. Check the output above for errors."
  fi
fi

# =============================================================================
# Chrome package
# =============================================================================
section "Building Chrome package"

CHROME_ZIP="${DIST_DIR}/pwledger-${VERSION}-chrome.zip"
create_zip "${CHROME_ZIP}"
success "Chrome zip: ${CHROME_ZIP}"

# =============================================================================
# Summary
# =============================================================================
section "Packaging complete"

echo ""
echo -e "${BOLD}Outputs:${RESET}"
echo "  Firefox zip: ${FIREFOX_ZIP}"
if [[ "${SIGN_FIREFOX}" == "ON" && -n "${SIGNED_XPI:-}" ]]; then
  echo "  Firefox xpi: ${SIGNED_XPI} (signed)"
fi
echo "  Chrome zip:  ${CHROME_ZIP}"
echo ""
echo -e "${BOLD}Next steps:${RESET}"
echo ""
echo "  Firefox (self-distributed):"
echo "    1. Sign:  ./package-extension.sh --sign-firefox"
echo "    2. Set:   WEB_EXT_API_KEY and WEB_EXT_API_SECRET"
echo "    3. Users install the .xpi from about:addons"
echo ""
echo "  Firefox (public via AMO):"
echo "    1. Go to: https://addons.mozilla.org/developers/addon/submit/"
echo "    2. Upload: ${FIREFOX_ZIP}"
echo ""
echo "  Chrome Web Store:"
echo "    1. Go to: https://chrome.google.com/webstore/devconsole"
echo "    2. Upload: ${CHROME_ZIP}"
echo ""
