#Requires -Version 5.1
<#
.SYNOPSIS
    pwledger build and installation setup for Windows.

.DESCRIPTION
    Installs dependencies (libsodium via vcpkg or manual download),
    configures and builds the project with CMake + MSVC or Clang,
    runs the test suite, registers the Firefox native host manifest,
    and optionally loads the browser extension for development.

    GoogleTest and nlohmann/json are fetched automatically by CMake
    (FetchContent) and do not require manual installation.

.PARAMETER BuildType
    CMake build type: Debug, Release, RelWithDebInfo. Default: RelWithDebInfo.

.PARAMETER BuildDir
    CMake build output directory. Default: build.

.PARAMETER NoTests
    Skip building and running the test suite.

.PARAMETER UseVcpkg
    Install and use vcpkg for libsodium. Clones vcpkg into .deps\vcpkg if not
    already present. This is the recommended approach and the default.

.PARAMETER VcpkgRoot
    Path to an existing vcpkg installation. Use this if vcpkg is already on
    your machine and you do not want the script to clone a second copy.

.PARAMETER LibsodiumManual
    Download the prebuilt MSVC libsodium binaries from libsodium.org instead
    of using vcpkg. Use this if you cannot run vcpkg.

.PARAMETER RegisterExtension
    Register the native host manifest with Firefox (writes the registry key)
    and print instructions for loading the extension.

.PARAMETER SkipDeps
    Skip all dependency installation. Assumes dependencies are already present
    and findable by CMake.

.EXAMPLE
    .\setup.ps1
    Full setup with vcpkg, RelWithDebInfo build, tests, no extension registration.

.EXAMPLE
    .\setup.ps1 -BuildType Debug -NoTests -RegisterExtension
    Debug build, skip tests, register Firefox manifest.

.EXAMPLE
    .\setup.ps1 -VcpkgRoot C:\tools\vcpkg -RegisterExtension
    Use an existing vcpkg installation.

.EXAMPLE
    .\setup.ps1 -LibsodiumManual
    Download prebuilt libsodium instead of using vcpkg.
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug','Release','RelWithDebInfo')]
    [string]$BuildType          = 'RelWithDebInfo',

    [string]$BuildDir           = 'build',

    [switch]$NoTests,

    [switch]$UseVcpkg,           # default if neither vcpkg flag is set

    [string]$VcpkgRoot          = '',

    [switch]$LibsodiumManual,

    [switch]$RegisterExtension,

    [switch]$SkipDeps
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
function Write-Step   { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok     { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Info   { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Gray }
function Write-Warn   { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err    { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Fail         { param($msg) Write-Err $msg; exit 1 }

function Test-CommandExists {
    param([string]$cmd)
    return [bool](Get-Command $cmd -ErrorAction SilentlyContinue)
}

function Get-VersionFromString {
    param([string]$str)
    if ($str -match '(\d+\.\d+(\.\d+)?)') { return $matches[1] }
    return '0.0.0'
}

function Compare-Versions {
    # Returns $true if $installed >= $required
    param([string]$installed, [string]$required)
    $a = [version]($installed -replace '-.*','')
    $b = [version]($required  -replace '-.*','')
    return $a -ge $b
}

# Script root — the directory containing this script (i.e., the repo root).
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DepsDir   = Join-Path $ScriptDir '.deps'

# -----------------------------------------------------------------------------
# Dependency version requirements
# -----------------------------------------------------------------------------
$CMakeMinVersion      = '3.15'
$LibsodiumMinVersion  = '1.0.18'
$LibsodiumMsvcVersion = '1.0.18'
$LibsodiumMsvcUrl     = "https://download.libsodium.org/libsodium/releases/libsodium-${LibsodiumMsvcVersion}-msvc.zip"

# -----------------------------------------------------------------------------
# Step 1 — Validate build tools
# -----------------------------------------------------------------------------
Write-Step "Checking build tools"

# CMake
if (-not (Test-CommandExists 'cmake')) {
    Fail "cmake not found. Install CMake >= $CMakeMinVersion from https://cmake.org/download/ and add it to PATH."
}
$cmakeVersion = Get-VersionFromString (cmake --version | Select-Object -First 1)
if (-not (Compare-Versions $cmakeVersion $CMakeMinVersion)) {
    Fail "cmake $cmakeVersion found; >= $CMakeMinVersion required."
}
Write-Ok "cmake $cmakeVersion"

# Compiler: prefer MSVC (cl.exe) detected via VS environment, fall back to clang-cl.
$CompilerFound = $false
if (Test-CommandExists 'cl') {
    $clOutput   = (cl.exe 2>&1 | Select-Object -First 1)
    Write-Ok "MSVC compiler: $clOutput"
    $CompilerFound = $true
} elseif (Test-CommandExists 'clang++') {
    $clangVersion = Get-VersionFromString (clang++ --version | Select-Object -First 1)
    Write-Ok "Clang++ $clangVersion"
    $CompilerFound = $true
}

if (-not $CompilerFound) {
    Write-Warn "No C++20 compiler found in PATH."
    Write-Warn "Install Visual Studio 2022 with 'Desktop development with C++'"
    Write-Warn "and run this script from a 'Developer PowerShell for VS 2022',"
    Write-Warn "or install LLVM from https://releases.llvm.org/"
    Fail "C++20 compiler required."
}

# Git (needed for vcpkg and FetchContent fallback)
if (-not (Test-CommandExists 'git')) {
    Fail "git not found. Install Git from https://git-scm.com/ and add it to PATH."
}
Write-Ok "git $(Get-VersionFromString (git --version))"

# -----------------------------------------------------------------------------
# Step 2 — Install / locate libsodium
# -----------------------------------------------------------------------------
Write-Step "Setting up libsodium"

$CmakePrefixPath = ''

if ($SkipDeps) {
    Write-Info "Skipping dependency installation (--SkipDeps)."
} elseif ($LibsodiumManual) {
    # -------------------------------------------------------------------------
    # Manual: download prebuilt MSVC binaries from libsodium.org
    # -------------------------------------------------------------------------
    $SodiumZip  = Join-Path $DepsDir "libsodium-${LibsodiumMsvcVersion}-msvc.zip"
    $SodiumDir  = Join-Path $DepsDir "libsodium-msvc"

    New-Item -ItemType Directory -Path $DepsDir -Force | Out-Null

    if (-not (Test-Path $SodiumDir)) {
        if (-not (Test-Path $SodiumZip)) {
            Write-Info "Downloading libsodium MSVC prebuilt ($LibsodiumMsvcVersion)..."
            try {
                Invoke-WebRequest -Uri $LibsodiumMsvcUrl `
                    -OutFile $SodiumZip `
                    -UseBasicParsing `
                    -ErrorAction Stop
            } catch {
                Fail "Failed to download libsodium: $_"
            }
        } else {
            Write-Info "Using cached archive: $SodiumZip"
        }

        Write-Info "Extracting libsodium..."
        Expand-Archive -Path $SodiumZip -DestinationPath $SodiumDir -Force
        Write-Ok "libsodium extracted to $SodiumDir"
    } else {
        Write-Info "libsodium already extracted: $SodiumDir"
    }

    # The MSVC zip lays out as:
    #   libsodium-<ver>-msvc\
    #     include\
    #     x64\Release\v143\static\libsodium.lib
    # CMake's FindSodium module needs CMAKE_PREFIX_PATH to point at the root.
    $CmakePrefixPath = Join-Path $SodiumDir "libsodium-${LibsodiumMsvcVersion}-msvc"
    if (-not (Test-Path $CmakePrefixPath)) {
        # Some releases name the inner directory differently; find the first child.
        $inner = Get-ChildItem -Path $SodiumDir -Directory | Select-Object -First 1
        if ($inner) { $CmakePrefixPath = $inner.FullName }
    }
    Write-Ok "CMAKE_PREFIX_PATH set to: $CmakePrefixPath"

} else {
    # -------------------------------------------------------------------------
    # Default: vcpkg
    # -------------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($VcpkgRoot)) {
        $VcpkgRoot = Join-Path $DepsDir 'vcpkg'
    }

    if (-not (Test-Path (Join-Path $VcpkgRoot 'vcpkg.exe'))) {
        Write-Info "vcpkg not found at $VcpkgRoot. Cloning..."
        New-Item -ItemType Directory -Path (Split-Path $VcpkgRoot) -Force | Out-Null
        git clone https://github.com/microsoft/vcpkg.git $VcpkgRoot
        & (Join-Path $VcpkgRoot 'bootstrap-vcpkg.bat') -disableMetrics
        Write-Ok "vcpkg bootstrapped at $VcpkgRoot"
    } else {
        Write-Info "vcpkg found at $VcpkgRoot"
    }

    Write-Info "Installing libsodium via vcpkg (x64-windows-static)..."
    # x64-windows-static links the CRT and libsodium statically, producing a
    # self-contained .exe with no runtime DLL dependencies beyond the OS itself.
    & (Join-Path $VcpkgRoot 'vcpkg.exe') install 'libsodium:x64-windows-static'

    $CmakePrefixPath = ''   # vcpkg toolchain handles this automatically below
    Write-Ok "libsodium installed via vcpkg"
}

# -----------------------------------------------------------------------------
# Step 3 — Configure CMake
# -----------------------------------------------------------------------------
Write-Step "Configuring CMake"

Set-Location $ScriptDir

$BuildTests = if ($NoTests) { 'OFF' } else { 'ON' }

# Construct the cmake invocation as an argument list so paths with spaces
# are handled correctly without manual quoting gymnastics.
$CmakeArgs = @(
    '-B', $BuildDir,
    "-DCMAKE_BUILD_TYPE=$BuildType",
    "-DPWLEDGER_BUILD_TESTS=$BuildTests",
    '-DPWLEDGER_ENABLE_SECURITY_HARDENING=ON'
)

# Attach vcpkg toolchain if vcpkg was used.
if (-not $LibsodiumManual -and -not $SkipDeps) {
    $ToolchainFile = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
    if (Test-Path $ToolchainFile) {
        $CmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$ToolchainFile"
        $CmakeArgs += '-DVCPKG_TARGET_TRIPLET=x64-windows-static'
    }
}

# Attach manual libsodium prefix path if used.
if ($CmakePrefixPath -ne '') {
    $CmakeArgs += "-DCMAKE_PREFIX_PATH=$CmakePrefixPath"
}

Write-Info "cmake $($CmakeArgs -join ' ')"
& cmake @CmakeArgs
if ($LASTEXITCODE -ne 0) { Fail "CMake configuration failed." }
Write-Ok "CMake configuration complete"

# -----------------------------------------------------------------------------
# Step 4 — Build
# -----------------------------------------------------------------------------
Write-Step "Building"

$CpuCount = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
& cmake --build $BuildDir --parallel $CpuCount
if ($LASTEXITCODE -ne 0) { Fail "Build failed." }
Write-Ok "Build complete: $BuildDir\"

# Print output paths.
$CliExe  = Join-Path $BuildDir 'apps\pwledger-cli.exe'
$HostExe = Join-Path $BuildDir 'apps\native_host\pwledger-host.exe'
if (Test-Path $CliExe)  { Write-Info "CLI:         $((Resolve-Path $CliExe).Path)" }
if (Test-Path $HostExe) { Write-Info "Native host: $((Resolve-Path $HostExe).Path)" }

# -----------------------------------------------------------------------------
# Step 5 — Tests
# -----------------------------------------------------------------------------
if (-not $NoTests) {
    Write-Step "Running tests"
    Push-Location $BuildDir
    & ctest --output-on-failure --parallel $CpuCount
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        Fail "One or more tests failed."
    }
    Pop-Location
    Write-Ok "All tests passed"
}

# -----------------------------------------------------------------------------
# Step 6 — Register Firefox native host manifest
# -----------------------------------------------------------------------------
if ($RegisterExtension) {
    Write-Step "Registering Firefox native host manifest"

    $HostExeAbs = $null
    $Candidate  = Join-Path $ScriptDir "$BuildDir\apps\native_host\pwledger-host.exe"

    if (Test-Path $Candidate) {
        $HostExeAbs = (Resolve-Path $Candidate).Path
    } else {
        Fail "Native host binary not found: $Candidate. Ensure the build succeeded."
    }

    # Destination for the manifest file.
    $ManifestDir  = Join-Path $env:APPDATA 'Mozilla\NativeMessagingHosts'
    $ManifestDest = Join-Path $ManifestDir 'pwledger.json'

    New-Item -ItemType Directory -Path $ManifestDir -Force | Out-Null

    # Write the manifest with the resolved Windows absolute path.
    # Forward slashes are used in the JSON to avoid JSON escape issues;
    # Firefox on Windows accepts both.
    $HostExeJson = $HostExeAbs -replace '\\','/'
    $ManifestContent = @"
{
  "name": "pwledger",
  "description": "pwledger native messaging host",
  "path": "$HostExeJson",
  "type": "stdio",
  "allowed_extensions": ["pwledger@example.com"]
}
"@
    Set-Content -Path $ManifestDest -Value $ManifestContent -Encoding UTF8
    Write-Ok "Manifest written to $ManifestDest"

    # Write the registry key that points Firefox to the manifest file.
    # HKEY_CURRENT_USER does not require administrator rights.
    $RegKey = 'HKCU:\SOFTWARE\Mozilla\NativeMessagingHosts\pwledger'
    if (-not (Test-Path $RegKey)) {
        New-Item -Path $RegKey -Force | Out-Null
    }
    Set-ItemProperty -Path $RegKey -Name '(Default)' -Value $ManifestDest
    Write-Ok "Registry key set: $RegKey -> $ManifestDest"

    Write-Info ""
    Write-Info "To load the extension in Firefox:"
    Write-Info "  1. Open Firefox and navigate to about:debugging#/runtime/this-firefox"
    Write-Info "  2. Click 'Load Temporary Add-on...'"
    Write-Info "  3. Select: $ScriptDir\extension\manifest.json"
    Write-Info ""
    Write-Info "To verify the native host is reachable:"
    Write-Info "  Run $HostExeAbs directly in PowerShell."
    Write-Info "  It will block on stdin — that is normal. Press Ctrl-C to exit."
}

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
Write-Step "Setup complete"

Write-Host ""
Write-Host "Build outputs:" -ForegroundColor White
$outCli  = Join-Path $ScriptDir "$BuildDir\apps\pwledger-cli.exe"
$outHost = Join-Path $ScriptDir "$BuildDir\apps\native_host\pwledger-host.exe"
if (Test-Path $outCli)  { Write-Host "  CLI:         $((Resolve-Path $outCli).Path)" }
if (Test-Path $outHost) { Write-Host "  Native host: $((Resolve-Path $outHost).Path)" }
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
if (-not $RegisterExtension) {
    Write-Host "  Register the Firefox native host manifest:"
    Write-Host "    .\setup.ps1 -RegisterExtension"
}
Write-Host "  See README.md for complete usage instructions."
Write-Host ""
