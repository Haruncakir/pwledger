# Copyright (c) 2026 Harun
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# pwledger_core is currently header-only (Secret.h, TerminalManager.h).
# INTERFACE is used instead of STATIC because there are no compiled .cc files;
# the library exists to propagate include paths and the libsodium link
# dependency to downstream targets (pwledger-cli, pwledger-host, tests).
#
# When compiled source files are added to the core library (e.g., a persistence
# layer or crypto wrappers), change INTERFACE back to STATIC and move the
# INTERFACE keywords below to PUBLIC.
include(FetchContent)
FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(nlohmann_json)

add_library(pwledger_core STATIC
    Clipboard.cc
    Config.cc
    ProcessHardening.cc
    Secret.cc
    SecretEntry.cc
    TerminalManager.cc
    uuid.cc
    VaultCrypto.cc
    VaultIO.cc
    VaultPath.cc
    VaultSerializer.cc
)

# Tell downstream targets where the public headers are.
# The generator expression ensures both in-tree builds and installed packages
# get the correct include path automatically.
target_include_directories(pwledger_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Link libsodium and nlohmann_json to the core library. Downstream targets
# that link pwledger_core will transitively receive both dependencies.
if(TARGET Sodium::Sodium)
    target_link_libraries(pwledger_core PUBLIC Sodium::Sodium nlohmann_json::nlohmann_json)
else()
    target_link_libraries(pwledger_core PUBLIC sodium nlohmann_json::nlohmann_json)
endif()
