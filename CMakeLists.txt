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

cmake_minimum_required(VERSION 3.15)

set(PACKAGE_VERSION_MAJOR 0)
set(PACKAGE_VERSION_MINOR 1)
set(PACKAGE_VERSION_PATCH 0)
set(PACKAGE_VERSION "${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR}.${PACKAGE_VERSION_PATCH}")

set(CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
    ${CMAKE_MODULE_PATH})

set(PACKAGE_NAME "pwledger")
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_TARNAME "${PACKAGE_NAME}-${PACKAGE_VERSION}")

project(${PACKAGE_NAME}
    VERSION ${PACKAGE_VERSION}
    LANGUAGES CXX C ASM
    DESCRIPTION "Secure password management application")

option(PWLEDGER_ENABLE_SECURITY_HARDENING "Enable security hardening compiler flags" ON)
option(PWLEDGER_ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan for development builds" OFF)
option(PWLEDGER_ENABLE_STATIC_ANALYSIS "Enable static analysis tools integration" OFF)

if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)  # Disable compiler extensions for portability
    message(STATUS "Setting C++ standard to C++${CMAKE_CXX_STANDARD} (required for modern crypto libraries and memory safety features)")
endif()

if(NOT DEFINED IS_X86_64_ARCH AND ${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64|AMD64")
    set(IS_X86_64_ARCH TRUE)
    message(STATUS "Detected x86_64 architecture - enabling AES-NI optimizations")
else()
    set(IS_X86_64_ARCH FALSE)
endif()

if(NOT DEFINED IS_AARCH64_ARCH AND ${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64|arm64")
    set(IS_AARCH64_ARCH TRUE)
    message(STATUS "Detected ARM64 architecture - enabling crypto extensions")
else()
    set(IS_AARCH64_ARCH FALSE)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING 
        "Choose build type: Debug Release RelWithDebInfo MinSizeRel" FORCE)
    message(STATUS "No build type specified, defaulting to RelWithDebInfo for security/debugging balance")
endif()

set(TOP_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(PWLEDGER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/pwledger")
set(PWLEDGER_DIR_PREFIXES
    "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}")
string(REGEX REPLACE "(.)" "\\\\\\1" PWLEDGER_DIR_REGEX_ESCAPED "${PWLEDGER_DIR}")

add_compile_definitions(
    # Version information accessible to the application
    PWLEDGER_VERSION_MAJOR=${PACKAGE_VERSION_MAJOR}
    PWLEDGER_VERSION_MINOR=${PACKAGE_VERSION_MINOR}
    PWLEDGER_VERSION_PATCH=${PACKAGE_VERSION_PATCH}
    PWLEDGER_VERSION_STRING="${PACKAGE_VERSION}"
    
    # Security-focused feature test macros
    $<$<BOOL:${PWLEDGER_ENABLE_SECURITY_HARDENING}>:PWLEDGER_SECURITY_HARDENED=1>
)

if(MSVC)
    message(STATUS "Configuring for Microsoft Visual C++")
    include(PwledgerCompilerMSVC)
else()
    message(STATUS "Configuring for Unix-like system (GCC/Clang)")
    include(PwledgerCompilerUnix)
endif()

if(PWLEDGER_ENABLE_SECURITY_HARDENING)
    message(STATUS "Security hardening enabled - applying additional protection flags")
    
    if(NOT MSVC)
        add_compile_options(
            -fstack-protector-strong    # Stack smashing protection
            -fPIE                       # Position independent executable
            # _FORTIFY_SOURCE is set per build type in PwledgerCompilerUnix.cmake
            # rather than globally, because it requires at least -O1 and is
            # silently ignored in debug (-O0) builds.
        )
        add_link_options(
            -pie                        # Position independent executable
            -Wl,-z,relro                # Read-only relocations
            -Wl,-z,now                  # Immediate binding
            -Wl,-z,noexecstack          # Non-executable stack
        )
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            add_compile_options(
                -fstack-clash-protection    # Stack clash protection
                -fcf-protection=full        # Control flow integrity (newer GCC/Clang)
            )
        endif()
    else()
        message(STATUS "MSVC security flags will be applied via compiler-specific configuration")
    endif()
endif()

# Development-time sanitizers (should not be used in production)
if(PWLEDGER_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE MATCHES "Debug")
    message(STATUS "Enabling sanitizers for development build")
    if(NOT MSVC)
        add_compile_options(-fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    else()
        message(WARNING "Sanitizers requested but not fully supported on MSVC")
    endif()
endif()

# Static analysis integration (clang-tidy runs automatically during builds)
if(PWLEDGER_ENABLE_STATIC_ANALYSIS)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy)
    if(CLANG_TIDY_EXE)
        message(STATUS "Found clang-tidy: ${CLANG_TIDY_EXE}")
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
        set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY_EXE}")
    else()
        message(WARNING "PWLEDGER_ENABLE_STATIC_ANALYSIS is ON but clang-tidy was not found")
    endif()
endif()

# Code formatting targets (available in all build configurations)
find_program(CLANG_FORMAT_EXE NAMES clang-format)
if(CLANG_FORMAT_EXE)
    message(STATUS "Found clang-format: ${CLANG_FORMAT_EXE}")
    file(GLOB_RECURSE ALL_SOURCE_FILES
        ${CMAKE_SOURCE_DIR}/src/*.cc
        ${CMAKE_SOURCE_DIR}/src/*.cpp
        ${CMAKE_SOURCE_DIR}/src/*.c
        ${CMAKE_SOURCE_DIR}/src/*.h
        ${CMAKE_SOURCE_DIR}/include/*.h
        ${CMAKE_SOURCE_DIR}/apps/*.cc
        ${CMAKE_SOURCE_DIR}/apps/*.cpp
        ${CMAKE_SOURCE_DIR}/apps/*.c
        ${CMAKE_SOURCE_DIR}/apps/*.h
        ${CMAKE_SOURCE_DIR}/tests/*.cc
        ${CMAKE_SOURCE_DIR}/tests/*.cpp
        ${CMAKE_SOURCE_DIR}/tests/*.c
        ${CMAKE_SOURCE_DIR}/tests/*.h
    )

    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXE} -i ${ALL_SOURCE_FILES}
        COMMENT "Running clang-format on all source files"
        VERBATIM
    )

    add_custom_target(check-format
        COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror ${ALL_SOURCE_FILES}
        COMMENT "Checking source file formatting with clang-format"
        VERBATIM
    )
else()
    message(STATUS "clang-format not found - format/check-format targets will not be available")
endif()

# Memory protection and secure coding practices
if(PWLEDGER_ENABLE_SECURITY_HARDENING)
    # Ensure sensitive data can be properly cleared from memory
    add_compile_definitions(
        PWLEDGER_SECURE_MEMORY=1
        PWLEDGER_ZERO_MEMORY_ON_FREE=1
    )
endif()

find_package(Sodium REQUIRED)
if(SODIUM_FOUND)
    message(STATUS "Found libsodium: ${SODIUM_LIBRARIES}")
    if(SODIUM_VERSION)
        message(STATUS "libsodium version: ${SODIUM_VERSION}")
    endif()
else()
    message(FATAL_ERROR "libsodium is required for cryptographic operations")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

# Build the core library (Secret, TerminalManager, etc.)
add_subdirectory(src)

# 2. Build the executables (CLI app, Native Messaging Host)
add_subdirectory(apps)

# 3. Build tests (if testing is enabled)
option(PWLEDGER_BUILD_TESTS "Build the test suite" ON)
if(PWLEDGER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Display configuration summary for verification
message(STATUS "=== PWLedger Configuration Summary ===")
message(STATUS "Version: ${PACKAGE_VERSION}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Security Hardening: ${PWLEDGER_ENABLE_SECURITY_HARDENING}")
message(STATUS "Sanitizers: ${PWLEDGER_ENABLE_SANITIZERS}")
message(STATUS "Static Analysis: ${PWLEDGER_ENABLE_STATIC_ANALYSIS}")
message(STATUS "Target Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "=====================================")
