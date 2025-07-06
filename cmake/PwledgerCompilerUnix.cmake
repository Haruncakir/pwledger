# Copyright (c) 2025 Harun
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

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(COMPILER_IS_GCC TRUE)
    message(STATUS "Detected GCC compiler version ${CMAKE_CXX_COMPILER_VERSION}")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(COMPILER_IS_CLANG TRUE)
    message(STATUS "Detected Clang compiler version ${CMAKE_CXX_COMPILER_VERSION}")
else()
    message(STATUS "Detected other Unix compiler: ${CMAKE_CXX_COMPILER_ID}")
endif()

set(CMAKE_CXX_FLAGS_COMMON "")
list(APPEND CMAKE_CXX_FLAGS_COMMON
    -g                        # Debug symbols for crash analysis and profiling
    -Wall                     # Enable most warning categories
    -Wextra                   # Additional useful warnings
    -Wpedantic                # Strict ISO C++ compliance warnings
    -Wconversion              # Warn about type conversions that may lose data
    -Wsign-conversion         # Warn about signed/unsigned conversions
    -Wcast-align              # Warn about casts that increase alignment requirements
    -Wcast-qual               # Warn about casts that remove qualifiers
    -Wctor-dtor-privacy       # Warn about classes with private constructors but no friends
    -Wdisabled-optimization   # Warn when optimization passes are disabled
    -Wformat=2                # Strict format string checking
    -Winit-self               # Warn about uninitialized variables used in their own initialization
    -Wmissing-include-dirs    # Warn about missing include directories
    -Wold-style-cast          # Warn about C-style casts (prefer C++ casts)
    -Woverloaded-virtual      # Warn about overloaded virtual functions
    -Wredundant-decls         # Warn about redundant declarations
    -Wshadow                  # Warn about variable shadowing
    -Wstrict-overflow=5       # Warn about strict overflow assumptions
    -Wswitch-default          # Warn about switch statements without default
    -Wundef                   # Warn about undefined macros in #if
    -Werror=return-type       # Make missing return statements an error
    -Werror=uninitialized     # Make uninitialized variable usage an error
)

string(JOIN " " CMAKE_CXX_FLAGS_COMMON_STR ${CMAKE_CXX_FLAGS_COMMON})

# Build-type specific optimizations
# Debug builds prioritize debuggability and safety checking
string(APPEND CMAKE_CXX_FLAGS_DEBUG " ${CMAKE_CXX_FLAGS_COMMON_STR}")
# No optimization for easier debugging
# Enable debug-specific code paths
# Standard debug macro
# Keep frame pointers for better stack traces
# Disable tail call optimization for clearer stack traces
string(APPEND CMAKE_CXX_FLAGS_DEBUG " -O0 -DDEBUG -D_DEBUG -fno-omit-frame-pointer -fno-optimize-sibling-calls")

# Release builds prioritize performance while maintaining security
string(APPEND CMAKE_CXX_FLAGS_RELEASE " ${CMAKE_CXX_FLAGS_COMMON_STR}")
# Optimize for performance
# Disable assertions
# Place functions in separate sections for better linking
# Place data in separate sections for better linking
string(APPEND CMAKE_CXX_FLAGS_RELEASE " -O2 -DNDEBUG -ffunction-sections -fdata-sections")

# RelWithDebInfo balances performance with debugging capability
string(APPEND CMAKE_CXX_FLAGS_RELWITHDEBINFO " ${CMAKE_CXX_FLAGS_COMMON_STR}")
# Optimize for performance
# Disable assertions
# Keep frame pointers for profiling
string(APPEND CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -DNDEBUG -fno-omit-frame-pointer")

# MinSizeRel optimizes for smallest binary size
string(APPEND CMAKE_CXX_FLAGS_MINSIZEREL " ${CMAKE_CXX_FLAGS_COMMON_STR}")
# Optimize for size
# Disable assertions
# Enable section-based optimization
string(APPEND CMAKE_CXX_FLAGS_MINSIZEREL " -Os -DNDEBUG -ffunction-sections -fdata-sections")

# Linker flags for dead code elimination (works with -ffunction-sections/-fdata-sections)
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "${CMAKE_EXE_LINKER_FLAGS_MINSIZEREL} -Wl,--gc-sections")

# Required definitions for proper system header behavior
list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")

# Architecture-specific optimizations for cryptographic operations
if(IS_X86_64_ARCH)
    # Enable AES-NI and other crypto instructions available on modern x86_64
    set(ARCH_SPECIFIC_FLAGS "-march=native -mtune=native")
    message(STATUS "Enabling x86_64 optimizations including AES-NI support")
elseif(IS_AARCH64_ARCH)
    # Enable ARM crypto extensions if available
    set(ARCH_SPECIFIC_FLAGS "-march=native -mtune=native")
    message(STATUS "Enabling ARM64 optimizations including crypto extensions")
else()
    # Generic optimizations for other architectures
    set(ARCH_SPECIFIC_FLAGS "-mtune=generic")
endif()

# Function to apply all pwledger-specific compile options to a target
# This encapsulates our security and performance requirements
function(apply_pwledger_compile_options_to_target THETARGET)
    # System and threading definitions required for secure applications
    target_compile_definitions(${THETARGET}
        PRIVATE
            _REENTRANT              # Enable thread-safe library functions
            _GNU_SOURCE             # Enable GNU extensions
            _THREAD_SAFE            # Enable thread-safe operations
            _LARGEFILE64_SOURCE     # Enable large file support
            _FILE_OFFSET_BITS=64    # Enable 64-bit file offsets
            
            # Security-focused definitions
            $<$<BOOL:${PWLEDGER_ENABLE_SECURITY_HARDENING}>:
                _FORTIFY_SOURCE=2   # Enable buffer overflow detection
                PWLEDGER_SECURE_BUILD=1
            >
    )
    
    # Core compile options that ensure security and correctness
    target_compile_options(${THETARGET}
        PRIVATE
            # Debug and development flags
            -g                          # Debug symbols
            -finput-charset=UTF-8       # Handle UTF-8 input properly
            -fsigned-char               # Ensure consistent char behavior
            
            # Warning configuration - be strict about potential issues
            -Wall                       # Enable most warnings
            -Wextra                     # Additional useful warnings
            -Wpedantic                  # Strict standard compliance
            -Wconversion                # Warn about potentially lossy conversions
            -Wsign-conversion           # Warn about signed/unsigned mismatches
            -Wcast-align                # Warn about alignment issues
            -Wcast-qual                 # Warn about qualifier removal
            -Wformat=2                  # Strict format string checking
            -Wmissing-include-dirs      # Warn about missing include directories
            -Wold-style-cast            # Prefer C++ casts over C casts
            -Woverloaded-virtual        # Warn about virtual function issues
            -Wredundant-decls           # Warn about redundant declarations
            -Wshadow                    # Warn about variable shadowing
            -Wstrict-overflow=5         # Warn about overflow assumptions
            -Wswitch-default            # Require default cases in switches
            -Wundef                     # Warn about undefined macros
            -Werror=return-type         # Missing return is an error
            -Werror=uninitialized       # Uninitialized variables are errors
            
            # Warnings we suppress for practicality but monitor
            -Wno-deprecated             # Allow deprecated functions (monitor separately)
            -Wno-deprecated-declarations # Allow deprecated declarations
            -Wno-unused-parameter       # Allow unused parameters (common in interfaces)
            
            # Security-focused compiler options
            $<$<BOOL:${PWLEDGER_ENABLE_SECURITY_HARDENING}>:
                -fstack-protector-strong    # Stack smashing protection
                -fPIE                       # Position independent executable
                -D_FORTIFY_SOURCE=2         # Buffer overflow detection
                -Wstack-protector           # Warn about stack protection issues
                -fstack-clash-protection    # Stack clash protection
            >
            
            # Architecture-specific optimizations
            ${ARCH_SPECIFIC_FLAGS}
            
            # Compiler-specific additional flags
            $<$<BOOL:${COMPILER_IS_GCC}>:
                -Wlogical-op            # Warn about logical operation issues (GCC-specific)
                -Wduplicated-cond       # Warn about duplicated conditions (GCC-specific)
                -Wduplicated-branches   # Warn about duplicated branches (GCC-specific)
                -Wnull-dereference      # Warn about null pointer dereferences (GCC-specific)
            >
            
            $<$<BOOL:${COMPILER_IS_CLANG}>:
                -Wthread-safety         # Thread safety analysis (Clang-specific)
                -Wthread-safety-beta    # Experimental thread safety warnings (Clang-specific)
            >
    )
    
    # Linker options for security hardening
    if(PWLEDGER_ENABLE_SECURITY_HARDENING)
        target_link_options(${THETARGET}
            PRIVATE
                -pie                    # Position independent executable
                -Wl,-z,relro           # Read-only relocations
                -Wl,-z,now             # Immediate binding
                -Wl,-z,noexecstack     # Non-executable stack
                -Wl,-z,defs            # Disallow undefined symbols
                -Wl,--as-needed        # Only link needed libraries
        )
    endif()
    
    # Additional security considerations for password management
    target_compile_definitions(${THETARGET}
        PRIVATE
            # Memory security
            $<$<BOOL:${PWLEDGER_ENABLE_SECURITY_HARDENING}>:
                PWLEDGER_SECURE_MEMORY=1        # Enable secure memory handling
                PWLEDGER_ZERO_ON_FREE=1         # Zero memory on deallocation
                PWLEDGER_MLOCK_SENSITIVE=1      # Lock sensitive memory pages
            >
    )
endfunction()

# Display Unix-specific configuration summary
message(STATUS "=== Unix Compiler Configuration ===")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Architecture optimizations: ${ARCH_SPECIFIC_FLAGS}")
message(STATUS "Security hardening: ${PWLEDGER_ENABLE_SECURITY_HARDENING}")
if(PWLEDGER_ENABLE_SECURITY_HARDENING)
    message(STATUS "  - Stack protection: enabled")
    message(STATUS "  - PIE/ASLR: enabled")
    message(STATUS "  - Fortify source: enabled")
    message(STATUS "  - Relro/Bind now: enabled")
endif()
message(STATUS "==================================")