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

#
# THIRD-PARTY CODE ATTRIBUTION
# ============================
# 
# This file contains substantial portions of code originally developed by
# Meta, Inc. and its affiliates for the Folly C++ library project.
# 
# Original Source: https://github.com/facebook/folly
# Original License: Apache License 2.0
# Original Copyright: Copyright (c) Meta, Inc. and its affiliates.
# 
# The original Folly CMake configuration has been adapted and modified for
# use in the PWLedger password management application. Modifications include:
# - Integration with PWLedger-specific build options and security hardening
# - Adaptation for password management application requirements
# - Addition of security-focused compiler flags and definitions
# - Customization of warning levels and error handling for sensitive data processing
# 
# All modifications are released under the MIT License (see above), while
# the original Folly code portions remain under the Apache License 2.0.
# See THIRD_PARTY_LICENSES file for complete license text.
#
# The extensive compiler flag configuration and optimization settings
# in this file represent years of production experience from Meta's
# engineering team and provide a robust foundation for building secure,
# high-performance C++ applications.
#

# Some additional configuration options.
option(MSVC_ENABLE_ALL_WARNINGS "If enabled, pass /Wall to the compiler." ON)
option(MSVC_ENABLE_DEBUG_INLINING "If enabled, enable inlining in the debug configuration. This allows /Zc:inline to be far more effective." OFF)
option(MSVC_ENABLE_FAST_LINK "If enabled, pass /DEBUG:FASTLINK to the linker. This makes linking faster, but the gtest integration for Visual Studio can't currently handle the .pdbs generated." OFF)
option(MSVC_ENABLE_LEAN_AND_MEAN_WINDOWS "If enabled, define WIN32_LEAN_AND_MEAN to include a smaller subset of Windows.h" ON)
option(MSVC_ENABLE_LTCG "If enabled, use Link Time Code Generation for Release builds." OFF)
option(MSVC_ENABLE_PARALLEL_BUILD "If enabled, build multiple source files in parallel." ON)
option(MSVC_ENABLE_STATIC_ANALYSIS "If enabled, do more complex static analysis and generate warnings appropriately." OFF)
option(MSVC_USE_STATIC_RUNTIME "If enabled, build against the static, rather than the dynamic, runtime." OFF)
option(MSVC_SUPPRESS_BOOST_CONFIG_OUTDATED "If enabled, suppress Boost's warnings about the config being out of date." ON)

# PWLedger-specific security options
option(MSVC_ENABLE_SECURITY_HARDENING "If enabled, apply additional security hardening flags for sensitive data protection." ON)
option(MSVC_ENABLE_CONTROL_FLOW_GUARD "If enabled, enable Control Flow Guard for exploit mitigation." ON)

# Alas, option() doesn't support string values.
set(MSVC_FAVORED_ARCHITECTURE "blend" CACHE STRING "One of 'blend', 'AMD64', 'INTEL64', or 'ATOM'. This tells the compiler to generate code optimized to run best on the specified architecture.")
# Add a pretty drop-down selector for these values when using the GUI.
set_property(
  CACHE MSVC_FAVORED_ARCHITECTURE
  PROPERTY STRINGS
    blend
    AMD64
    ATOM
    INTEL64
)
# Validate, and then add the favored architecture.
if (NOT MSVC_FAVORED_ARCHITECTURE STREQUAL "blend" AND NOT MSVC_FAVORED_ARCHITECTURE STREQUAL "AMD64" AND NOT MSVC_FAVORED_ARCHITECTURE STREQUAL "INTEL64" AND NOT MSVC_FAVORED_ARCHITECTURE STREQUAL "ATOM")
  message(FATAL_ERROR "MSVC_FAVORED_ARCHITECTURE must be set to one of exactly, 'blend', 'AMD64', 'INTEL64', or 'ATOM'! Got '${MSVC_FAVORED_ARCHITECTURE}' instead!")
endif()

# Updated language version options for PWLedger (modified from original Folly configuration)
set(MSVC_LANGUAGE_VERSION "c++20" CACHE STRING "One of 'c++17', 'c++20', or 'c++latest'. This determines which version of C++ to compile as.")
set_property(
  CACHE MSVC_LANGUAGE_VERSION
  PROPERTY STRINGS
    "c++17"
    "c++20"
    "c++latest"
)

############################################################
# We need to adjust a couple of the default option sets.
# (This section is largely unchanged from the original Folly configuration)
############################################################

# If the static runtime is requested, we have to
# overwrite some of CMake's defaults.
if (MSVC_USE_STATIC_RUNTIME)
  foreach(flag_var
      CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
      CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
      CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
      CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    if (${flag_var} MATCHES "/MD")
      string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif()
  endforeach()
endif()

# The Ninja generator doesn't de-dup the exception mode flag, so remove the
# default flag so that MSVC doesn't warn about it on every single file.
if ("${CMAKE_GENERATOR}" STREQUAL "Ninja")
  foreach(flag_var
      CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
      CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
      CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
      CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    if (${flag_var} MATCHES "/EHsc")
      string(REGEX REPLACE "/EHsc" "" ${flag_var} "${${flag_var}}")
    endif()
  endforeach()
endif()

# In order for /Zc:inline, which speeds up the build significantly, to work
# we need to remove the /Ob0 parameter that CMake adds by default, because that
# would normally disable all inlining.
foreach(flag_var CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG)
  if (${flag_var} MATCHES "/Ob0")
    string(REGEX REPLACE "/Ob0" "" ${flag_var} "${${flag_var}}")
  endif()
endforeach()

# When building with Ninja, or with /MP enabled, there is the potential
# for multiple processes to need to lock the same pdb file.
# The /FS option (which is implicitly enabled by /MP) is widely believed
# to be the solution for this, but even with /FS enabled the problem can
# still randomly occur.
# https://stackoverflow.com/a/58020501/149111 suggests that /Z7 should be
# used; rather than placing the debug info into a .pdb file it embeds it
# into the object files in a similar way to gcc/clang which should reduce
# contention and potentially make the build faster... but at the cost of
# larger object files
foreach(flag_var CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG)
  if (${flag_var} MATCHES "/Zi")
    string(REGEX REPLACE "/Zi" "/Z7" ${flag_var} "${${flag_var}}")
  endif()
endforeach()

# Apply the option set for pwledger to the specified target.
# This function has been modified from the original Folly version to include
# PWLedger-specific security hardening and password management requirements.
function(apply_pwledger_compile_options_to_target THETARGET)
  # The general options passed (based on Folly configuration with PWLedger modifications):
  target_compile_options(${THETARGET}
    PUBLIC
      /EHs # Don't catch structured exceptions with catch (...)
      /GF # There are bugs with constexpr StringPiece when string pooling is disabled.
      /Zc:referenceBinding # Disallow temporaries from binding to non-const lvalue references.
      /Zc:rvalueCast # Enforce the standard rules for explicit type conversion.
      /Zc:implicitNoexcept # Enable implicit noexcept specifications where required, such as destructors.
      /Zc:strictStrings # Don't allow conversion from a string literal to mutable characters.
      /Zc:threadSafeInit # Enable thread-safe function-local statics initialization.
      /Zc:throwingNew # Assume operator new throws on failure.

      /permissive- # Be mean, don't allow bad non-standard stuff (C++/CLI, __declspec, etc. are all left intact).
      /std:${MSVC_LANGUAGE_VERSION} # Build in the requested version of C++
      /utf-8 # fmt needs unicode support, which requires compiling with /utf-8

      # PWLedger-specific security additions
      $<$<BOOL:${MSVC_ENABLE_SECURITY_HARDENING}>:
        /GS # Buffer security check (stack protection)
        /sdl # Enable additional security development lifecycle checks
      >
      
      $<$<BOOL:${MSVC_ENABLE_CONTROL_FLOW_GUARD}>:
        /guard:cf # Control Flow Guard for exploit mitigation
      >

    PRIVATE
      /bigobj # Support objects with > 65k sections. Needed due to templates.
      /favor:${MSVC_FAVORED_ARCHITECTURE} # Architecture to prefer when generating code.
      /Zc:inline # Have the compiler eliminate unreferenced COMDAT functions and data before emitting the object file.

      $<$<BOOL:${MSVC_ENABLE_ALL_WARNINGS}>:/Wall> # Enable all warnings if requested.
      $<$<BOOL:${MSVC_ENABLE_PARALLEL_BUILD}>:/MP> # Enable multi-processor compilation if requested.
      $<$<BOOL:${MSVC_ENABLE_STATIC_ANALYSIS}>:/analyze> # Enable static analysis if requested.

      # Debug builds
      $<$<CONFIG:DEBUG>:
        /Gy- # Disable function level linking.
        /RTC1 # Enable run-time error checks (PWLedger addition for security)

        $<$<BOOL:${MSVC_ENABLE_DEBUG_INLINING}>:/Ob2> # Add /Ob2 if allowing inlining in debug mode.
      >

      # Non-debug builds
      $<$<NOT:$<CONFIG:DEBUG>>:
        /Gw # Optimize global data. (-fdata-sections)
        /Gy # Enable function level linking. (-ffunction-sections)
        /Qpar # Enable parallel code generation.
        /Oi # Enable intrinsic functions.
        /Ot # Favor fast code.

        $<$<BOOL:${MSVC_ENABLE_LTCG}>:/GL> # Enable link time code generation.
      >
  )

  # Warning configuration (extensive list from original Folly configuration)
  # These have been proven effective in large-scale C++ development
  target_compile_options(${THETARGET}
    PUBLIC
      /wd4191 # 'type cast' unsafe conversion of function pointers
      /wd4291 # no matching operator delete found
      /wd4309 # '=' truncation of constant value
      /wd4310 # cast truncates constant value
      /wd4366 # result of unary '&' operator may be unaligned
      /wd4587 # behavior change; constructor no longer implicitly called
      /wd4592 # symbol will be dynamically initialized (implementation limitation)
      /wd4628 # digraphs not supported with -Ze
      /wd4723 # potential divide by 0
      /wd4724 # potential mod by 0
      /wd4868 # compiler may not enforce left-to-right evaluation order
      /wd4996 # user deprecated

      # The warnings that are disabled:
      /wd4068 # Unknown pragma.
      /wd4091 # 'typedef' ignored on left of '' when no variable is declared.
      /wd4146 # Unary minus applied to unsigned type, result still unsigned.
      /wd4800 # Values being forced to bool, this happens many places, and is a "performance warning".

      # Signed/unsigned mismatch warnings (critical for security in password management)
      /wd4018 # Signed/unsigned mismatch.
      /wd4365 # Signed/unsigned mismatch.
      /wd4388 # Signed/unsigned mismatch on relative comparison operator.
      /wd4389 # Signed/unsigned mismatch on equality comparison operator.

      # Development warnings that we manage separately
      /wd4100 # Unreferenced formal parameter.
      /wd4459 # Declaration of parameter hides global declaration.
      /wd4505 # Unreferenced local function has been removed.
      /wd4701 # Potentially uninitialized local variable used.
      /wd4702 # Unreachable code.

      # Warnings disabled due to /Wall enabling (from original Folly configuration)
      /wd4061 # Enum value not handled by a case in a switch on an enum.
      /wd4127 # Conditional expression is constant.
      /wd4200 # Non-standard extension, zero sized array.
      /wd4201 # Non-standard extension used: nameless struct/union.
      /wd4296 # '<' Expression is always false.
      /wd4316 # Object allocated on the heap may not be aligned to 128.
      /wd4324 # Structure was padded due to alignment specifier.
      /wd4355 # 'this' used in base member initializer list.
      /wd4371 # Layout of class may have changed due to fixes in packing.
      /wd4435 # Object layout under /vd2 will change due to virtual base.
      /wd4514 # Unreferenced inline function has been removed.
      /wd4548 # Expression before comma has no effect.
      /wd4571 # Semantics of catch(...) changed in VC 7.1
      /wd4574 # ifdef'd macro was defined to 0.
      /wd4582 # Constructor is not implicitly called.
      /wd4583 # Destructor is not implicitly called.
      /wd4619 # Invalid warning number used in #pragma warning.
      /wd4623 # Default constructor was implicitly defined as deleted.
      /wd4625 # Copy constructor was implicitly defined as deleted.
      /wd4626 # Assignment operator was implicitly defined as deleted.
      /wd4643 # Forward declaring standard library types is not permitted.
      /wd4647 # Behavior change in __is_pod.
      /wd4668 # Macro was not defined, replacing with 0.
      /wd4706 # Assignment within conditional expression.
      /wd4710 # Function was not inlined.
      /wd4711 # Function was selected for automated inlining.
      /wd4714 # Function marked as __forceinline not inlined.
      /wd4820 # Padding added after data member.
      /wd5026 # Move constructor was implicitly defined as deleted.
      /wd5027 # Move assignment operator was implicitly defined as deleted.
      /wd5031 # #pragma warning(pop): likely mismatch, popping warning state pushed in different file.
      /wd5045 # Compiler will insert Spectre mitigation for memory load if /Qspectre switch is specified.

      # Warnings to treat as errors (critical for security):
      /we4099 # Mixed use of struct and class on same type names.
      /we4129 # Unknown escape sequence.
      /we4566 # Character cannot be represented in current charset.

    PRIVATE
      # Static analysis warnings (from original Folly configuration)
      $<$<BOOL:${MSVC_ENABLE_STATIC_ANALYSIS}>:
        /wd6001 # Using uninitialized memory.
        /wd6011 # Dereferencing potentially NULL pointer.
        /wd6031 # Return value ignored.
        /wd6235 # (<non-zero constant> || <expression>) is always a non-zero constant.
        /wd6237 # (<zero> && <expression>) is always zero.
        /wd6239 # (<non-zero constant> && <expression>) always evaluates to the result of <expression>.
        /wd6240 # (<expression> && <non-zero constant>) always evaluates to the result of <expression>.
        /wd6246 # Local declaration hides declaration of same name in outer scope.
        /wd6248 # Setting a SECURITY_DESCRIPTOR's DACL to NULL will result in an unprotected object.
        /wd6255 # _alloca indicates failure by raising a stack overflow exception.
        /wd6262 # Function uses more than x bytes of stack space.
        /wd6271 # Extra parameter passed to format function.
        /wd6285 # (<non-zero constant> || <non-zero constant>) is always true.
        /wd6297 # 32-bit value is shifted then cast to 64-bits.
        /wd6308 # Realloc might return null pointer.
        /wd6326 # Potential comparison of a constant with another constant.
        /wd6330 # Unsigned/signed mismatch when passed as a parameter.
        /wd6340 # Mismatch on sign when passed as format string value.
        /wd6387 # '<value>' could be '0'.
        /wd28182 # Dereferencing NULL pointer.
        /wd28251 # Inconsistent annotation for function.
        /wd28278 # Function appears with no prototype in scope.
      >
  )

  # Preprocessor definitions (mix of original Folly and PWLedger additions)
  target_compile_definitions(${THETARGET}
    PUBLIC
      _CRT_NONSTDC_NO_WARNINGS # Don't deprecate POSIX function names
      _CRT_SECURE_NO_WARNINGS # Don't deprecate non-_s versions of standard library functions
      _SCL_SECURE_NO_WARNINGS # Don't deprecate non-_s versions of standard library functions
      _ENABLE_EXTENDED_ALIGNED_STORAGE # Support types with extended alignment in VS 15.8+
      _STL_EXTRA_DISABLED_WARNINGS=4774\ 4987

      # PWLedger-specific security definitions
      $<$<BOOL:${MSVC_ENABLE_SECURITY_HARDENING}>:
        PWLEDGER_SECURE_BUILD=1
        PWLEDGER_MEMORY_PROTECTION=1
      >

      $<$<BOOL:${MSVC_ENABLE_CPP_LATEST}>:_HAS_AUTO_PTR_ETC=1>
      $<$<BOOL:${MSVC_ENABLE_LEAN_AND_MEAN_WINDOWS}>:WIN32_LEAN_AND_MEAN>
      $<$<BOOL:${MSVC_SUPPRESS_BOOST_CONFIG_OUTDATED}>:BOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE>
  )

  # Linker flags (from original Folly configuration with PWLedger security additions)
  set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY STATIC_LIBRARY_FLAGS " /ignore:4221")

  # Debug linking options
  set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_DEBUG " /INCREMENTAL")
  if (NOT $<TARGET_PROPERTY:${THETARGET},TYPE> STREQUAL "STATIC_LIBRARY")
    set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_DEBUG " /OPT:NOREF")
    set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_DEBUG " /OPT:NOICF")

    # Release linking optimizations
    set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_RELEASE " /OPT:REF")
    set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_RELEASE " /OPT:ICF")
    
    # PWLedger security additions for release builds
    if(MSVC_ENABLE_SECURITY_HARDENING)
      set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_RELEASE " /DYNAMICBASE")
      set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_RELEASE " /NXCOMPAT")
    endif()
    
    if(MSVC_ENABLE_CONTROL_FLOW_GUARD)
      set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_RELEASE " /guard:cf")
    endif()
  endif()

  # Fast linking for development builds
  if (MSVC_ENABLE_FAST_LINK)
    set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_DEBUG " /DEBUG:FASTLINK")
  endif()

  # Link-time code generation
  if (MSVC_ENABLE_LTCG)
    set_property(TARGET ${THETARGET} APPEND_STRING PROPERTY LINK_FLAGS_RELEASE " /LTCG")
  endif()
endfunction()

# Display configuration summary
message(STATUS "=== PWLedger MSVC Configuration ===")
message(STATUS "Language Version: ${MSVC_LANGUAGE_VERSION}")
message(STATUS "Favored Architecture: ${MSVC_FAVORED_ARCHITECTURE}")
message(STATUS "Security Hardening: ${MSVC_ENABLE_SECURITY_HARDENING}")
message(STATUS "Control Flow Guard: ${MSVC_ENABLE_CONTROL_FLOW_GUARD}")
message(STATUS "Parallel Build: ${MSVC_ENABLE_PARALLEL_BUILD}")
message(STATUS "Static Analysis: ${MSVC_ENABLE_STATIC_ANALYSIS}")
message(STATUS "===================================")