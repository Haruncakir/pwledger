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


# This module defines:
#  SODIUM_FOUND - True if libsodium is found
#  SODIUM_INCLUDE_DIRS - Include directories for libsodium
#  SODIUM_LIBRARIES - Libraries to link against
#  SODIUM_VERSION - Version string
#  Sodium::Sodium - Imported target
#
# You can set these variables to help guide the search:
#  SODIUM_ROOT_DIR - Root directory to search for libsodium

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_SODIUM QUIET libsodium)
endif()

find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    PATHS
        ${SODIUM_ROOT_DIR}
        ${PC_SODIUM_INCLUDE_DIRS}
        /usr/local
        /usr
        /opt/local
        /opt
        $ENV{SODIUM_ROOT_DIR}
        $ENV{PROGRAMFILES}/libsodium
        $ENV{PROGRAMFILES\(X86\)}/libsodium
    PATH_SUFFIXES
        include
        include/sodium
    DOC "libsodium include directory")

find_library(SODIUM_LIBRARY
    NAMES sodium libsodium
    PATHS
        ${SODIUM_ROOT_DIR}
        ${PC_SODIUM_LIBRARY_DIRS}
        /usr/local
        /usr
        /opt/local
        /opt
        $ENV{SODIUM_ROOT_DIR}
        $ENV{PROGRAMFILES}/libsodium
        $ENV{PROGRAMFILES\(X86\)}/libsodium
    PATH_SUFFIXES
        lib
        lib64
        lib/x64
        lib/x86
        lib/Win32
        lib/Release
        lib/Debug
    DOC "libsodium library")

# On Windows, search for debug library
if(WIN32)
    find_library(SODIUM_LIBRARY_DEBUG
        NAMES sodium_d libsodium_d
        PATHS
            ${SODIUM_ROOT_DIR}
            ${PC_SODIUM_LIBRARY_DIRS}
            $ENV{SODIUM_ROOT_DIR}
            $ENV{PROGRAMFILES}/libsodium
            $ENV{PROGRAMFILES\(X86\)}/libsodium
        PATH_SUFFIXES
            lib
            lib64
            lib/x64
            lib/x86
            lib/Win32
            lib/Debug
        DOC "libsodium debug library")
endif()

if(SODIUM_INCLUDE_DIR AND EXISTS "${SODIUM_INCLUDE_DIR}/sodium/version.h")
    file(STRINGS "${SODIUM_INCLUDE_DIR}/sodium/version.h" SODIUM_VERSION_STRING
         REGEX "^#define SODIUM_VERSION_STRING ")
    string(REGEX REPLACE "^#define SODIUM_VERSION_STRING \"([^\"]+)\".*" "\\1"
           SODIUM_VERSION "${SODIUM_VERSION_STRING}")
elseif(PC_SODIUM_VERSION)
    set(SODIUM_VERSION ${PC_SODIUM_VERSION})
endif()

# Handle standard arguments
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS SODIUM_LIBRARY SODIUM_INCLUDE_DIR
    VERSION_VAR SODIUM_VERSION
    FAIL_MESSAGE "Could not find libsodium. Try setting SODIUM_ROOT_DIR to the installation directory.")

# Set output variables
if(SODIUM_FOUND)
    set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
    set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
    
    # Create imported target
    if(NOT TARGET Sodium::Sodium)
        add_library(Sodium::Sodium UNKNOWN IMPORTED)
        set_target_properties(Sodium::Sodium PROPERTIES
            IMPORTED_LOCATION "${SODIUM_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")
        
        # Set debug library if found
        if(SODIUM_LIBRARY_DEBUG)
            set_target_properties(Sodium::Sodium PROPERTIES
                IMPORTED_LOCATION_DEBUG "${SODIUM_LIBRARY_DEBUG}")
        endif()
        
        # Add compile definitions if needed
        if(WIN32)
            set_target_properties(Sodium::Sodium PROPERTIES
                INTERFACE_COMPILE_DEFINITIONS "SODIUM_STATIC")
        endif()
    endif()
endif()

# Mark variables as advanced
mark_as_advanced(
    SODIUM_INCLUDE_DIR
    SODIUM_LIBRARY
    SODIUM_LIBRARY_DEBUG
)