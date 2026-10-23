# Setup GoogleTest via FetchContent 
include(FetchContent)

# Automatically download and build GoogleTest. 
# This guarantees everyone building the project uses the exact same version,
# and nobody has to run `apt-get install libgtest-dev` or equivalent.
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.17.0
)

# For MSVC (Windows) ensure GTest uses the same C-Runtime library as the app.
# Without this, we get linker errors about mismatched MSVCRT.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

# Bring in the GoogleTest CMake macros (gives us gtest_discover_tests)
include(GoogleTest)

# Secret class tests
# ---------------------------
add_executable(test_secret
    test_secret.cc
)

# Link against the core library and GoogleTest.
# Notice we use GTest::gtest_main. This automatically provides the main() 
# function for the test executable, so we don't have to write one.
target_link_libraries(test_secret 
    PRIVATE 
        pwledger_core 
        GTest::gtest_main
)

# Automatically parse the test_secret.cc file and register every TEST() or 
# TEST_F() macro as an individual test case in CTest.
gtest_discover_tests(test_secret)

# ---------------------------

# Vault storage tests
# ---------------------------
add_executable(test_vault
    test_vault.cc
)

target_compile_definitions(test_vault PRIVATE
    PWLEDGER_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)

target_link_libraries(test_vault 
    PRIVATE 
        pwledger_core 
        GTest::gtest_main
)

gtest_discover_tests(test_vault)

# ---------------------------

# Config tests
# ---------------------------
add_executable(test_config
    test_config.cc
)

target_link_libraries(test_config
    PRIVATE
        pwledger_core
        GTest::gtest_main
)

gtest_discover_tests(test_config)

# ---------------------------

# UUID tests
# ---------------------------
add_executable(test_uuid
    test_uuid.cc
)

target_link_libraries(test_uuid
    PRIVATE
        pwledger_core
        GTest::gtest_main
)

gtest_discover_tests(test_uuid)

# ---------------------------

# SecureBuffer tests
# ---------------------------
add_executable(test_secure_buffer
    test_secure_buffer.cc
)

target_link_libraries(test_secure_buffer
    PRIVATE
        pwledger_core
        GTest::gtest_main
)

gtest_discover_tests(test_secure_buffer)

# On MSVC with ASan enabled, copy ASan runtime DLLs to target output directories
if(MSVC AND PWLEDGER_ENABLE_SANITIZERS)
    get_filename_component(MSVC_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    file(GLOB ASAN_DLLS "${MSVC_BIN_DIR}/clang_rt.asan_*.dll")
    foreach(DLL IN LISTS ASAN_DLLS)
        foreach(TARGET_NAME test_secret test_vault test_config test_uuid test_secure_buffer)
            add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${DLL}" "$<TARGET_FILE_DIR:${TARGET_NAME}>"
            )
        endforeach()
    endforeach()
endif()

# ---------------------------
