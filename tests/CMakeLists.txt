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
