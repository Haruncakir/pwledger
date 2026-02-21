# The CLI application
add_executable(pwledger-cli
  cli/main.cc
)
# Link the core library (this automatically brings in the include paths)
target_link_libraries(pwledger-cli PRIVATE pwledger_core)

# The native messaging host for the browser extension
add_executable(pwledger-host
    native_host/main.cc
)
target_link_libraries(pwledger-host PRIVATE pwledger_core)
