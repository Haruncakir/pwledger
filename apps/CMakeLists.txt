# ============================================================================
# CLI application
# ============================================================================

# Static library containing all CLI helper modules (I/O, CRUD, display,
# command loop). This lets the main.cc remain a thin entry-point wrapper.
add_library(pwledger_cli_lib STATIC
    cli/SecretIO.cc
    cli/EntryOps.cc
    cli/Display.cc
    cli/CommandLoop.cc
)
target_link_libraries(pwledger_cli_lib PUBLIC pwledger_core)
target_include_directories(pwledger_cli_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cli)

add_executable(pwledger-cli cli/main.cc)
target_link_libraries(pwledger-cli PRIVATE pwledger_cli_lib)

# ============================================================================
# Native messaging host for the browser extension
# ============================================================================

# Static library containing all native host helper modules (messaging I/O,
# command handlers, dispatch/message loop).
add_library(pwledger_host_lib STATIC
    native_host/NativeMessaging.cc
    native_host/CommandHandlers.cc
    native_host/MessageLoop.cc
)
target_link_libraries(pwledger_host_lib PUBLIC pwledger_core)
target_include_directories(pwledger_host_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/native_host)

add_executable(pwledger-host native_host/main.cc)
target_link_libraries(pwledger-host PRIVATE pwledger_host_lib)
