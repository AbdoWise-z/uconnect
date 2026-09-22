add_executable(uconnect_tests
    test_main.cpp
    test_wire.cpp
    test_crypto.cpp
    test_store.cpp
    test_punch.cpp
    test_session.cpp
    test_stream.cpp
)
target_link_libraries(uconnect_tests PRIVATE uconnect_wire uconnect_crypto uconnect_store uconnect_path uconnect_session uconnect_stream)
target_include_directories(uconnect_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
uconnect_bundle_runtime(uconnect_tests)
add_test(NAME uconnect_tests COMMAND uconnect_tests)

# End-to-end: a real server and two real peers that must punch, handshake and
# exchange data over actual UDP sockets. Separate from the unit suite because
# it binds a port and takes ~15s; the sans-IO tests above cover the protocol
# logic deterministically in milliseconds.
if (UCONNECT_BUILD_SERVER AND UNIX OR MINGW)
    add_test(NAME uconnect_smoke
             COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/smoke.sh)
    set_tests_properties(uconnect_smoke PROPERTIES TIMEOUT 90 LABELS "e2e")
endif()

# Reliable streams over both paths a peer can take: directly punched, and
# relayed through the rendezvous server. Transfers a megabyte each way and
# verifies every byte. Slower than the smoke test above, so it is labelled
# separately: ctest -L e2e runs both, ctest -LE slow skips this one.
if (UCONNECT_BUILD_SERVER AND UNIX OR MINGW)
    add_test(NAME uconnect_stream_smoke
             COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/stream-smoke.sh)
    set_tests_properties(uconnect_stream_smoke PROPERTIES TIMEOUT 400 LABELS "e2e;slow")
endif()
