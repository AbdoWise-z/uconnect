add_executable(uconnect_tests
    test_main.cpp
    test_wire.cpp
    test_crypto.cpp
    test_punch.cpp
    test_session.cpp
    test_node.cpp
    test_stun.cpp
    test_chat.cpp
    test_io.cpp
    test_control.cpp
    test_registry.cpp
    test_rendezvous.cpp
    test_tcp_session.cpp
    test_capi.cpp
    capi_header.c
    # The server's STUN client is compiled straight in: it lives in the server
    # executable, not a library, and only its pure classification is tested.
    ${CMAKE_SOURCE_DIR}/server/stun.cpp
)
target_link_libraries(uconnect_tests PRIVATE uconnect_wire uconnect_crypto uconnect_store uconnect_path uconnect_session uconnect uconnect_rendezvous uconnect_c)
target_include_directories(uconnect_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
uconnect_bundle_runtime(uconnect_tests)

# Windows finds a DLL beside the executable, not where it was built.
if (WIN32)
    add_custom_command(TARGET uconnect_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:uconnect_c>" "$<TARGET_FILE_DIR:uconnect_tests>"
        VERBATIM)
endif()
add_test(NAME uconnect_tests COMMAND uconnect_tests)

# uconn-observe must report a server it cannot reach as a failure, not as an
# empty directory. Runs the real binary; needs no server, so it is not e2e.
add_test(NAME uconn_observe_reports_unreachable_server
         COMMAND ${CMAKE_COMMAND} -DOBSERVE=$<TARGET_FILE:uconn-observe>
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/observe_unreachable.cmake)

# The end-to-end tests below are bash scripts, and the bash must be one that
# understands Windows paths. A bare "bash" on Windows can resolve to the WSL
# launcher in System32 (or WindowsApps), which runs Linux -- and Linux cannot
# open the C:/ paths CTest hands it. Git for Windows' bash can, so look beside
# git first and refuse the launchers. Set UCONNECT_BASH to choose one yourself.
function(uconnect_usable_bash result candidate)
    string(TOLOWER "${candidate}" lower)
    if (WIN32 AND lower MATCHES "/(system32|windowsapps)/")
        set(${result} FALSE PARENT_SCOPE)
    endif()
endfunction()

set(_bash_hints)
if (WIN32)
    find_package(Git QUIET)
    if (GIT_EXECUTABLE)
        # git.exe is in <git>/cmd or <git>/mingw64/bin; bash in <git>/bin.
        get_filename_component(_git_dir "${GIT_EXECUTABLE}" DIRECTORY)
        list(APPEND _bash_hints "${_git_dir}/../bin" "${_git_dir}/../../bin")
    endif()
endif()
find_program(UCONNECT_BASH NAMES bash HINTS ${_bash_hints}
             VALIDATOR uconnect_usable_bash
             DOC "bash for the end-to-end tests")

# Each script is handed this tree's binaries. Left to themselves they run
# ./build's, which from any other build tree are stale or missing.
set(_e2e_env
    "UCONNECT_SERVER=$<TARGET_FILE:uconnect-rendezvous>"
    "UCONNECT_DEMO=$<TARGET_FILE:uconn-demo>"
    "UCONNECT_XFER=$<TARGET_FILE:uconn-transfer>")

# Both run the server executable, so they exist only when it is built.
set(_e2e OFF)
if (UCONNECT_BUILD_SERVER AND (UNIX OR MINGW))
    if (UCONNECT_BASH)
        set(_e2e ON)
    else()
        message(STATUS "No usable bash found: end-to-end tests not registered (set UCONNECT_BASH)")
    endif()
endif()

# End-to-end: a real server and two real peers that must punch, handshake and
# exchange data over actual TCP sockets. Separate from the unit suite because
# it binds a port and takes ~15s; the sans-IO tests above cover the protocol
# logic deterministically in milliseconds.
if (_e2e)
    add_test(NAME uconnect_smoke
             COMMAND ${UCONNECT_BASH} ${CMAKE_SOURCE_DIR}/scripts/smoke.sh)
    set_tests_properties(uconnect_smoke PROPERTIES TIMEOUT 90 LABELS "e2e"
                         ENVIRONMENT "${_e2e_env}")
endif()

# A megabyte of messages over both paths a peer can take: directly punched,
# and relayed through the rendezvous server, verifying every byte. Slower than
# the smoke test above, so it is labelled separately: ctest -L e2e runs both,
# ctest -LE slow skips this one.
if (_e2e)
    add_test(NAME uconnect_transfer_smoke
             COMMAND ${UCONNECT_BASH} ${CMAKE_SOURCE_DIR}/scripts/transfer-smoke.sh)
    set_tests_properties(uconnect_transfer_smoke PROPERTIES TIMEOUT 200 LABELS "e2e;slow"
                         ENVIRONMENT "${_e2e_env}")
endif()
