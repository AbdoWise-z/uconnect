# uconnect-rendezvous reading its configuration file, as an operator runs it.
# --print-config exits before any socket opens, so none of this needs the
# network or a free port.
#
#   cmake -DSERVER=<path to uconnect-rendezvous> -DEXAMPLE=<example yaml>
#         -DWORK=<scratch dir> -P server_config.cmake

if (NOT SERVER OR NOT EXAMPLE OR NOT WORK)
    message(FATAL_ERROR "pass -DSERVER, -DEXAMPLE and -DWORK")
endif()
file(MAKE_DIRECTORY "${WORK}")

function(run_server out_rc out_stdout out_stderr)
    execute_process(COMMAND "${SERVER}" ${ARGN}
                    RESULT_VARIABLE rc OUTPUT_VARIABLE so ERROR_VARIABLE se TIMEOUT 30)
    set(${out_rc} "${rc}" PARENT_SCOPE)
    set(${out_stdout} "${so}" PARENT_SCOPE)
    set(${out_stderr} "${se}" PARENT_SCOPE)
endfunction()

# The example file, printed back: every default in force.
run_server(rc printed err --config "${EXAMPLE}" --print-config)
if (NOT rc EQUAL 0)
    message(FATAL_ERROR "example config refused (exit ${rc}):\n${err}")
endif()
foreach (want "port: 4433" "max_bytes: 32MiB" "max_per_ip: 8" "udp_burst_bytes: 8MiB")
    string(FIND "${printed}" "${want}" at)
    if (at EQUAL -1)
        message(FATAL_ERROR "--print-config lacks '${want}':\n${printed}")
    endif()
endforeach()

# What it prints, it reads back unchanged.
file(WRITE "${WORK}/printed.yaml" "${printed}")
run_server(rc again err --config "${WORK}/printed.yaml" --print-config)
if (NOT rc EQUAL 0 OR NOT again STREQUAL printed)
    message(FATAL_ERROR "printed config did not read back the same (exit ${rc}):\n${err}\n${again}")
endif()

# A flag beats the file, even placed before it.
run_server(rc flagged err --port 0 --config "${EXAMPLE}" --print-config)
string(FIND "${flagged}" "port: 0\n" at)
if (NOT rc EQUAL 0 OR at EQUAL -1)
    message(FATAL_ERROR "--port did not override the file (exit ${rc}):\n${flagged}${err}")
endif()

# A bad file stops the server, naming the file and the line.
file(WRITE "${WORK}/bad.yaml" "port: 4433\nrelay:\n  max_byts: 1MiB\n")
run_server(rc out err --config "${WORK}/bad.yaml")
string(FIND "${err}" "bad.yaml:3: unknown key 'relay.max_byts'" at)
if (rc EQUAL 0 OR at EQUAL -1)
    message(FATAL_ERROR "bad config not reported as expected (exit ${rc}):\n${err}")
endif()
message(STATUS "bad config refused, exit ${rc}: ${err}")
