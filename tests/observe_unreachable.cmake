# uconn-observe against a port nothing listens on. #48: it printed ok:true with
# null stats and an empty listing, and exited 0 -- exactly what an empty server
# looks like, which is the one confusion the tool exists to prevent.
#
# Every mode must instead print valid JSON with ok:false and exit non-zero.
#
#   cmake -DOBSERVE=<path to uconn-observe> -P observe_unreachable.cmake

if (NOT OBSERVE)
    message(FATAL_ERROR "pass -DOBSERVE=<path to uconn-observe>")
endif()

set(modes "overview" "topic" "members")
set(args_overview "")
set(args_topic    "--topic;00112233445566778899aabbccddeeff")
set(args_members  "--members")

set(failed FALSE)
foreach (mode IN LISTS modes)
    execute_process(
        COMMAND "${OBSERVE}" --server 127.0.0.1:1 --timeout 300 ${args_${mode}}
        RESULT_VARIABLE rc
        OUTPUT_VARIABLE out
        ERROR_VARIABLE  err
        TIMEOUT 30)

    string(JSON ok ERROR_VARIABLE json_err GET "${out}" ok)
    if (json_err)
        message(SEND_ERROR "[${mode}] not valid JSON (${json_err}):\n${out}")
        set(failed TRUE)
    elseif (ok)
        message(SEND_ERROR "[${mode}] reported ok:true for an unreachable server:\n${out}")
        set(failed TRUE)
    endif()
    if ("${rc}" STREQUAL "0")
        message(SEND_ERROR "[${mode}] exited 0 for an unreachable server")
        set(failed TRUE)
    endif()
    if (NOT failed)
        message(STATUS "[${mode}] exit ${rc}: ${out}")
    endif()
endforeach()
