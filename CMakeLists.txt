cmake_minimum_required(VERSION 3.28)
project(uConnect VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)

option(UCONNECT_BUILD_TESTS  "Build the test suite"   ON)
option(UCONNECT_BUILD_SERVER "Build the rendezvous server" ON)

# std::thread needs an explicit link on most Unix toolchains. It happens to work
# without one on MinGW and on glibc 2.34+, where pthread was folded into libc --
# which is exactly why this was missing and nothing complained.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

# Static-link the MinGW runtime so the binaries run anywhere, not just in a
# shell that has the toolchain on PATH. Without this they exit 127 looking for
# libstdc++-6.dll.
#
# This MUST appear before the add_subdirectory() calls below: add_link_options
# only affects targets created after it, so putting it at the end of the file
# silently applies it to nothing.
if (MINGW)
    # These two remove the libstdc++-6.dll and libgcc_s_seh-1.dll dependencies.
    #
    # Bare -static is NOT usable here: it fails to link with an undefined
    # __ms_vsnprintf out of libmsvcrt. Forcing libwinpthread static does not
    # work either -- CMake appends its own dynamic -lwinpthread after our
    # options -- so that last DLL is copied next to the executables instead.
    add_link_options(-static-libgcc -static-libstdc++)

    get_filename_component(_mingw_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
    file(GLOB _mingw_runtime_dlls "${_mingw_bin}/libwinpthread-1.dll")
endif()

# Copy any remaining runtime DLLs beside an executable, so it runs from a plain
# shell or Explorer rather than only from one that has the toolchain on PATH.
# Without this the binaries exit 127 with no diagnostic.
function(uconnect_bundle_runtime target)
    if (MINGW)
        foreach(_dll ${_mingw_runtime_dlls})
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${_dll}" "$<TARGET_FILE_DIR:${target}>"
                VERBATIM)
        endforeach()
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Layering. Each target declares what it may link. If a lower layer ever needs
# to link a higher one, that is a layering violation and the build says so.
#
#   wire    <- nothing        (pure encode/decode)
#   crypto  <- nothing        (pure primitives + noise state machine)
#   path    <- wire           (candidate/punch state machine, sans-IO)
#   session <- wire, crypto   (per-peer secure session, sans-IO)
#   store   <- wire           (server-side record store, sans-IO)
#   io      <- everything     (the ONLY target that may touch a socket)
# ---------------------------------------------------------------------------

add_subdirectory(src/wire)
add_subdirectory(third_party)
add_subdirectory(src/crypto)
add_subdirectory(src/path)
add_subdirectory(src/session)
add_subdirectory(src/stream)
add_subdirectory(src/io)
add_subdirectory(src/api)
add_subdirectory(examples)

if (UCONNECT_BUILD_SERVER)
    add_subdirectory(server)
endif()

if (UCONNECT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

