cmake_minimum_required(VERSION 3.28)
project(uConnect VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)

option(UCONNECT_BUILD_TESTS  "Build the test suite"   ON)
option(UCONNECT_BUILD_SERVER "Build the rendezvous server" ON)

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

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

# Static-link the MinGW runtime so the binaries run without libstdc++-6.dll and
# friends on PATH -- otherwise they exit 127 outside the toolchain shell.
if (MINGW)
    add_link_options(-static-libgcc -static-libstdc++ -static)
endif()
