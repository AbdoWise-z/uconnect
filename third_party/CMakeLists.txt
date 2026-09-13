# Vendored public-domain primitives. Warnings are relaxed here and only here:
# this code is deliberately kept close to its upstream form so it can be
# diffed against the original, and reformatting crypto to satisfy a linter is
# how subtle bugs get introduced.
add_library(uconnect_primitives STATIC
    x25519.c
    poly1305.c
)
target_include_directories(uconnect_primitives PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
if (NOT MSVC)
    target_compile_options(uconnect_primitives PRIVATE
        -Wno-conversion -Wno-sign-conversion -Wno-shadow)
endif()
