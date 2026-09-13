# Layer 0: primitives and the Noise state machine. Links only the vendored
# primitives -- no wire, no io, no clock.
add_library(uconnect_crypto STATIC
    blake2s.cpp
    aead.cpp
    random.cpp
    noise.cpp
    kdf.cpp
)
target_include_directories(uconnect_crypto
    PUBLIC ${CMAKE_SOURCE_DIR}/include
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(uconnect_crypto PUBLIC uconnect_primitives)

if (WIN32)
    target_link_libraries(uconnect_crypto PUBLIC bcrypt)
endif()
