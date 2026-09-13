# Per-peer secure session: Noise handshake bound to a validated path, then
# authenticated transport with replay protection and path migration. Sans-IO.
add_library(uconnect_session STATIC
    session.cpp
)
target_include_directories(uconnect_session PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uconnect_session PUBLIC uconnect_wire uconnect_crypto)
