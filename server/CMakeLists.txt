# Sans-IO record store: no sockets, no clock, no threads.
add_library(uconnect_store STATIC
    store.cpp
    udp_service.cpp
    registry.cpp
)
target_include_directories(uconnect_store PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uconnect_store PUBLIC uconnect_wire uconnect_crypto)

# Control protocol v2 on the server: the sans-IO service, and the runtime that
# owns its sockets. A library so tests can run a real server in-process.
add_library(uconnect_rendezvous STATIC
    control_service.cpp
    rendezvous.cpp
)
target_include_directories(uconnect_rendezvous PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uconnect_rendezvous PUBLIC uconnect_store uconnect_io)

# The binary is the only part here that touches the network.
add_executable(uconnect-rendezvous
        main.cpp
        stun.hpp
        stun.cpp
)
target_link_libraries(uconnect-rendezvous PRIVATE uconnect_store uconnect_io Threads::Threads)
uconnect_bundle_runtime(uconnect-rendezvous)
