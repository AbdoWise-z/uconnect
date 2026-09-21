# Reliable, ordered, flow-controlled, multiplexed streams over the session
# layer's unreliable datagrams. Sans-IO: links wire only -- no crypto (the
# session below already encrypted everything), no sockets, no clock.
add_library(uconnect_stream STATIC
    frame.cpp
    recovery.cpp
    buffers.cpp
    connection.cpp
)
target_include_directories(uconnect_stream PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uconnect_stream PUBLIC uconnect_wire)
