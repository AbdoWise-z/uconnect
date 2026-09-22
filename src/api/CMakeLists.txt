# The public API. This is where the sans-IO layers get a real socket and a real
# clock; it is the only client-side target that links uconnect_io.
add_library(uconnect STATIC
    node.cpp
)
target_include_directories(uconnect PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(uconnect PUBLIC
    uconnect_wire uconnect_crypto uconnect_path uconnect_session uconnect_stream uconnect_io)
