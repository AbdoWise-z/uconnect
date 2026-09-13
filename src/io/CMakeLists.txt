# The ONLY target permitted to touch a socket. Everything below it takes bytes
# and a clock reading as parameters.
add_library(uconnect_io STATIC
    socket.cpp
)
target_include_directories(uconnect_io PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uconnect_io PUBLIC uconnect_wire)
if (WIN32)
    target_link_libraries(uconnect_io PUBLIC ws2_32 iphlpapi)
endif()
