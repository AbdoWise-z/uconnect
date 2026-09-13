# Candidate ranking and the punch state machine. Sans-IO: links wire and crypto,
# never io. This is the layer that cannot be debugged against the real internet,
# so it must be drivable from a simulated network in tests.
add_library(uconnect_path STATIC
    punch.cpp
)
target_include_directories(uconnect_path PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uconnect_path PUBLIC uconnect_wire uconnect_crypto)
