# Layer 0: pure encode/decode. Links nothing. If this ever needs a dependency,
# something has leaked downward.
add_library(uconnect_wire STATIC
    messages.cpp
    types.cpp
)
target_include_directories(uconnect_wire
    PUBLIC  ${CMAKE_SOURCE_DIR}/include
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}
)
