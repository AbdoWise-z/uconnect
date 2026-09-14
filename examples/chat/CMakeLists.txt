# uconn-chat: an interactive P2P chat client.
#
# Depends only on the uconnect library target and the standard library. It can
# also be built standalone against an installed copy -- see the note in
# examples/chat/README.md.
add_executable(uconn-chat main.cpp)
target_link_libraries(uconn-chat PRIVATE uconnect)
target_include_directories(uconn-chat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
uconnect_bundle_runtime(uconn-chat)
