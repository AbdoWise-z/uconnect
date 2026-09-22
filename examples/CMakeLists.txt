add_executable(uconn-demo uconn-demo.cpp)
target_link_libraries(uconn-demo PRIVATE uconnect)
uconnect_bundle_runtime(uconn-demo)
add_subdirectory(chat)

add_executable(uconn-stream uconn-stream.cpp)
target_link_libraries(uconn-stream PRIVATE uconnect)
uconnect_bundle_runtime(uconn-stream)
