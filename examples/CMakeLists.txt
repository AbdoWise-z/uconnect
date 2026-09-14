add_executable(uconn-demo uconn-demo.cpp)
target_link_libraries(uconn-demo PRIVATE uconnect)
uconnect_bundle_runtime(uconn-demo)
add_subdirectory(chat)
