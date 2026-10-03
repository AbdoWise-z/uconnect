# Observation tooling. Links the client library, not the server's store: this
# watches a rendezvous server from outside over the ordinary protocol, exactly
# as any other client would, rather than reaching into its memory.
add_executable(uconn-observe uconn-observe.cpp)
target_link_libraries(uconn-observe PRIVATE uconnect)
uconnect_bundle_runtime(uconn-observe)

# Throughput by node count and path. Unlike the observer it hosts its own
# rendezvous server in-process, under a limits file it is given, so it needs
# the server's libraries -- built whenever the server or the tests are.
if (UCONNECT_BUILD_SERVER OR UCONNECT_BUILD_TESTS)
    add_executable(uconn-bench uconn-bench.cpp)
    target_link_libraries(uconn-bench PRIVATE uconnect uconnect_rendezvous)
    uconnect_bundle_runtime(uconn-bench)
endif()
