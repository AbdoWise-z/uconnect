# Observation tooling. Links the client library, not the server's store: this
# watches a rendezvous server from outside over the ordinary protocol, exactly
# as any other client would, rather than reaching into its memory.
add_executable(uconn-observe uconn-observe.cpp)
target_link_libraries(uconn-observe PRIVATE uconnect)
uconnect_bundle_runtime(uconn-observe)
