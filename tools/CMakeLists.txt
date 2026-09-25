# Observation tooling. Links the client library, not the server's store: this
# watches a rendezvous server from outside over the ordinary protocol, exactly
# as any other client would, rather than reaching into its memory.
add_executable(uconn-observe uconn-observe.cpp)
target_link_libraries(uconn-observe PRIVATE uconnect)
uconnect_bundle_runtime(uconn-observe)

# The browser's stand-in. A browser cannot be a peer -- no UDP socket, no hole
# punching, no Noise handshake -- so the web chat runs one of these per session
# and relays between it and the page.
add_executable(uconn-bridge uconn-bridge.cpp)
target_link_libraries(uconn-bridge PRIVATE uconnect)
uconnect_bundle_runtime(uconn-bridge)
