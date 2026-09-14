# Build the rendezvous server as a static Linux binary.
#
#   docker build -t uconnect-rendezvous .
#   docker run --rm -p 4433:4433/udp uconnect-rendezvous
#
# Note the /udp suffix on the port mapping. This server speaks only UDP; a TCP
# mapping publishes nothing and the container will look alive while being
# completely unreachable.

FROM alpine:3.20 AS build

RUN apk add --no-cache build-base cmake ninja linux-headers

WORKDIR /src
COPY CMakeLists.txt ./
COPY include/ include/
COPY src/ src/
COPY server/ server/
COPY third_party/ third_party/
COPY tests/ tests/
COPY examples/ examples/
COPY scripts/ scripts/

# Static link so the runtime image needs no libc at all. Alpine/musl makes this
# straightforward, unlike the MinGW toolchain where bare -static fails.
RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DUCONNECT_BUILD_TESTS=ON \
        -DCMAKE_EXE_LINKER_FLAGS="-static" \
 && cmake --build build \
 && ./build/tests/uconnect_tests \
 && strip build/server/uconnect-rendezvous

# ---------------------------------------------------------------------------
# Runtime: nothing but the binary. The server holds no keys, writes no files,
# and keeps every record in memory with a 90s expiry, so there is nothing to
# persist and nothing to mount.
FROM scratch

COPY --from=build /src/build/server/uconnect-rendezvous /uconnect-rendezvous

EXPOSE 4433/udp
ENTRYPOINT ["/uconnect-rendezvous"]
CMD ["--port", "4433"]
