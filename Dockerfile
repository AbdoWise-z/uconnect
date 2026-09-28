# Build the rendezvous server as a static Linux binary.
#
#   docker build -t uconnect-rendezvous .
#   docker run --rm -p 4433:4433/tcp -p 4433:4433/udp uconnect-rendezvous
#
# Publish BOTH. Nodes keep their control connection -- and the TCP relay -- on
# TCP; datagram channels learn their address and use the UDP relay on UDP. With
# only one mapped, the container looks alive while half the protocol is
# unreachable.

FROM alpine:3.20 AS build

RUN apk add --no-cache build-base cmake ninja linux-headers

WORKDIR /src
# This list mirrors every add_subdirectory() in the root CMakeLists. Adding one
# there and not here fails the configure step with "not an existing directory",
# which is a confusing way to learn that a directory was never copied -- it is
# how this Dockerfile silently stopped building when tools/ was added.
COPY CMakeLists.txt ./
COPY include/ include/
COPY src/ src/
COPY server/ server/
COPY third_party/ third_party/
COPY tools/ tools/
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
# and keeps every record only as long as its node's connection is open, so
# there is nothing to persist and nothing to mount.
FROM scratch

COPY --from=build /src/build/server/uconnect-rendezvous /uconnect-rendezvous

EXPOSE 4433/tcp
EXPOSE 4433/udp
ENTRYPOINT ["/uconnect-rendezvous"]
CMD ["--port", "4433"]
