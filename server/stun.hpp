#pragma once


#include <chrono>
#include <optional>

#include "socket.hpp"
#include "uconnect/types.hpp"

namespace stun {

    struct BindingResult {
        uconnect::Endpoint mapped_endpoint;
    };

    // Send a STUN Binding Request through the supplied UDP socket and return
    // the server-reflexive address observed by the STUN server.
    //
    // The socket must already be open/bound.
    //
    // Returns std::nullopt on timeout, malformed response, or STUN failure.
    std::optional<BindingResult> binding(
        uconnect::io::UdpSocket& socket,
        const uconnect::Endpoint& server,
        std::chrono::milliseconds timeout =
            std::chrono::milliseconds(2000));

    // How this NAT builds mappings, which is the single fact that decides
    // whether hole punching can work from here.
    enum class Mapping {
        Unknown,            // no STUN server answered
        Open,               // no NAT: the mapped address is our own local one
        EndpointIndependent,// one mapping for all destinations -- punching works
        EndpointDependent,  // a new port per destination (symmetric) -- punching fails
    };

    const char* to_string(Mapping);

    struct NatReport {
        Mapping                             mapping = Mapping::Unknown;
        std::vector<uconnect::Endpoint>     observed;     // one per STUN server reached
        bool                                port_preserved = false;
        uint16_t                            local_port = 0;
    };

    // Query several STUN servers from the SAME socket and compare what each one
    // reports.
    //
    // If every server sees the same ip:port, the NAT assigns one mapping per
    // internal socket regardless of destination, and a peer told that address
    // can punch to it. If the port differs per server, the NAT allocates a fresh
    // port per destination -- so the address any third party was told is not the
    // address a peer must hit, and punching cannot work.
    NatReport probe_nat(uconnect::io::UdpSocket& socket,
                        std::chrono::milliseconds timeout =
                            std::chrono::milliseconds(2000));

} // namespace stun