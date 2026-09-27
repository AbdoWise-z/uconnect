// NAT classification from STUN results. The probing itself needs the network;
// deciding what the answers mean does not, and that is where #35 went wrong.

#include "stun.hpp"
#include "testing.hpp"

using namespace uconnect;
using stun::Mapping;

namespace {

Endpoint at(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    return Endpoint{IpAddr::v4(a, b, c, d), port};
}

const std::vector<IpAddr> kLocal{IpAddr::v4(192, 168, 1, 20)};

}  // namespace

TEST(stun_same_mapping_from_every_server_is_endpoint_independent) {
    // #35. Every server saw the same address, so the NAT hands out one mapping
    // per socket whatever the destination -- the case punching works for. It
    // was being reported as symmetric, telling operators punching could not.
    std::vector<Endpoint> seen{at(203, 0, 113, 7, 40000), at(203, 0, 113, 7, 40000)};
    CHECK(stun::classify_mapping(seen, 5000, kLocal) == Mapping::EndpointIndependent);
}

TEST(stun_a_different_mapping_per_server_is_endpoint_dependent) {
    std::vector<Endpoint> seen{at(203, 0, 113, 7, 40000), at(203, 0, 113, 7, 40001)};
    CHECK(stun::classify_mapping(seen, 5000, kLocal) == Mapping::EndpointDependent);
}

TEST(stun_a_mapping_that_is_our_own_address_means_no_nat) {
    // #35: Mapping::Open was documented but never produced.
    std::vector<Endpoint> seen{at(192, 168, 1, 20, 5000), at(192, 168, 1, 20, 5000)};
    CHECK(stun::classify_mapping(seen, 5000, kLocal) == Mapping::Open);

    // Our IP but a different port is still a translating NAT, not an open host.
    std::vector<Endpoint> moved{at(192, 168, 1, 20, 6000), at(192, 168, 1, 20, 6000)};
    CHECK(stun::classify_mapping(moved, 5000, kLocal) == Mapping::EndpointIndependent);
}

TEST(stun_fewer_than_two_answers_cannot_classify) {
    CHECK(stun::classify_mapping({}, 5000, kLocal) == Mapping::Unknown);
    CHECK(stun::classify_mapping({at(203, 0, 113, 7, 40000)}, 5000, kLocal) ==
          Mapping::Unknown);
}
