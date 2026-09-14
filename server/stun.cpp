#include "stun.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <span>
#include <vector>

#include "socket.hpp"
#include "uconnect/types.hpp"

namespace stun {

namespace {

// STUN magic cookie defined by RFC 5389 / RFC 8489.
constexpr uint32_t kMagicCookie = 0x2112A442;

// Message types.
constexpr uint16_t kBindingRequest         = 0x0001;
constexpr uint16_t kBindingSuccessResponse = 0x0101;

// Attributes.
constexpr uint16_t kMappedAddress    = 0x0001;
constexpr uint16_t kXorMappedAddress = 0x0020;

constexpr size_t kHeaderSize = 20;
constexpr size_t kTransactionIdSize = 12;

// ---------------------------------------------------------------------------
// Big-endian helpers
// ---------------------------------------------------------------------------

uint16_t read_u16(const uint8_t* p)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) |
        static_cast<uint16_t>(p[1]));
}

uint32_t read_u32(const uint8_t* p)
{
    return
        (static_cast<uint32_t>(p[0]) << 24) |
        (static_cast<uint32_t>(p[1]) << 16) |
        (static_cast<uint32_t>(p[2]) << 8)  |
        static_cast<uint32_t>(p[3]);
}

void write_u16(uint8_t* p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value >> 8);
    p[1] = static_cast<uint8_t>(value);
}

void write_u32(uint8_t* p, uint32_t value)
{
    p[0] = static_cast<uint8_t>(value >> 24);
    p[1] = static_cast<uint8_t>(value >> 16);
    p[2] = static_cast<uint8_t>(value >> 8);
    p[3] = static_cast<uint8_t>(value);
}

// ---------------------------------------------------------------------------
// Transaction ID
// ---------------------------------------------------------------------------

std::array<uint8_t, kTransactionIdSize> generate_transaction_id()
{
    std::array<uint8_t, kTransactionIdSize> id{};

    std::random_device rd;

    // random_device is sufficient here as a source of transaction-ID
    // unpredictability. The transaction ID isn't used as a cryptographic key.
    for (size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<uint8_t>(rd());

    return id;
}

// ---------------------------------------------------------------------------
// Build Binding Request
// ---------------------------------------------------------------------------

std::array<uint8_t, kHeaderSize> make_binding_request(
    const std::array<uint8_t, kTransactionIdSize>& transaction_id)
{
    std::array<uint8_t, kHeaderSize> packet{};

    // Message Type.
    write_u16(packet.data() + 0, kBindingRequest);

    // Message Length.
    //
    // We don't include any attributes, so this is zero.
    write_u16(packet.data() + 2, 0);

    // Magic Cookie.
    write_u32(packet.data() + 4, kMagicCookie);

    // Transaction ID.
    std::memcpy(
        packet.data() + 8,
        transaction_id.data(),
        transaction_id.size());

    return packet;
}

// ---------------------------------------------------------------------------
// Decode XOR-MAPPED-ADDRESS
// ---------------------------------------------------------------------------

std::optional<uconnect::Endpoint> decode_xor_mapped_address(
    std::span<const uint8_t> value,
    const std::array<uint8_t, kTransactionIdSize>& transaction_id)
{
    // Attribute format:
    //
    //   0       reserved
    //   1       family
    //   2..3    XOR'ed port
    //   4..     XOR'ed address
    //
    if (value.size() < 4)
        return std::nullopt;

    const uint8_t family = value[1];

    const uint16_t xor_port = read_u16(value.data() + 2);

    const uint16_t port =
        xor_port ^ static_cast<uint16_t>(kMagicCookie >> 16);

    uconnect::Endpoint endpoint;
    endpoint.port = port;

    // -----------------------------------------------------------------------
    // IPv4
    // -----------------------------------------------------------------------

    if (family == 0x01) {
        if (value.size() < 8)
            return std::nullopt;

        const uint32_t xor_address =
            read_u32(value.data() + 4);

        const uint32_t address =
            xor_address ^ kMagicCookie;

        endpoint.ip = uconnect::IpAddr::v4(
            static_cast<uint8_t>((address >> 24) & 0xff),
            static_cast<uint8_t>((address >> 16) & 0xff),
            static_cast<uint8_t>((address >> 8)  & 0xff),
            static_cast<uint8_t>(address & 0xff));

        return endpoint;
    }

    // -----------------------------------------------------------------------
    // IPv6
    // -----------------------------------------------------------------------

    if (family == 0x02) {
        if (value.size() < 20)
            return std::nullopt;

        endpoint.ip.family = uconnect::IpAddr::Family::V6;

        // XOR mask for IPv6:
        //
        //   magic cookie (4 bytes)
        //   transaction ID (12 bytes)
        //
        std::array<uint8_t, 16> mask{};

        write_u32(mask.data(), kMagicCookie);

        std::memcpy(
            mask.data() + 4,
            transaction_id.data(),
            transaction_id.size());

        for (size_t i = 0; i < 16; ++i) {
            endpoint.ip.bytes[i] =
                value[4 + i] ^ mask[i];
        }

        return endpoint;
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Decode legacy MAPPED-ADDRESS
//
// This isn't normally needed for modern STUN servers because
// XOR-MAPPED-ADDRESS is the standard attribute. Keeping it here gives us
// compatibility with older implementations.
// ---------------------------------------------------------------------------

std::optional<uconnect::Endpoint> decode_mapped_address(
    std::span<const uint8_t> value)
{
    if (value.size() < 4)
        return std::nullopt;

    const uint8_t family = value[1];

    const uint16_t port =
        read_u16(value.data() + 2);

    uconnect::Endpoint endpoint;
    endpoint.port = port;

    // IPv4
    if (family == 0x01) {
        if (value.size() < 8)
            return std::nullopt;

        endpoint.ip = uconnect::IpAddr::v4(
            value[4],
            value[5],
            value[6],
            value[7]);

        return endpoint;
    }

    // IPv6
    if (family == 0x02) {
        if (value.size() < 20)
            return std::nullopt;

        endpoint.ip.family = uconnect::IpAddr::Family::V6;

        std::memcpy(
            endpoint.ip.bytes.data(),
            value.data() + 4,
            16);

        return endpoint;
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Parse Binding Success Response
// ---------------------------------------------------------------------------

std::optional<uconnect::Endpoint> parse_binding_response(
    std::span<const uint8_t> packet,
    const std::array<uint8_t, kTransactionIdSize>& transaction_id)
{
    if (packet.size() < kHeaderSize)
        return std::nullopt;

    // The first two bits of a STUN message must be zero.
    const uint16_t message_type =
        read_u16(packet.data());

    if ((message_type & 0xC000) != 0)
        return std::nullopt;

    if (message_type != kBindingSuccessResponse)
        return std::nullopt;

    const uint16_t message_length =
        read_u16(packet.data() + 2);

    // STUN message length describes everything after the 20-byte header.
    if (kHeaderSize + message_length > packet.size())
        return std::nullopt;

    const uint32_t magic_cookie =
        read_u32(packet.data() + 4);

    if (magic_cookie != kMagicCookie)
        return std::nullopt;

    // Transaction ID must match our request.
    if (std::memcmp(
            packet.data() + 8,
            transaction_id.data(),
            transaction_id.size()) != 0)
    {
        return std::nullopt;
    }

    const size_t end =
        kHeaderSize + message_length;

    size_t offset = kHeaderSize;

    while (offset + 4 <= end) {
        const uint16_t attribute_type =
            read_u16(packet.data() + offset);

        const uint16_t attribute_length =
            read_u16(packet.data() + offset + 2);

        offset += 4;

        if (offset + attribute_length > end)
            return std::nullopt;

        const auto value =
            std::span<const uint8_t>(
                packet.data() + offset,
                attribute_length);

        if (attribute_type == kXorMappedAddress) {
            if (auto endpoint =
                    decode_xor_mapped_address(
                        value,
                        transaction_id))
            {
                return endpoint;
            }
        }

        if (attribute_type == kMappedAddress) {
            if (auto endpoint =
                    decode_mapped_address(value))
            {
                return endpoint;
            }
        }

        // Attributes are padded to a 4-byte boundary.
        offset += attribute_length;
        offset = (offset + 3) & ~size_t(3);
    }

    return std::nullopt;
}

} // namespace

// ============================================================================
// Public API
// ============================================================================

std::optional<BindingResult> binding(
    uconnect::io::UdpSocket& socket,
    const uconnect::Endpoint& server,
    std::chrono::milliseconds timeout)
{
    if (!socket.is_open())
        return std::nullopt;

    // ------------------------------------------------------------------------
    // Generate transaction ID.
    // ------------------------------------------------------------------------

    const auto transaction_id =
        generate_transaction_id();

    // ------------------------------------------------------------------------
    // Build request.
    // ------------------------------------------------------------------------

    const auto request =
        make_binding_request(transaction_id);

    // ------------------------------------------------------------------------
    // Send using UdpSocket.
    // ------------------------------------------------------------------------

    if (!socket.send_to(
            server,
            std::span<const uint8_t>(
                request.data(),
                request.size())))
    {
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // Wait for packets until timeout.
    //
    // Important:
    //
    // The socket is shared. There could be unrelated packets arriving while
    // we're waiting for STUN. recv_from() is therefore called repeatedly and
    // packets that aren't our STUN response are simply ignored.
    // ------------------------------------------------------------------------

    const auto deadline =
        std::chrono::steady_clock::now() + timeout;

    std::array<uint8_t, 2048> buffer{};

    while (std::chrono::steady_clock::now() < deadline) {
        const auto now =
            std::chrono::steady_clock::now();

        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);

        if (remaining <= std::chrono::milliseconds::zero())
            break;

        if (!socket.wait_readable(remaining))
            break;

        for (;;) {
            auto received =
                socket.recv_from(
                    std::span<uint8_t>(
                        buffer.data(),
                        buffer.size()));

            if (!received)
                break;

            // Ignore packets that aren't from our STUN server.
            if (!(received->from == server))
                continue;

            const auto packet =
                std::span<const uint8_t>(
                    buffer.data(),
                    received->len);

            auto mapped =
                parse_binding_response(
                    packet,
                    transaction_id);

            if (!mapped)
                continue;

            return BindingResult{
                .mapped_endpoint = *mapped
            };
        }
    }

    return std::nullopt;
}

} // namespace stun
namespace stun {

const char* to_string(Mapping m)
{
    switch (m) {
        case Mapping::Open:                 return "open (no NAT)";
        case Mapping::EndpointIndependent:  return "endpoint-independent (cone)";
        case Mapping::EndpointDependent:    return "endpoint-dependent (symmetric)";
        case Mapping::Unknown:              return "unknown";
    }
    return "unknown";
}

NatReport probe_nat(uconnect::io::UdpSocket& socket,
                    std::chrono::milliseconds timeout)
{
    using namespace uconnect;

    NatReport report;
    report.local_port = socket.local_port();

    // Resolved by name, never hardcoded: these addresses are anycast and they
    // do change. A stale literal silently turns every probe into a timeout.
    static const char* kServers[] = {
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun.cloudflare.com:3478",
    };

    // Probe only genuinely DISTINCT destinations.
    //
    // stun.l.google.com and stun1.l.google.com frequently resolve to the same
    // anycast address. Querying both and finding the same mapped port proves
    // nothing about NAT behaviour -- it is one destination asked twice -- and
    // would let a symmetric NAT pass as endpoint-independent.
    std::vector<Endpoint> destinations;
    for (const char* host : kServers) {
        auto addr = io::resolve(host);
        if (!addr) continue;

        bool duplicate = false;
        for (const auto& d : destinations) {
            if (d == *addr) { duplicate = true; break; }
        }
        if (duplicate) continue;

        destinations.push_back(*addr);
    }

    for (const auto& dest : destinations) {
        auto res = binding(socket, dest, timeout);
        if (!res) continue;

        report.observed.push_back(res->mapped_endpoint);
    }

    if (report.observed.empty()) {
        report.mapping = Mapping::Unknown;
        return report;
    }

    report.port_preserved = report.observed.front().port == report.local_port;

    // A single reachable server cannot distinguish the two NAT behaviours: we
    // need at least two destinations to see whether the mapping changes.
    if (report.observed.size() < 2) {
        report.mapping = Mapping::Unknown;
        return report;
    }

    bool all_same = true;
    for (size_t i = 1; i < report.observed.size(); ++i) {
        if (!(report.observed[i] == report.observed[0])) {
            all_same = false;
            break;
        }
    }

    if (!all_same) {
        report.mapping = Mapping::EndpointDependent;
    } else if (report.observed[0].ip.is_private() ||
               report.observed[0].port == report.local_port) {
        // Same mapping everywhere. Whether there is a NAT at all is a separate
        // question from whether it is cone-shaped; either way punching works.
        report.mapping = Mapping::EndpointIndependent;
    } else {
        report.mapping = Mapping::EndpointIndependent;
    }

    return report;
}

} // namespace stun
