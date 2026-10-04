#include "control_service.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::server;
using namespace std::chrono_literals;
namespace ctl = wire::ctl;

TEST(issue70_udp_source_buckets_have_a_hard_bound) {
    Registry registry;
    ControlConfig config;
    config.max_udp_sources = 8;
    ControlService service{registry, config};
    auto now = Instant{} + 100s;
    const auto request = ctl::message(wire::MsgType::WhoAmI, 1, ctl::WhoAmI{42});
    for (unsigned i = 1; i < 200; ++i)
        service.on_udp({IpAddr::v4(10, 0, 0, static_cast<uint8_t>(i)), 5000}, request, now);
    CHECK_EQ(service.udp_sources(), 8u);
    CHECK(!service.on_udp({IpAddr::v4(10, 0, 0, 1), 5000}, request, now).empty());
    service.tick(now + 301s);
    CHECK_EQ(service.udp_sources(), 0u);
    CHECK(!service.on_udp({IpAddr::v4(10, 0, 1, 1), 5000}, request, now + 301s).empty());
}

TEST(issue58_large_lookup_fits_the_control_frame) {
    for (bool ipv6 : {false, true}) {
        Registry registry{{}, crypto::SymKey{}, 123};
        ControlService service{registry};
        const auto now = Instant{} + 100s;
        TopicId topic{};
        for (unsigned i = 1; i <= 100; ++i) {
            ctl::Register req;
            req.id = topic;
            req.meta.assign(256, 42);
            Endpoint source{IpAddr::v4(10, 0, 0, static_cast<uint8_t>(i)), 4000};
            if (ipv6) {
                source.ip.family = IpAddr::Family::V6;
                source.ip.bytes[15] = static_cast<uint8_t>(i);
            }
            for (unsigned j = 0; j < 7; ++j)
                req.host_cands.push_back({Candidate::Kind::Host, source});
            REQUIRE(registry.register_entry(req, source, i, now).code == ErrorCode::None);
        }
        service.on_open(101, {IpAddr::v4(127, 0, 0, 1), 5000}, now);
        ctl::Lookup query;
        query.id = topic;
        query.max = 100;
        query.want_meta = true;
        auto result = service.on_message(101, ctl::message(wire::MsgType::Lookup, 7, query,
                                                         wire::flags::kWantMeta), now);
        REQUIRE(result.out.size() == 1);
        ctl::FrameReader frames;
        REQUIRE(frames.feed(result.out[0].bytes));
        auto message = frames.next();
        REQUIRE(message && !message->empty());
        CHECK(message->size() <= ctl::kMaxFrame);
        wire::Reader reader{*message};
        auto header = wire::Header::decode(reader, ctl::kVersion);
        REQUIRE(header && header->type == wire::MsgType::LookupOk);
        auto reply = ctl::LookupOk::decode(reader);
        REQUIRE(reply);
        CHECK_EQ(reply->total, 100u);
        CHECK(!reply->entries.empty());
        for (const auto& entry : reply->entries) CHECK_EQ(entry.meta.size(), 256u);
    }
}
