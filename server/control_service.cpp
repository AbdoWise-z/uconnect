#include "control_service.hpp"

namespace uconnect::server {
namespace ctl = wire::ctl;
using wire::MsgType;

namespace {

template <typename T>
Framed reply(ConnKey to, MsgType type, uint32_t txn, const T& body, uint8_t flags = 0) {
    return Framed{to, ctl::frame(ctl::message(type, txn, body, flags))};
}

Framed reply_empty(ConnKey to, MsgType type, uint32_t txn) {
    return Framed{to, ctl::frame(ctl::empty_message(type, txn))};
}

Framed error(ConnKey to, uint32_t txn, ErrorCode code) {
    wire::Error e;
    e.code   = code;
    e.reason = to_string(code);
    return reply(to, MsgType::Error, txn, e);
}

// A UDP message in v2 framing: no length prefix, one per datagram.
template <typename T>
std::vector<uint8_t> udp_message(MsgType type, uint32_t txn, const T& body) {
    return ctl::message(type, txn, body);
}

}  // namespace

ControlService::ControlService(Registry& reg, ControlConfig cfg) : reg_(reg), cfg_(cfg) {}

bool ControlService::take(Bucket& b, size_t bytes, size_t rate, size_t burst, Instant now) {
    if (b.last == Instant{}) {
        b.tokens = static_cast<double>(burst);
        b.last   = now;
    }
    const double elapsed = std::chrono::duration<double>(now - b.last).count();
    b.last               = now;
    b.tokens = std::min(static_cast<double>(burst), b.tokens + elapsed * static_cast<double>(rate));
    if (b.tokens < static_cast<double>(bytes)) return false;
    b.tokens -= static_cast<double>(bytes);
    return true;
}

void ControlService::on_open(ConnKey key, const Endpoint& peer, Instant now) {
    Conn c;
    c.peer = peer;
    take(c.budget, 0, cfg_.rate_bytes_per_sec, cfg_.rate_burst_bytes, now);
    conns_[key] = c;
}

void ControlService::on_close(ConnKey key) {
    conns_.erase(key);
    reg_.drop_owner(key);
}

ControlService::Result ControlService::on_message(ConnKey key, std::span<const uint8_t> msg,
                                                  Instant now) {
    Result out;
    auto   cit = conns_.find(key);
    if (cit == conns_.end()) {
        out.close = true;
        return out;
    }
    auto& conn = cit->second;

    // Over its budget, a connection is closed rather than answered: it is a
    // real TCP peer, so dropping it costs nothing and helps nobody abuse us.
    if (!take(conn.budget, msg.size() + kMessageOverhead, cfg_.rate_bytes_per_sec,
              cfg_.rate_burst_bytes, now)) {
        ++rej_rate_limited_;
        out.close = true;
        return out;
    }

    wire::Reader r{msg};
    auto         h = wire::Header::decode(r, ctl::kVersion);
    if (!h) {
        out.close = true;  // not our protocol; framing is intact but trust is not
        return out;
    }
    const uint32_t txn = h->txn_id;

    switch (h->type) {
        case MsgType::Register: {
            auto m = ctl::Register::decode(r, *h);
            if (!m) break;
            auto res = reg_.register_entry(*m, conn.peer, key, now);
            if (res.code != ErrorCode::None) {
                out.out.push_back(error(key, txn, res.code));
            } else {
                out.out.push_back(reply(key, MsgType::RegisterOk, txn,
                                        ctl::RegisterOk{res.dev_id, res.srflx, res.peers_in_topic}));
            }
            return out;
        }
        case MsgType::Keepalive: {
            // With no body it keeps the connection itself alive: a node with
            // nothing published still needs its connection, so the server
            // can introduce peers to it and it can learn its address.
            if (r.remaining() == 0) {
                out.out.push_back(reply(key, MsgType::KeepaliveOk, txn, ctl::KeepaliveOk{conn.peer}));
                return out;
            }
            auto m = ctl::DevRef::decode(r);
            if (!m) break;
            auto code = reg_.refresh(m->dev_id, key, now);
            if (code != ErrorCode::None) out.out.push_back(error(key, txn, code));
            else out.out.push_back(reply(key, MsgType::KeepaliveOk, txn, ctl::KeepaliveOk{conn.peer}));
            return out;
        }
        case MsgType::Update: {
            auto m = ctl::Update::decode(r);
            if (!m) break;
            auto code = reg_.update(*m, key, now);
            if (code != ErrorCode::None) out.out.push_back(error(key, txn, code));
            else out.out.push_back(reply_empty(key, MsgType::UpdateOk, txn));
            return out;
        }
        case MsgType::Unregister: {
            auto m = ctl::DevRef::decode(r);
            if (!m) break;
            auto code = reg_.unregister(m->dev_id, key);
            if (code != ErrorCode::None) out.out.push_back(error(key, txn, code));
            else out.out.push_back(reply_empty(key, MsgType::UnregisterOk, txn));
            return out;
        }
        case MsgType::Lookup: {
            auto m = ctl::Lookup::decode(r, *h);
            if (!m) break;
            auto         res = reg_.lookup(m->id, m->max, m->want_meta, now);
            ctl::LookupOk ok;
            ok.id      = m->id;
            ok.mode    = res.mode;
            ok.total   = res.total;
            ok.entries = std::move(res.entries);
            out.out.push_back(reply(key, MsgType::LookupOk, txn, ok));
            return out;
        }
        case MsgType::Resolve: {
            auto m = ctl::Resolve::decode(r);
            if (!m) break;
            wire::ResolveOk ok;
            if (auto got = reg_.resolve(m->dev_id, now)) {
                ok.found = true;
                ok.topic = got->first;
                ok.entry = got->second;
            }
            out.out.push_back(reply(key, MsgType::ResolveOk, txn, ok));
            return out;
        }
        case MsgType::Topics: {
            auto m = ctl::Topics::decode(r);
            if (!m) break;
            auto         res = reg_.list_topics(m->cursor, m->limit, now);
            ctl::TopicsOk ok;
            ok.next_cursor = res.next_cursor;
            ok.topics      = std::move(res.topics);
            out.out.push_back(reply(key, MsgType::TopicsOk, txn, ok));
            return out;
        }
        case MsgType::Stats: {
            const auto   s = reg_.stats(now);
            ctl::StatsOk ok;
            ok.topics_total     = s.topics_total;
            ok.topics_listed    = s.topics_listed;
            ok.entries_total    = s.entries_total;
            ok.entries_fresh    = s.entries_fresh;
            ok.registers        = s.registers;
            ok.lookups          = s.lookups;
            ok.connects         = s.connects;
            ok.expired          = s.expired;
            ok.rej_quota        = s.rej_quota;
            ok.rej_rate_limited = rej_rate_limited_;
            ok.relays_open      = s.relays_open;
            ok.relays_allocated = s.relays_allocated;
            ok.relay_bytes      = s.relay_bytes;
            ok.connections      = conns_.size();
            out.out.push_back(reply(key, MsgType::StatsOk, txn, ok));
            return out;
        }
        case MsgType::Connect: {
            auto m = ctl::Connect::decode(r);
            if (!m) break;
            auto target = reg_.connect_target(m->from_dev, m->to_dev, key);
            if (!target) {
                out.out.push_back(error(key, txn, ErrorCode::NotFound));
                return out;
            }
            wire::Relayed rel;
            rel.from_dev = m->from_dev;
            rel.payload  = m->payload;
            out.out.push_back(reply(*target, MsgType::Relayed, 0, rel));
            return out;
        }
        case MsgType::RelayAlloc: {
            auto m = ctl::RelayAlloc::decode(r);
            if (!m) break;
            auto g = reg_.relay_alloc(m->from_dev, m->peer_dev, m->kind, key, conn.peer, now);
            if (g.code != ErrorCode::None) {
                out.out.push_back(error(key, txn, g.code));
                return out;
            }
            out.out.push_back(reply(key, MsgType::RelayAllocOk, txn,
                                    ctl::RelayAllocOk{g.id, g.token, m->kind, g.max_kib}));
            // The peer learns of the binding from the server, with its own
            // token -- nothing the requester could forge or withhold.
            out.out.push_back(reply(g.peer_owner, MsgType::RelayOffer, 0,
                                    ctl::RelayOffer{g.id, g.peer_token, m->kind, m->from_dev,
                                                    g.topic}));
            return out;
        }
        default:
            out.out.push_back(error(key, txn, ErrorCode::Unsupported));
            return out;
    }

    // A known type that failed to decode.
    out.out.push_back(error(key, txn, ErrorCode::BadRequest));
    return out;
}

std::vector<UdpOut> ControlService::on_udp(const Endpoint& from, std::span<const uint8_t> dgram,
                                           Instant now) {
    std::vector<UdpOut> out;
    if (!take(udp_buckets_[from.ip.bytes], dgram.size(), cfg_.udp_bytes_per_sec,
              cfg_.udp_burst_bytes, now)) {
        return out;  // over budget: silence, never an error to an unvalidated address
    }

    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r, ctl::kVersion);
    if (!h) return out;

    switch (h->type) {
        case MsgType::WhoAmI: {
            auto m = ctl::WhoAmI::decode(r);
            if (!m) return out;
            auto rep = udp_message(MsgType::WhoAmIOk, h->txn_id, ctl::WhoAmIOk{m->nonce, from});
            // Nothing validated this address: never answer with more than
            // arrived. An honest client pads to kWhoAmISize.
            if (rep.size() <= dgram.size()) out.push_back({from, std::move(rep)});
            return out;
        }
        case MsgType::UdpRelayBind: {
            auto m = ctl::UdpRelayBind::decode(r);
            if (!m || !reg_.udp_bind(m->relay_id, m->token, from, now)) return out;
            out.push_back({from, udp_message(MsgType::UdpRelayBindOk, h->txn_id,
                                             ctl::UdpRelayBindOk{m->relay_id})});
            return out;
        }
        case MsgType::RelayData: {
            auto m = wire::RelayData::decode(r);
            if (!m) return out;
            auto dst = reg_.udp_forward(m->relay_id, from, m->payload.size(), now);
            if (!dst) return out;  // unknown, unbound, a stranger, or spent: drop
            out.push_back({*dst, udp_message(MsgType::RelayData, 0, *m)});
            return out;
        }
        default:
            return out;
    }
}

void ControlService::tick(Instant now) {
    reg_.sweep(now);
    for (auto it = udp_buckets_.begin(); it != udp_buckets_.end();) {
        if (now - it->second.last > std::chrono::minutes(5)) it = udp_buckets_.erase(it);
        else ++it;
    }
}

}  // namespace uconnect::server
