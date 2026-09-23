#include "udp_service.hpp"

#include <algorithm>
#include <chrono>
#include <span>
#include <utility>

namespace uconnect::server {
namespace {

std::vector<uint8_t> finish(wire::Writer& w, std::vector<uint8_t>& buf) {
    if (!w.ok()) return {};
    buf.resize(w.size());
    return buf;
}

}  // namespace

UdpService::UdpService(Store& store, ServiceConfig cfg) : store_(store), cfg_(cfg) {}

template <typename T>
Reply UdpService::encode(const Endpoint& to, wire::MsgType type, uint32_t txn_id, const T& msg,
                         uint8_t flags) {
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{type, wire::kVersion, flags, txn_id}.encode(w);
    msg.encode(w);
    return Reply{to, finish(w, buf)};
}

Reply UdpService::make_retry(const Endpoint& to, uint32_t txn_id, Instant now) {
    wire::Retry r;
    r.cookie = store_.make_cookie(to, now);
    return encode(to, wire::MsgType::Retry, txn_id, r);
}

Reply UdpService::make_error(const Endpoint& to, uint32_t txn_id, ErrorCode code) {
    wire::Error e;
    e.code   = code;
    e.reason = to_string(code);
    return encode(to, wire::MsgType::Error, txn_id, e);
}

namespace {

// Token bucket, shared by the two independent budgets below.
template <typename Bucket>
bool take_tokens(Bucket& b, size_t bytes, size_t rate, size_t burst, Instant now) {
    if (b.last == Instant{}) {
        b.tokens = static_cast<double>(burst);
        b.last   = now;
    }
    auto elapsed =
        std::chrono::duration_cast<std::chrono::duration<double>>(now - b.last).count();
    b.last = now;
    b.tokens += elapsed * static_cast<double>(rate);
    if (b.tokens > static_cast<double>(burst)) b.tokens = static_cast<double>(burst);
    if (b.tokens < static_cast<double>(bytes)) return false;
    b.tokens -= static_cast<double>(bytes);
    return true;
}

}  // namespace

bool UdpService::consume_budget(const Endpoint& from, size_t bytes, Instant now) {
    return take_tokens(buckets_[from.ip.bytes], bytes, cfg_.rate_bytes_per_sec,
                       cfg_.rate_burst_bytes, now);
}

// Relayed payload draws on a separate, larger budget. Sharing the signaling
// bucket capped every relayed transfer at the signaling rate -- slow with no
// error and no counter to explain it.
bool UdpService::consume_relay_budget(const Endpoint& from, size_t bytes, Instant now) {
    return take_tokens(relay_buckets_[from.ip.bytes], bytes, cfg_.relay_bytes_per_sec,
                       cfg_.relay_burst_bytes, now);
}

std::vector<Reply> UdpService::handle(const Endpoint& from, std::span<const uint8_t> dgram,
                                      Instant now) {
    std::vector<Reply> out;

    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h) return out;
    if (wire::classify(static_cast<uint8_t>(h->type)) != wire::MsgClass::Signaling) return out;

    // Cheap fixed cost for every request, so a flood of tiny messages still
    // draws down the budget.
    if (!consume_budget(from, 64, now)) {
        out.push_back(make_error(from, h->txn_id, ErrorCode::RateLimited));
        return out;
    }

    switch (h->type) {
        case wire::MsgType::Register: {
            auto m = wire::Register::decode(r, *h);
            if (!m) return out;
            if (!store_.validate_cookie(m->cookie, from, now)) {
                out.push_back(make_retry(from, h->txn_id, now));
                return out;
            }
            auto res = store_.register_entry(*m, from, now);
            if (res.code != ErrorCode::None) {
                out.push_back(make_error(from, h->txn_id, res.code));
                return out;
            }
            wire::RegisterOk ok;
            ok.dev_id         = res.dev_id;
            ok.lease_token    = res.lease_token;
            ok.srflx          = res.srflx;
            ok.peers_in_topic = res.peers_in_topic;
            ok.ttl_secs       = static_cast<uint16_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::seconds(90))
                    .count());
            out.push_back(encode(from, wire::MsgType::RegisterOk, h->txn_id, ok));
            return out;
        }

        case wire::MsgType::Keepalive: {
            auto m = wire::Keepalive::decode(r);
            if (!m) return out;
            auto res = store_.keepalive(m->dev_id, m->auth.seq, m->auth.authed, m->auth.mac,
                                        from, now);
            if (res.code != ErrorCode::None) {
                out.push_back(make_error(from, h->txn_id, res.code));
                return out;
            }
            wire::KeepaliveOk ok;
            ok.srflx      = res.srflx;
            ok.expires_in = 90;
            out.push_back(encode(from, wire::MsgType::KeepaliveOk, h->txn_id, ok));
            return out;
        }

        case wire::MsgType::Update: {
            auto m = wire::Update::decode(r);
            if (!m) return out;
            auto res = store_.update(*m, from, now);
            if (res.code != ErrorCode::None) {
                out.push_back(make_error(from, h->txn_id, res.code));
                return out;
            }
            wire::KeepaliveOk ok;
            ok.srflx      = res.srflx;
            ok.expires_in = 90;
            out.push_back(encode(from, wire::MsgType::UpdateOk, h->txn_id, ok));
            return out;
        }

        case wire::MsgType::Unregister: {
            auto m = wire::Unregister::decode(r);
            if (!m) return out;
            auto res = store_.unregister(m->dev_id, m->auth.seq, m->auth.authed, m->auth.mac,
                                         from, now);
            if (res.code != ErrorCode::None) {
                out.push_back(make_error(from, h->txn_id, res.code));
                return out;
            }
            wire::KeepaliveOk ok;
            ok.srflx = from;
            out.push_back(encode(from, wire::MsgType::UnregisterOk, h->txn_id, ok));
            return out;
        }

        case wire::MsgType::Lookup: {
            auto m = wire::Lookup::decode(r, *h);
            if (!m) return out;
            if (!store_.validate_cookie(m->cookie, from, now)) {
                out.push_back(make_retry(from, h->txn_id, now));
                return out;
            }
            auto res = store_.lookup(m->id, m->max, m->want_meta, now);

            // Page by accumulating encoded_size(). A full sample does not fit
            // in one datagram once IPv6 candidates or metadata are involved,
            // and guessing a fixed entry count silently truncates.
            const size_t prefix = wire::Header::kSize + kTopicIdLen + 1 + 2 + 1 + 1 + 1;
            std::vector<std::vector<wire::PeerEntry>> pages;
            std::vector<wire::PeerEntry>              cur;
            size_t                                    used = prefix;
            for (auto& e : res.entries) {
                size_t sz = e.encoded_size();
                if (!cur.empty() && used + sz > wire::kMaxDatagram) {
                    pages.push_back(std::move(cur));
                    cur.clear();
                    used = prefix;
                }
                used += sz;
                cur.push_back(std::move(e));
            }
            if (!cur.empty()) pages.push_back(std::move(cur));
            if (pages.empty()) pages.emplace_back();
            if (pages.size() > cfg_.max_pages) pages.resize(cfg_.max_pages);

            for (size_t i = 0; i < pages.size(); ++i) {
                wire::LookupOk ok;
                ok.id      = m->id;
                ok.mode    = res.mode;
                ok.total   = res.total;
                ok.part    = static_cast<uint8_t>(i);
                ok.parts   = static_cast<uint8_t>(pages.size());
                ok.entries = std::move(pages[i]);
                auto reply = encode(from, wire::MsgType::LookupOk, h->txn_id, ok);
                if (!consume_budget(from, reply.data.size(), now)) break;
                out.push_back(std::move(reply));
            }
            return out;
        }

        case wire::MsgType::Resolve: {
            auto m = wire::Resolve::decode(r);
            if (!m) return out;
            if (!store_.validate_cookie(m->cookie, from, now)) {
                out.push_back(make_retry(from, h->txn_id, now));
                return out;
            }
            auto got = store_.resolve(m->dev_id, now);
            wire::ResolveOk ok;
            if (got) {
                ok.found = true;
                ok.topic = got->first;
                ok.entry = got->second;
            }
            out.push_back(encode(from, wire::MsgType::ResolveOk, h->txn_id, ok));
            return out;
        }

        case wire::MsgType::Topics: {
            auto m = wire::Topics::decode(r);
            if (!m) return out;
            if (!store_.validate_cookie(m->cookie, from, now)) {
                out.push_back(make_retry(from, h->txn_id, now));
                return out;
            }
            auto res = store_.list_topics(m->cursor, m->limit, now);

            const size_t prefix    = wire::Header::kSize + 4 + 1 + 1 + 1;
            const size_t per_topic = kTopicIdLen + 1 + 4 + 4;
            const size_t per_page  = (wire::kMaxDatagram - prefix) / per_topic;

            size_t pages = res.topics.empty() ? 1 : (res.topics.size() + per_page - 1) / per_page;
            for (size_t i = 0; i < pages && i < cfg_.max_pages; ++i) {
                wire::TopicsOk ok;
                ok.next_cursor = res.next_cursor;
                ok.part        = static_cast<uint8_t>(i);
                ok.parts       = static_cast<uint8_t>(pages);
                size_t begin   = i * per_page;
                size_t end     = std::min(begin + per_page, res.topics.size());
                for (size_t j = begin; j < end; ++j) ok.topics.push_back(res.topics[j]);
                auto reply = encode(from, wire::MsgType::TopicsOk, h->txn_id, ok);
                if (!consume_budget(from, reply.data.size(), now)) break;
                out.push_back(std::move(reply));
            }
            return out;
        }

        case wire::MsgType::Connect: {
            auto m = wire::Connect::decode(r);
            if (!m) return out;
            auto target = store_.relay_target(m->from_dev, m->to_dev, m->auth.seq,
                                              m->auth.authed, m->auth.mac, from, now);
            if (!target) {
                out.push_back(make_error(from, h->txn_id, ErrorCode::NotFound));
                return out;
            }
            wire::Relayed rel;
            rel.from_dev = m->from_dev;
            rel.payload  = m->payload;
            out.push_back(encode(*target, wire::MsgType::Relayed, h->txn_id, rel));
            return out;
        }

        case wire::MsgType::RelayAlloc: {
            auto m = wire::RelayAlloc::decode(r);
            if (!m) return out;
            // Authenticated with the requester's lease token, exactly like
            // CONNECT: only a registered peer may open a relay, and only for
            // someone in its own topic.
            auto target = store_.relay_target(m->from_dev, m->peer_dev, m->auth.seq,
                                              m->auth.authed, m->auth.mac, from, now);
            if (!target) {
                out.push_back(make_error(from, h->txn_id, ErrorCode::BadAuth));
                return out;
            }
            auto res = store_.relay_alloc(m->from_dev, m->peer_dev, from, now);
            if (res.code != ErrorCode::None) {
                out.push_back(make_error(from, h->txn_id, res.code));
                return out;
            }
            wire::RelayAllocOk ok;
            ok.relay_id   = res.relay_id;
            ok.expires_in = 90;
            ok.max_kib    = res.max_kib;
            out.push_back(encode(from, wire::MsgType::RelayAllocOk, h->txn_id, ok));
            return out;
        }

        case wire::MsgType::RelayData: {
            auto m = wire::RelayData::decode(r);
            if (!m) return out;

            auto dst = store_.relay_forward(m->relay_id, from, m->payload.size(), now);
            if (!dst) return out;  // unknown, exhausted, or a stranger: drop silently

            // Charge relayed bytes against the sender's rate budget. Forwarding
            // is not amplification -- the reply goes to a third party, not back
            // to a potentially spoofed source -- but it is the one path where
            // the server spends bandwidth on someone else's behalf.
            if (!consume_relay_budget(from, m->payload.size(), now)) return out;

            wire::RelayData fwd;
            fwd.relay_id = m->relay_id;
            fwd.payload  = std::move(m->payload);
            out.push_back(encode(*dst, wire::MsgType::RelayData, h->txn_id, fwd));
            return out;
        }

        case wire::MsgType::Stats: {
            auto m = wire::Stats::decode(r);
            if (!m) return out;
            if (!store_.validate_cookie(m->cookie, from, now)) {
                out.push_back(make_retry(from, h->txn_id, now));
                return out;
            }
            auto st = store_.stats(now);
            // Encoded as a compact fixed record; the HTTP front end renders the
            // same numbers as JSON.
            std::vector<uint8_t> buf(wire::kMaxDatagram);
            wire::Writer         w{buf};
            wire::Header{wire::MsgType::StatsOk, wire::kVersion, 0, h->txn_id}.encode(w);
            w.u64(st.topics_total);
            w.u64(st.topics_listed);
            w.u64(st.entries_total);
            w.u64(st.entries_fresh);
            w.u64(st.registers);
            w.u64(st.keepalives);
            w.u64(st.lookups);
            w.u64(st.connects);
            w.u64(st.rebinds);
            w.u64(st.expired);
            w.u64(st.rej_bad_auth);
            w.u64(st.rej_quota);
            w.u64(st.rej_rate_limited);
            w.u64(st.relays_open);
            w.u64(st.relays_allocated);
            w.u64(st.relay_bytes);
            out.push_back(Reply{from, finish(w, buf)});
            return out;
        }

        default:
            return out;
    }
}

void UdpService::tick(Instant now) {
    store_.sweep(now);

    // Prune idle rate-limit state so a long-running server does not accumulate
    // a bucket per address it has ever seen.
    for (auto it = buckets_.begin(); it != buckets_.end();) {
        if (now - it->second.last > std::chrono::minutes(5)) it = buckets_.erase(it);
        else ++it;
    }
}

}  // namespace uconnect::server
