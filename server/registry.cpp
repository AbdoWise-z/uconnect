#include "registry.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace uconnect::server {
namespace {

constexpr std::string_view kDevIdInfo = "uconnect:v2:devid";

void append_endpoint(std::vector<uint8_t>& v, const Endpoint& ep) {
    v.push_back(static_cast<uint8_t>(ep.ip.family));
    v.insert(v.end(), ep.ip.bytes.begin(), ep.ip.bytes.begin() + ep.ip.addr_len());
    v.push_back(static_cast<uint8_t>(ep.port >> 8));
    v.push_back(static_cast<uint8_t>(ep.port));
}

template <typename Map, typename Key>
void decrement(Map& m, const Key& k) {
    auto it = m.find(k);
    if (it == m.end()) return;
    if (it->second <= 1) m.erase(it);
    else --it->second;
}

}  // namespace

Registry::Registry(RegistryConfig cfg) : cfg_(cfg) {
    crypto::random_bytes(secret_);
    auto     s    = crypto::random_array<8>();
    uint64_t seed = 0;
    for (uint8_t b : s) seed = seed << 8 | b;
    sampler_.seed(seed);
}

Registry::Registry(RegistryConfig cfg, const crypto::SymKey& secret, uint64_t sample_seed)
    : cfg_(cfg), secret_(secret), sampler_(sample_seed) {}

DevId Registry::derive_dev_id(const TopicId& topic, const Endpoint& ep) const {
    std::vector<uint8_t> input(kDevIdInfo.begin(), kDevIdInfo.end());
    input.insert(input.end(), topic.begin(), topic.end());
    append_endpoint(input, ep);
    crypto::Hash h = crypto::Blake2s::mac(secret_, input);
    DevId        out{};
    std::memcpy(out.data(), h.data(), kDevIdLen);
    return out;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------
Registry::RegisterResult Registry::register_entry(const wire::ctl::Register& msg,
                                                  const Endpoint& src, ConnKey owner,
                                                  Instant now) {
    RegisterResult out;
    out.srflx = src;

    const DevId dev      = derive_dev_id(msg.id, src);
    out.dev_id           = dev;
    auto        existing = by_dev_.find(dev);

    if (existing != by_dev_.end() && existing->second.owner != owner) {
        // The same topic and address, registered by a different connection:
        // the device reconnected and this is its new control connection. The
        // TCP handshake has shown the new one holds the address, so it takes
        // the record over.
        auto& list = by_owner_[existing->second.owner];
        list.erase(std::remove(list.begin(), list.end(), dev), list.end());
        existing->second.owner = owner;
        by_owner_[owner].push_back(dev);
    }

    if (existing == by_dev_.end()) {
        if (by_dev_.size() >= cfg_.max_entries) {
            ++stats_.rej_quota;
            out.code = ErrorCode::QuotaExceeded;
            return out;
        }
        const auto ik    = ip_key(src);
        auto       total = per_ip_total_.find(ik);
        if (total != per_ip_total_.end() && total->second >= cfg_.max_per_ip_total) {
            ++stats_.rej_quota;
            out.code = ErrorCode::QuotaExceeded;
            return out;
        }
        auto tit = topics_.find(msg.id);
        if (tit != topics_.end()) {
            auto c = tit->second.per_ip.find(ik);
            if (c != tit->second.per_ip.end() && c->second >= cfg_.max_per_ip_per_topic) {
                ++stats_.rej_quota;
                out.code = ErrorCode::QuotaExceeded;
                return out;
            }
        } else if (topics_.size() >= cfg_.max_topics) {
            ++stats_.rej_quota;
            out.code = ErrorCode::QuotaExceeded;
            return out;
        }

        auto& topic = topics_[msg.id];
        if (topic.members.empty()) {
            // A new topic. The mode is fixed now, by whoever created it: a
            // later registrant cannot relabel a keyed topic as open (#30).
            topic.mode  = msg.mode;
            topic.order = next_order_++;
            listing_[topic.order] = msg.id;
        }
        topic.pos[dev] = topic.members.size();
        topic.members.push_back(dev);
        topic.per_ip[ik]++;
        per_ip_total_[ik]++;
        by_owner_[owner].push_back(dev);
    }

    Entry& e     = by_dev_[dev];
    e.dev_id     = dev;
    e.topic_id   = msg.id;
    e.bound_addr = src;
    e.host_cands = msg.host_cands;
    e.meta       = msg.meta;
    e.owner      = owner;
    e.last_seen  = now;
    e.key_epoch  = msg.key_epoch;
    e.mode       = msg.mode;

    auto& topic = topics_[msg.id];
    // Hiding is sticky and topic-wide: the two mistakes are not symmetric, and
    // a topic wrongly exposed cannot be taken back.
    if (msg.unlisted) topic.listed = false;

    out.peers_in_topic = static_cast<uint16_t>(std::min<size_t>(topic.members.size(), 0xFFFF));
    ++stats_.registers;
    return out;
}

ErrorCode Registry::refresh(const DevId& dev, ConnKey owner, Instant now) {
    auto it = by_dev_.find(dev);
    if (it == by_dev_.end()) return ErrorCode::NotFound;
    if (it->second.owner != owner) return ErrorCode::BadAuth;
    it->second.last_seen = now;
    return ErrorCode::None;
}

ErrorCode Registry::update(const wire::ctl::Update& msg, ConnKey owner, Instant now) {
    auto it = by_dev_.find(msg.dev_id);
    if (it == by_dev_.end()) return ErrorCode::NotFound;
    if (it->second.owner != owner) return ErrorCode::BadAuth;
    it->second.host_cands = msg.host_cands;
    it->second.meta       = msg.meta;
    it->second.last_seen  = now;
    return ErrorCode::None;
}

ErrorCode Registry::unregister(const DevId& dev, ConnKey owner) {
    auto it = by_dev_.find(dev);
    if (it == by_dev_.end()) return ErrorCode::NotFound;
    if (it->second.owner != owner) return ErrorCode::BadAuth;
    auto& list = by_owner_[owner];
    list.erase(std::remove(list.begin(), list.end(), dev), list.end());
    if (list.empty()) by_owner_.erase(owner);
    erase_entry(dev);
    return ErrorCode::None;
}

size_t Registry::drop_owner(ConnKey owner) {
    size_t dropped = 0;
    if (auto it = by_owner_.find(owner); it != by_owner_.end()) {
        for (const DevId& dev : it->second) {
            erase_entry(dev);
            ++dropped;
        }
        by_owner_.erase(it);
    }
    // A relay whose either side has gone can carry nothing more.
    for (auto it = relays_.begin(); it != relays_.end();) {
        if (it->second.owner[0] == owner || it->second.owner[1] == owner) {
            auto dead = it++;
            release_relay(dead);
        } else {
            ++it;
        }
    }
    stats_.expired += dropped;
    return dropped;
}

void Registry::erase_entry(const DevId& dev) {
    auto it = by_dev_.find(dev);
    if (it == by_dev_.end()) return;
    const auto ik = ip_key(it->second.bound_addr);

    if (auto tit = topics_.find(it->second.topic_id); tit != topics_.end()) {
        auto& t   = tit->second;
        auto  pit = t.pos.find(dev);
        if (pit != t.pos.end()) {
            const size_t idx  = pit->second;
            const size_t last = t.members.size() - 1;
            if (idx != last) {
                t.members[idx]        = t.members[last];
                t.pos[t.members[idx]] = idx;
            }
            t.members.pop_back();
            t.pos.erase(pit);
        }
        decrement(t.per_ip, ik);
        if (t.members.empty()) {
            listing_.erase(t.order);
            topics_.erase(tit);
        }
    }
    decrement(per_ip_total_, ik);
    by_dev_.erase(it);
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------
wire::PeerEntry Registry::to_entry(const Entry& e, bool want_meta, Instant now) const {
    wire::PeerEntry p;
    p.dev_id       = e.dev_id;
    const auto age = std::chrono::duration_cast<std::chrono::seconds>(now - e.last_seen).count();
    p.age_secs     = static_cast<uint16_t>(std::clamp<long long>(age, 0, 0xFFFF));
    p.stale        = !is_fresh(e, now);
    // The observed TCP address first -- it is the one most peers need -- then
    // the node's own, for peers behind the same NAT.
    p.cands.push_back(Candidate{Candidate::Kind::Srflx, e.bound_addr});
    for (const auto& c : e.host_cands) {
        if (p.cands.size() >= wire::kMaxCandidates) break;
        p.cands.push_back(c);
    }
    if (want_meta) p.meta = e.meta;
    return p;
}

Registry::LookupResult Registry::lookup(const TopicId& topic, uint8_t max, bool want_meta,
                                        Instant now) {
    ++stats_.lookups;
    LookupResult out;
    auto         tit = topics_.find(topic);
    if (tit == topics_.end()) return out;

    out.mode             = tit->second.mode;
    const auto& members  = tit->second.members;
    out.total            = static_cast<uint16_t>(std::min<size_t>(members.size(), 0xFFFF));
    if (max == 0) max = wire::kLookupDefault;
    if (max > wire::kLookupMax) max = wire::kLookupMax;

    const size_t        n    = members.size();
    const size_t        want = std::min<size_t>(max, n);
    std::vector<size_t> picked;
    picked.reserve(want);
    if (want == n) {
        for (size_t i = 0; i < n; ++i) picked.push_back(i);
    } else if (n < want * 4) {
        std::vector<size_t> idx(n);
        for (size_t i = 0; i < n; ++i) idx[i] = i;
        std::shuffle(idx.begin(), idx.end(), sampler_);
        picked.assign(idx.begin(), idx.begin() + static_cast<ptrdiff_t>(want));
    } else {
        std::unordered_set<size_t>            seen;
        std::uniform_int_distribution<size_t> dist(0, n - 1);
        while (seen.size() < want) {
            size_t i = dist(sampler_);
            if (seen.insert(i).second) picked.push_back(i);
        }
    }

    // Fresh entries first, so a client dials live peers before stale ones.
    std::vector<const Entry*> fresh, stale;
    for (size_t i : picked) {
        auto it = by_dev_.find(members[i]);
        if (it == by_dev_.end()) continue;
        (is_fresh(it->second, now) ? fresh : stale).push_back(&it->second);
    }
    for (const auto* e : fresh) out.entries.push_back(to_entry(*e, want_meta, now));
    for (const auto* e : stale) out.entries.push_back(to_entry(*e, want_meta, now));
    return out;
}

std::optional<std::pair<TopicId, wire::PeerEntry>> Registry::resolve(const DevId& dev,
                                                                     Instant now) {
    auto it = by_dev_.find(dev);
    if (it == by_dev_.end()) return std::nullopt;
    return std::make_pair(it->second.topic_id, to_entry(it->second, true, now));
}

Registry::TopicsResult Registry::list_topics(uint32_t cursor, uint8_t limit, Instant now) {
    TopicsResult out;
    if (limit == 0) limit = 100;
    auto it = listing_.lower_bound(cursor);
    for (; it != listing_.end() && out.topics.size() < limit; ++it) {
        auto tit = topics_.find(it->second);
        if (tit == topics_.end() || !tit->second.listed) continue;
        wire::TopicSummary s;
        s.id    = it->second;
        s.mode  = tit->second.mode;
        s.peers = static_cast<uint32_t>(tit->second.members.size());
        uint32_t fresh = 0;
        for (const auto& m : tit->second.members) {
            auto e = by_dev_.find(m);
            if (e != by_dev_.end() && is_fresh(e->second, now)) ++fresh;
        }
        s.fresh_peers = fresh;
        out.topics.push_back(s);
    }
    // The cursor is a position in creation order, not an index, so it stays
    // valid however many topics before it disappear in the meantime.
    out.next_cursor = it == listing_.end() ? 0 : it->first;
    return out;
}

std::optional<ConnKey> Registry::connect_target(const DevId& from, const DevId& to,
                                                ConnKey owner) {
    auto fit = by_dev_.find(from);
    auto tit = by_dev_.find(to);
    if (fit == by_dev_.end() || tit == by_dev_.end()) return std::nullopt;
    if (fit->second.owner != owner) return std::nullopt;
    if (!(fit->second.topic_id == tit->second.topic_id)) return std::nullopt;
    ++stats_.connects;
    return tit->second.owner;
}

// ---------------------------------------------------------------------------
// Relays
// ---------------------------------------------------------------------------
Registry::RelayGrant Registry::relay_alloc(const DevId& from, const DevId& peer,
                                           wire::ctl::RelayKind kind, ConnKey owner,
                                           const Endpoint& src, Instant now) {
    RelayGrant out;
    out.max_kib = static_cast<uint32_t>(cfg_.relay_max_bytes / 1024);
    if (!cfg_.relay_enabled) {
        out.code = ErrorCode::Unsupported;
        return out;
    }

    auto fit = by_dev_.find(from);
    auto pit = by_dev_.find(peer);
    if (fit == by_dev_.end() || pit == by_dev_.end()) {
        out.code = ErrorCode::NotFound;
        return out;
    }
    if (fit->second.owner != owner) {
        out.code = ErrorCode::BadAuth;
        return out;
    }
    if (!(fit->second.topic_id == pit->second.topic_id)) {
        out.code = ErrorCode::BadRequest;
        return out;
    }

    // An existing binding for this pair and kind, from either side, is
    // returned rather than duplicated -- checked before the quota, so asking
    // again for what you already hold is never refused for it.
    for (auto& [id, r] : relays_) {
        if (r.kind != kind) continue;
        int side = -1;
        if (r.dev[0] == from && r.dev[1] == peer) side = 0;
        if (r.dev[1] == from && r.dev[0] == peer) side = 1;
        if (side < 0) continue;
        if (r.exhausted) {
            // Spent: refused, not handed back to carry nothing.
            ++stats_.rej_quota;
            out.code = ErrorCode::QuotaExceeded;
            return out;
        }
        r.last_seen    = now;
        out.id         = id;
        out.token      = r.token[side];
        out.peer_token = r.token[1 - side];
        out.peer_owner = r.owner[1 - side];
        out.topic      = r.topic;
        return out;
    }

    const auto ik = ip_key(src);
    auto       c  = relays_per_ip_.find(ik);
    if (relays_.size() >= cfg_.max_relays ||
        (c != relays_per_ip_.end() && c->second >= cfg_.max_relays_per_ip)) {
        ++stats_.rej_quota;
        out.code = ErrorCode::QuotaExceeded;
        return out;
    }

    Relay r;
    do {
        auto rb = crypto::random_array<8>();
        r.id    = 0;
        for (uint8_t b : rb) r.id = r.id << 8 | b;
    } while (r.id == 0 || relays_.count(r.id));
    r.kind       = kind;
    r.topic      = fit->second.topic_id;
    r.dev[0]     = from;
    r.dev[1]     = peer;
    r.owner[0]   = owner;
    r.owner[1]   = pit->second.owner;
    crypto::random_bytes(r.token[0]);
    crypto::random_bytes(r.token[1]);
    r.counted_ip = ik;  // released under this same key, whatever happens next
    r.last_seen  = now;

    out.id         = r.id;
    out.token      = r.token[0];
    out.peer_token = r.token[1];
    out.peer_owner = r.owner[1];
    out.topic      = r.topic;

    relays_.emplace(r.id, r);
    relays_per_ip_[ik]++;
    ++stats_.relays_allocated;
    return out;
}

std::optional<int> Registry::relay_side(wire::RelayId id,
                                        const wire::ctl::RelayToken& token) const {
    auto it = relays_.find(id);
    if (it == relays_.end()) return std::nullopt;
    for (int side = 0; side < 2; ++side) {
        if (crypto::ct_equal(it->second.token[side], token)) return side;
    }
    return std::nullopt;
}

bool Registry::relay_charge(wire::RelayId id, size_t bytes, Instant now) {
    auto it = relays_.find(id);
    if (it == relays_.end()) return false;
    auto& r = it->second;
    if (r.exhausted || r.bytes + bytes > cfg_.relay_max_bytes) {
        r.exhausted = true;
        ++stats_.rej_quota;
        return false;
    }
    r.bytes += bytes;
    r.last_seen = now;
    stats_.relay_bytes += bytes;
    return true;
}

bool Registry::udp_bind(wire::RelayId id, const wire::ctl::RelayToken& token,
                        const Endpoint& src, Instant now) {
    auto it = relays_.find(id);
    if (it == relays_.end() || it->second.kind != wire::ctl::RelayKind::Udp) return false;
    auto side = relay_side(id, token);
    if (!side) return false;
    it->second.udp[*side] = src;
    it->second.last_seen  = now;
    return true;
}

std::optional<Endpoint> Registry::udp_forward(wire::RelayId id, const Endpoint& src,
                                              size_t bytes, Instant now) {
    auto it = relays_.find(id);
    if (it == relays_.end() || it->second.kind != wire::ctl::RelayKind::Udp) return std::nullopt;
    auto& r = it->second;
    int   from = -1;
    if (r.udp[0] && *r.udp[0] == src) from = 0;
    else if (r.udp[1] && *r.udp[1] == src) from = 1;
    // A stranger, or a side that has not bound yet: nothing to forward to.
    if (from < 0 || !r.udp[1 - from]) return std::nullopt;
    if (!relay_charge(id, bytes, now)) return std::nullopt;
    return *r.udp[1 - from];
}

void Registry::relay_close(wire::RelayId id) {
    auto it = relays_.find(id);
    if (it != relays_.end()) release_relay(it);
}

void Registry::release_relay(std::unordered_map<wire::RelayId, Relay>::iterator it) {
    decrement(relays_per_ip_, it->second.counted_ip);
    relays_.erase(it);
}

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------
void Registry::sweep(Instant now) {
    for (auto it = relays_.begin(); it != relays_.end();) {
        if (now - it->second.last_seen >= cfg_.relay_expiry) {
            auto dead = it++;
            release_relay(dead);
        } else {
            ++it;
        }
    }
}

RegistryStats Registry::stats(Instant now) const {
    RegistryStats s = stats_;
    s.topics_total  = topics_.size();
    s.entries_total = by_dev_.size();
    for (const auto& [id, t] : topics_) {
        (void)id;
        if (t.listed) ++s.topics_listed;
    }
    for (const auto& [id, e] : by_dev_) {
        (void)id;
        if (is_fresh(e, now)) ++s.entries_fresh;
    }
    s.relays_open = relays_.size();
    return s;
}

}  // namespace uconnect::server
