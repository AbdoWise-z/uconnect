#include "store.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>
#include <utility>

namespace uconnect::server {
namespace {

constexpr std::string_view kDevIdInfo  = "uconnect:v1:devid";
constexpr std::string_view kCookieInfo = "uconnect:v1:cookie";

void append_endpoint(std::vector<uint8_t>& v, const Endpoint& ep) {
    v.push_back(static_cast<uint8_t>(ep.ip.family));
    v.insert(v.end(), ep.ip.bytes.begin(), ep.ip.bytes.begin() + ep.ip.addr_len());
    v.push_back(static_cast<uint8_t>(ep.port >> 8));
    v.push_back(static_cast<uint8_t>(ep.port));
}

void append_str(std::vector<uint8_t>& v, std::string_view s) {
    v.insert(v.end(), s.begin(), s.end());
}

}  // namespace

Store::Store(StoreConfig cfg) : cfg_(cfg) {
    crypto::random_bytes(secret_);
    sampler_.seed(crypto::random_array<8>()[0] |
                  static_cast<uint64_t>(crypto::random_array<8>()[1]) << 32);
    // Reseed properly from the CSPRNG rather than the two bytes above.
    auto seed_bytes = crypto::random_array<8>();
    uint64_t seed = 0;
    for (size_t i = 0; i < 8; ++i) seed = seed << 8 | seed_bytes[i];
    sampler_.seed(seed);
}

Store::Store(StoreConfig cfg, const crypto::SymKey& server_secret, uint64_t sample_seed)
    : cfg_(cfg), secret_(server_secret), sampler_(sample_seed) {}

// ---------------------------------------------------------------------------
// dev_id
// ---------------------------------------------------------------------------
DevId Store::derive_dev_id(const TopicId& topic, const Endpoint& ep) const {
    std::vector<uint8_t> input;
    input.reserve(kTopicIdLen + 19 + kDevIdInfo.size());
    append_str(input, kDevIdInfo);
    input.insert(input.end(), topic.begin(), topic.end());
    append_endpoint(input, ep);

    crypto::Hash h = crypto::Blake2s::mac(secret_, input);
    DevId        out{};
    std::memcpy(out.data(), h.data(), kDevIdLen);
    return out;
}

// ---------------------------------------------------------------------------
// Retry cookies
// ---------------------------------------------------------------------------
uint64_t Store::cookie_epoch(Instant now) const {
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return static_cast<uint64_t>(secs) / static_cast<uint64_t>(cfg_.cookie_lifetime.count());
}

std::vector<uint8_t> Store::cookie_for_epoch(const Endpoint& ep, uint64_t epoch) const {
    std::vector<uint8_t> input;
    append_str(input, kCookieInfo);
    append_endpoint(input, ep);
    for (int i = 56; i >= 0; i -= 8) input.push_back(static_cast<uint8_t>(epoch >> i));

    crypto::Hash h = crypto::Blake2s::mac(secret_, input);
    return {h.begin(), h.begin() + 16};
}

std::vector<uint8_t> Store::make_cookie(const Endpoint& ep, Instant now) const {
    return cookie_for_epoch(ep, cookie_epoch(now));
}

bool Store::validate_cookie(std::span<const uint8_t> cookie, const Endpoint& ep,
                            Instant now) const {
    if (cookie.size() != 16) return false;
    uint64_t e = cookie_epoch(now);
    // Accept the previous epoch too, so a cookie issued a moment before a
    // boundary is not rejected for a race the client cannot see.
    auto cur  = cookie_for_epoch(ep, e);
    auto prev = cookie_for_epoch(ep, e - 1);
    return crypto::ct_equal(cookie, cur) || crypto::ct_equal(cookie, prev);
}

// ---------------------------------------------------------------------------
// membership bookkeeping
// ---------------------------------------------------------------------------
void Store::add_member(TopicState& t, const DevId& id) {
    if (t.pos.count(id)) return;
    t.pos[id] = t.members.size();
    t.members.push_back(id);
}

void Store::remove_member(TopicState& t, const DevId& id) {
    auto it = t.pos.find(id);
    if (it == t.pos.end()) return;
    size_t idx  = it->second;
    size_t last = t.members.size() - 1;
    if (idx != last) {
        t.members[idx]        = t.members[last];
        t.pos[t.members[idx]] = idx;
    }
    t.members.pop_back();
    t.pos.erase(it);
}

void Store::erase_record(const DevId& id) {
    auto it = by_dev_.find(id);
    if (it == by_dev_.end()) return;

    auto tit = topics_.find(it->second.topic_id);
    if (tit != topics_.end()) {
        remove_member(tit->second, id);
        auto cit = tit->second.per_ip.find(ip_key(it->second.bound_addr));
        if (cit != tit->second.per_ip.end()) {
            if (cit->second <= 1) tit->second.per_ip.erase(cit);
            else --cit->second;
        }
        if (tit->second.members.empty()) {
            TopicId gone = it->second.topic_id;
            topics_.erase(tit);
            topic_order_.erase(std::remove(topic_order_.begin(), topic_order_.end(), gone),
                               topic_order_.end());
        }
    }

    auto ik = ip_key(it->second.bound_addr);
    auto pit = per_ip_total_.find(ik);
    if (pit != per_ip_total_.end()) {
        if (pit->second <= 1) per_ip_total_.erase(pit);
        else --pit->second;
    }

    by_dev_.erase(it);
}

bool Store::is_fresh(const Record& r, Instant now) const {
    return now - r.last_seen < cfg_.stale_after;
}

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------
RegisterResult Store::register_entry(const wire::Register& msg, const Endpoint& src,
                                     Instant now) {
    RegisterResult out;
    out.srflx = src;

    if (by_dev_.size() >= cfg_.max_entries) {
        ++stats_.rej_quota;
        out.code = ErrorCode::QuotaExceeded;
        return out;
    }

    DevId dev = derive_dev_id(msg.id, src);
    out.dev_id = dev;

    auto existing = by_dev_.find(dev);
    const bool is_new = existing == by_dev_.end();

    if (is_new) {
        // Quotas count only against new records. A device refreshing its own
        // registration is not consuming additional capacity.
        auto ik = ip_key(src);
        size_t total = per_ip_total_.count(ik) ? per_ip_total_[ik] : 0;
        if (total >= cfg_.max_per_ip_total) {
            ++stats_.rej_quota;
            out.code = ErrorCode::QuotaExceeded;
            return out;
        }

        auto tit = topics_.find(msg.id);
        if (tit != topics_.end()) {
            auto   cit      = tit->second.per_ip.find(ik);
            size_t in_topic = cit == tit->second.per_ip.end() ? 0 : cit->second;
            if (in_topic >= cfg_.max_per_ip_per_topic) {
                ++stats_.rej_quota;
                out.code = ErrorCode::QuotaExceeded;
                return out;
            }
        } else if (topics_.size() >= cfg_.max_topics) {
            ++stats_.rej_quota;
            out.code = ErrorCode::QuotaExceeded;
            return out;
        }
    }

    Record& r = by_dev_[dev];
    if (is_new) {
        r.created = now;
        per_ip_total_[ip_key(src)]++;
    }
    r.dev_id     = dev;
    r.topic_id   = msg.id;
    r.bound_addr = src;
    r.host_cands = msg.host_cands;
    r.meta       = msg.meta;
    r.last_seen  = now;
    r.key_epoch  = msg.key_epoch;
    r.mode       = msg.mode;
    r.listed     = msg.listed;
    r.last_seq   = 0;

    // A fresh lease token on every registration. A device that restarted has
    // lost its old one, and since dev_id is derived from the source address --
    // which the Retry cookie has already validated -- whoever holds the address
    // legitimately owns the record.
    crypto::random_bytes(r.lease_token);
    out.lease_token = r.lease_token;

    auto& topic = topics_[msg.id];
    if (topic.members.empty() && std::find(topic_order_.begin(), topic_order_.end(), msg.id) ==
                                     topic_order_.end()) {
        topic_order_.push_back(msg.id);
    }
    topic.mode = msg.mode;
    // Listed is sticky per topic: one member opting in makes the topic
    // discoverable. That is why `listed` defaults to false everywhere -- a
    // single careless client would otherwise expose a private topic.
    if (msg.listed) topic.listed = true;
    if (is_new) {
        add_member(topic, dev);
        topic.per_ip[ip_key(src)]++;
    }

    out.peers_in_topic = static_cast<uint16_t>(
        topic.members.size() > 0xFFFF ? 0xFFFF : topic.members.size());
    ++stats_.registers;
    return out;
}

// ---------------------------------------------------------------------------
// authenticated operations
// ---------------------------------------------------------------------------
AuthResult Store::authenticate(Record& r, uint64_t seq, std::span<const uint8_t> authed,
                               const wire::Mac& mac, const Endpoint& src, Instant now) {
    AuthResult out;
    out.srflx = r.bound_addr;

    // Monotonic sequence kills replay of a captured datagram.
    if (seq <= r.last_seq) {
        ++stats_.rej_bad_auth;
        out.code = ErrorCode::BadAuth;
        return out;
    }

    crypto::Hash full = crypto::Blake2s::mac(r.lease_token, authed);
    if (!crypto::ct_equal(std::span<const uint8_t>(full.data(), wire::kMacLen), mac)) {
        ++stats_.rej_bad_auth;
        out.code = ErrorCode::BadAuth;
        return out;
    }

    r.last_seq  = seq;
    r.last_seen = now;

    if (!(src == r.bound_addr)) {
        // The MAC verified, so this really is the record's owner arriving from
        // a new address -- a NAT rebind or a Wi-Fi/LTE handoff. Update in
        // place: the whole reason to keep the record is so peers find the
        // current address.
        auto old_ik = ip_key(r.bound_addr);
        auto new_ik = ip_key(src);
        if (!(old_ik == new_ik)) {
            auto pit = per_ip_total_.find(old_ik);
            if (pit != per_ip_total_.end()) {
                if (pit->second <= 1) per_ip_total_.erase(pit);
                else --pit->second;
            }
            per_ip_total_[new_ik]++;

            // The per-topic count must move with it, or a roaming device leaks
            // quota at the address it left and eventually locks out that IP.
            auto tit = topics_.find(r.topic_id);
            if (tit != topics_.end()) {
                auto cit = tit->second.per_ip.find(old_ik);
                if (cit != tit->second.per_ip.end()) {
                    if (cit->second <= 1) tit->second.per_ip.erase(cit);
                    else --cit->second;
                }
                tit->second.per_ip[new_ik]++;
            }
        }
        r.bound_addr = src;
        out.rebound  = true;
        ++stats_.rebinds;
    }

    out.srflx = r.bound_addr;
    return out;
}

AuthResult Store::keepalive(const DevId& dev, uint64_t seq, std::span<const uint8_t> authed,
                            const wire::Mac& mac, const Endpoint& src, Instant now) {
    auto it = by_dev_.find(dev);
    if (it == by_dev_.end()) {
        ++stats_.rej_bad_request;
        return {ErrorCode::NotFound, {}, false};
    }
    auto res = authenticate(it->second, seq, authed, mac, src, now);
    if (res.code == ErrorCode::None) ++stats_.keepalives;
    return res;
}

AuthResult Store::update(const wire::Update& msg, const Endpoint& src, Instant now) {
    auto it = by_dev_.find(msg.dev_id);
    if (it == by_dev_.end()) {
        ++stats_.rej_bad_request;
        return {ErrorCode::NotFound, {}, false};
    }
    auto res = authenticate(it->second, msg.auth.seq, msg.auth.authed, msg.auth.mac, src, now);
    if (res.code != ErrorCode::None) return res;

    it->second.host_cands = msg.host_cands;
    it->second.meta       = msg.meta;
    ++stats_.updates;
    return res;
}

AuthResult Store::unregister(const DevId& dev, uint64_t seq, std::span<const uint8_t> authed,
                             const wire::Mac& mac, const Endpoint& src, Instant now) {
    auto it = by_dev_.find(dev);
    if (it == by_dev_.end()) {
        ++stats_.rej_bad_request;
        return {ErrorCode::NotFound, {}, false};
    }
    auto res = authenticate(it->second, seq, authed, mac, src, now);
    if (res.code != ErrorCode::None) return res;

    erase_record(dev);
    ++stats_.unregisters;
    return res;
}

// ---------------------------------------------------------------------------
// queries
// ---------------------------------------------------------------------------
wire::PeerEntry Store::to_entry(const Record& r, bool want_meta, Instant now) const {
    wire::PeerEntry e;
    e.dev_id = r.dev_id;
    auto age = std::chrono::duration_cast<std::chrono::seconds>(now - r.last_seen).count();
    e.age_secs = static_cast<uint16_t>(age < 0 ? 0 : (age > 0xFFFF ? 0xFFFF : age));
    e.stale    = !is_fresh(r, now);

    // srflx first: it is the candidate most peers will need. Host candidates
    // follow, and matter when both peers sit behind the same NAT, where the
    // srflx pair fails on any router that does not hairpin.
    e.cands.push_back(Candidate{Candidate::Kind::Srflx, r.bound_addr});
    for (const auto& c : r.host_cands) {
        if (e.cands.size() >= wire::kMaxCandidates) break;
        e.cands.push_back(c);
    }
    if (want_meta) e.meta = r.meta;
    return e;
}

Store::LookupResult Store::lookup(const TopicId& topic, uint8_t max, bool want_meta,
                                  Instant now) {
    ++stats_.lookups;
    LookupResult out;

    auto tit = topics_.find(topic);
    if (tit == topics_.end()) return out;

    out.mode = tit->second.mode;
    const auto& members = tit->second.members;
    out.total = static_cast<uint16_t>(members.size() > 0xFFFF ? 0xFFFF : members.size());

    if (max > wire::kLookupMax) max = wire::kLookupMax;
    if (max == 0) max = wire::kLookupDefault;

    const size_t n = members.size();
    const size_t want = max < n ? max : n;

    std::vector<size_t> picked;
    picked.reserve(want);

    if (want == n) {
        for (size_t i = 0; i < n; ++i) picked.push_back(i);
    } else if (n < want * 4) {
        // Dense case: a full shuffle is cheaper than fighting collisions.
        std::vector<size_t> idx(n);
        for (size_t i = 0; i < n; ++i) idx[i] = i;
        std::shuffle(idx.begin(), idx.end(), sampler_);
        picked.assign(idx.begin(), idx.begin() + static_cast<ptrdiff_t>(want));
    } else {
        // Sparse case: rejection sampling, cheap when n >> want.
        std::unordered_set<size_t> seen;
        seen.reserve(want * 2);
        std::uniform_int_distribution<size_t> dist(0, n - 1);
        while (seen.size() < want) {
            size_t i = dist(sampler_);
            if (seen.insert(i).second) picked.push_back(i);
        }
    }

    // Fresh entries first so a client fans out at live peers before stale ones.
    std::vector<const Record*> fresh, stale;
    for (size_t i : picked) {
        auto rit = by_dev_.find(members[i]);
        if (rit == by_dev_.end()) continue;
        (is_fresh(rit->second, now) ? fresh : stale).push_back(&rit->second);
    }

    for (const auto* r : fresh) out.entries.push_back(to_entry(*r, want_meta, now));
    for (const auto* r : stale) out.entries.push_back(to_entry(*r, want_meta, now));

    for (const auto& e : out.entries) stats_.bytes_out_lookup += e.encoded_size();
    return out;
}

std::optional<std::pair<TopicId, wire::PeerEntry>> Store::resolve(const DevId& dev,
                                                                  Instant now) {
    ++stats_.resolves;
    auto it = by_dev_.find(dev);
    if (it == by_dev_.end()) return std::nullopt;
    return std::make_pair(it->second.topic_id, to_entry(it->second, true, now));
}

Store::TopicsResult Store::list_topics(uint32_t cursor, uint8_t limit, Instant now) {
    TopicsResult out;
    if (limit == 0) limit = 100;

    size_t i = cursor;
    while (i < topic_order_.size() && out.topics.size() < limit) {
        const TopicId& id = topic_order_[i];
        ++i;
        auto tit = topics_.find(id);
        if (tit == topics_.end()) continue;
        if (!tit->second.listed) continue;  // opt-in only

        wire::TopicSummary s;
        s.id    = id;
        s.mode  = tit->second.mode;
        s.peers = static_cast<uint32_t>(tit->second.members.size());
        uint32_t fresh = 0;
        for (const auto& m : tit->second.members) {
            auto rit = by_dev_.find(m);
            if (rit != by_dev_.end() && is_fresh(rit->second, now)) ++fresh;
        }
        s.fresh_peers = fresh;
        out.topics.push_back(s);
    }
    out.next_cursor = static_cast<uint32_t>(i >= topic_order_.size() ? 0 : i);
    return out;
}

std::optional<Endpoint> Store::relay_target(const DevId& from, const DevId& to, uint64_t seq,
                                            std::span<const uint8_t> authed,
                                            const wire::Mac& mac, const Endpoint& src,
                                            Instant now) {
    auto fit = by_dev_.find(from);
    if (fit == by_dev_.end()) {
        ++stats_.rej_bad_request;
        return std::nullopt;
    }
    if (authenticate(fit->second, seq, authed, mac, src, now).code != ErrorCode::None) {
        return std::nullopt;
    }

    auto tit = by_dev_.find(to);
    if (tit == by_dev_.end()) return std::nullopt;
    // Relay only within a topic: the server must not become a general-purpose
    // message bus between arbitrary registrants.
    if (!(tit->second.topic_id == fit->second.topic_id)) {
        ++stats_.rej_bad_request;
        return std::nullopt;
    }

    ++stats_.connects;
    return tit->second.bound_addr;
}

// ---------------------------------------------------------------------------
// maintenance
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// relay
// ---------------------------------------------------------------------------
Store::RelayResult Store::relay_alloc(const DevId& from, const DevId& peer,
                                      const Endpoint& src, Instant now) {
    RelayResult out;

    if (!cfg_.relay_enabled) {
        out.code = ErrorCode::Unsupported;
        return out;
    }

    auto fit = by_dev_.find(from);
    auto pit = by_dev_.find(peer);
    if (fit == by_dev_.end() || pit == by_dev_.end()) {
        ++stats_.rej_bad_request;
        out.code = ErrorCode::NotFound;
        return out;
    }
    // Relay only within a topic, for the same reason CONNECT does: the server
    // must not become a general purpose tunnel between arbitrary registrants.
    if (!(fit->second.topic_id == pit->second.topic_id)) {
        ++stats_.rej_bad_request;
        out.code = ErrorCode::BadRequest;
        return out;
    }

    auto ik = ip_key(src);
    if (relays_.size() >= cfg_.max_relays ||
        (relays_per_ip_.count(ik) && relays_per_ip_[ik] >= cfg_.max_relays_per_ip)) {
        ++stats_.rej_relay_quota;
        out.code = ErrorCode::QuotaExceeded;
        return out;
    }

    // Reuse an existing binding for the same pair rather than stacking new
    // ones: a retried allocation after a lost reply must not leak a binding.
    for (auto& [id, b] : relays_) {
        if (b.a_dev == from && b.b_dev == peer) {
            b.last_seen = now;
            b.a_addr    = src;
            out.relay_id = id;
            out.max_kib  = static_cast<uint32_t>(cfg_.relay_max_bytes / 1024);
            return out;
        }
    }

    RelayBinding b;
    // 64 random bits. The id is the only thing gating who may claim slot B, so
    // it must be unguessable; it travels to the peer inside the authenticated
    // CONNECT relay.
    auto rb = crypto::random_array<8>();
    for (size_t i = 0; i < 8; ++i) b.id = b.id << 8 | rb[i];
    if (b.id == 0) b.id = 1;

    b.topic     = fit->second.topic_id;
    b.a_dev     = from;
    b.b_dev     = peer;
    b.a_addr    = src;
    b.created   = now;
    b.last_seen = now;

    relays_[b.id] = b;
    relays_per_ip_[ik]++;
    ++stats_.relays_allocated;

    out.relay_id = b.id;
    out.max_kib  = static_cast<uint32_t>(cfg_.relay_max_bytes / 1024);
    return out;
}

std::optional<Endpoint> Store::relay_forward(wire::RelayId id, const Endpoint& src,
                                             size_t bytes, Instant now) {
    auto it = relays_.find(id);
    if (it == relays_.end()) {
        ++stats_.rej_relay_unknown;
        return std::nullopt;
    }
    auto& b = it->second;

    if (b.bytes + bytes > cfg_.relay_max_bytes) {
        ++stats_.rej_relay_quota;
        return std::nullopt;
    }

    // Resolve both endpoints from the live registry rather than from whoever
    // spoke first.
    //
    // Two reasons. It removes a deadlock: an earlier version let the first
    // datagram from a new address claim the far slot, so the allocator could
    // not send until its peer spoke, and the peer had nothing to say until it
    // received the handshake -- neither side could start. And it is stronger,
    // because both addresses now come from authenticated registrations instead
    // of from possession of the relay id, so knowing the id is not enough to
    // insert yourself into someone else's binding.
    //
    // Reading them fresh each time also means a NAT rebind is picked up
    // automatically: the keepalive updates the record, and the next relayed
    // datagram follows it.
    auto ait = by_dev_.find(b.a_dev);
    auto bit = by_dev_.find(b.b_dev);
    if (ait == by_dev_.end() || bit == by_dev_.end()) {
        // One of the peers let its registration lapse. The binding is dead.
        ++stats_.rej_relay_unknown;
        return std::nullopt;
    }
    // Both endpoints are resolved from the live registry on every forward, so
    // a rebinding peer keeps working and no "is B here yet" flag is needed.
    b.a_addr = ait->second.bound_addr;
    b.b_addr = bit->second.bound_addr;

    std::optional<Endpoint> dst;
    if (src == b.a_addr) dst = b.b_addr;
    else if (src == b.b_addr) dst = b.a_addr;

    if (!dst) {
        // A stranger who learned the id. Drop it: the payload is Noise
        // protected anyway, so this only stops it wasting our bandwidth.
        ++stats_.rej_relay_unknown;
        return std::nullopt;
    }

    b.last_seen = now;
    b.bytes += bytes;
    stats_.relay_bytes += bytes;
    return dst;
}

size_t Store::sweep(Instant now) {
    std::vector<DevId> dead;
    for (const auto& [id, r] : by_dev_) {
        if (now - r.last_seen >= cfg_.hard_expiry) dead.push_back(id);
    }
    for (const auto& id : dead) erase_record(id);
    stats_.expired += dead.size();

    // Idle relay bindings evaporate on the same principle as records: the
    // server holds no long-lived state it does not have to.
    for (auto it = relays_.begin(); it != relays_.end();) {
        if (now - it->second.last_seen >= cfg_.relay_expiry) {
            auto ik  = ip_key(it->second.a_addr);
            auto pit = relays_per_ip_.find(ik);
            if (pit != relays_per_ip_.end()) {
                if (pit->second <= 1) relays_per_ip_.erase(pit);
                else --pit->second;
            }
            it = relays_.erase(it);
        } else {
            ++it;
        }
    }

    return dead.size();
}

Stats Store::stats(Instant now) const {
    Stats s = stats_;
    s.topics_total  = topics_.size();
    s.entries_total = by_dev_.size();

    uint64_t listed = 0;
    for (const auto& [id, t] : topics_) {
        (void)id;
        if (t.listed) ++listed;
    }
    s.topics_listed = listed;

    uint64_t fresh = 0;
    for (const auto& [id, r] : by_dev_) {
        (void)id;
        if (is_fresh(r, now)) ++fresh;
    }
    s.entries_fresh = fresh;
    s.relays_open   = relays_.size();
    return s;
}

const Record* Store::find(const DevId& dev) const {
    auto it = by_dev_.find(dev);
    return it == by_dev_.end() ? nullptr : &it->second;
}

}  // namespace uconnect::server
