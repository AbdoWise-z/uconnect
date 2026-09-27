#include "control.hpp"

#include <utility>

namespace uconnect::wire::ctl {
namespace {

// Counts are capped before anything is reserved, or a count field becomes a
// remote allocation primitive. Caps are protocol constants, so exceeding one
// is malformed.
bool read_cands(Reader& r, std::vector<Candidate>& out) {
    const size_t n = r.u8();
    if (n > kMaxCandidates) return false;
    out.reserve(n);
    for (size_t i = 0; i < n && r.ok(); ++i) out.push_back(r.candidate());
    return r.ok();
}

void write_cands(Writer& w, const std::vector<Candidate>& c) {
    const size_t n = c.size() > kMaxCandidates ? kMaxCandidates : c.size();
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) w.candidate(c[i]);
}

void write_meta(Writer& w, const std::vector<uint8_t>& m) {
    const size_t n = m.size() > kMaxMeta ? kMaxMeta : m.size();
    w.u16(static_cast<uint16_t>(n));
    w.bytes(m.data(), n);
}

bool read_meta(Reader& r, std::vector<uint8_t>& out) {
    const size_t n = r.u16();
    if (n > kMaxMeta) return false;
    auto s = r.bytes(n);
    if (!r.ok()) return false;
    out.assign(s.begin(), s.end());
    return true;
}

bool read_mode(Reader& r, TopicMode& mode) {
    const uint8_t m = r.u8();
    if (m > static_cast<uint8_t>(TopicMode::Keyed)) return false;
    mode = static_cast<TopicMode>(m);
    return true;
}

bool read_kind(Reader& r, RelayKind& kind) {
    const uint8_t k = r.u8();
    if (k > static_cast<uint8_t>(RelayKind::Udp)) return false;
    kind = static_cast<RelayKind>(k);
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------
std::vector<uint8_t> frame(std::span<const uint8_t> message) {
    if (message.size() > kMaxFrame || message.size() > 0xFFFF) return {};
    std::vector<uint8_t> out;
    out.reserve(message.size() + 2);
    out.push_back(static_cast<uint8_t>(message.size() >> 8));
    out.push_back(static_cast<uint8_t>(message.size()));
    out.insert(out.end(), message.begin(), message.end());
    return out;
}

bool FrameReader::feed(std::span<const uint8_t> bytes) {
    if (broken_) return false;
    buf_.insert(buf_.end(), bytes.begin(), bytes.end());
    // A declared length over the limit is caught as soon as the prefix is in,
    // not after buffering the body it announces.
    if (buf_.size() >= 2) {
        const size_t len = static_cast<size_t>(buf_[0]) << 8 | buf_[1];
        if (len > max_) broken_ = true;
    }
    return !broken_;
}

std::optional<std::vector<uint8_t>> FrameReader::next() {
    if (broken_ || buf_.size() < 2) return std::nullopt;
    const size_t len = static_cast<size_t>(buf_[0]) << 8 | buf_[1];
    if (len > max_) {
        broken_ = true;
        return std::nullopt;
    }
    if (buf_.size() < 2 + len) return std::nullopt;
    std::vector<uint8_t> msg(buf_.begin() + 2, buf_.begin() + 2 + static_cast<ptrdiff_t>(len));
    buf_.erase(buf_.begin(), buf_.begin() + 2 + static_cast<ptrdiff_t>(len));
    // The next frame's prefix may already be here; check its length too.
    if (buf_.size() >= 2 && (static_cast<size_t>(buf_[0]) << 8 | buf_[1]) > max_) broken_ = true;
    return msg;
}

std::vector<uint8_t> FrameReader::take_rest() {
    std::vector<uint8_t> rest;
    rest.swap(buf_);
    return rest;
}

std::vector<uint8_t> empty_message(MsgType type, uint32_t txn, uint8_t flags) {
    std::vector<uint8_t> buf(Header::kSize);
    Writer               w{buf};
    Header{type, kVersion, flags, txn}.encode(w);
    return buf;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
void Register::encode(Writer& w) const {
    w.array(id);
    w.u8(static_cast<uint8_t>(mode));
    w.u8(key_epoch);
    write_cands(w, host_cands);
    write_meta(w, meta);
}

std::optional<Register> Register::decode(Reader& r, const Header& h) {
    Register m;
    m.id = r.array<kTopicIdLen>();
    if (!read_mode(r, m.mode)) return std::nullopt;
    m.key_epoch = r.u8();
    m.unlisted  = (h.flags & flags::kUnlisted) != 0;
    if (!read_cands(r, m.host_cands)) return std::nullopt;
    if (!read_meta(r, m.meta)) return std::nullopt;
    return m;
}

void RegisterOk::encode(Writer& w) const {
    w.array(dev_id);
    w.endpoint(srflx);
    w.u16(peers_in_topic);
}

std::optional<RegisterOk> RegisterOk::decode(Reader& r) {
    RegisterOk m;
    m.dev_id         = r.array<kDevIdLen>();
    m.srflx          = r.endpoint();
    m.peers_in_topic = r.u16();
    if (!r.ok()) return std::nullopt;
    return m;
}

void DevRef::encode(Writer& w) const { w.array(dev_id); }

std::optional<DevRef> DevRef::decode(Reader& r) {
    DevRef m;
    m.dev_id = r.array<kDevIdLen>();
    if (!r.ok()) return std::nullopt;
    return m;
}

void KeepaliveOk::encode(Writer& w) const { w.endpoint(srflx); }

std::optional<KeepaliveOk> KeepaliveOk::decode(Reader& r) {
    KeepaliveOk m;
    m.srflx = r.endpoint();
    if (!r.ok()) return std::nullopt;
    return m;
}

void Update::encode(Writer& w) const {
    w.array(dev_id);
    write_cands(w, host_cands);
    write_meta(w, meta);
}

std::optional<Update> Update::decode(Reader& r) {
    Update m;
    m.dev_id = r.array<kDevIdLen>();
    if (!read_cands(r, m.host_cands)) return std::nullopt;
    if (!read_meta(r, m.meta)) return std::nullopt;
    return m;
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------
void Lookup::encode(Writer& w) const {
    w.array(id);
    w.u8(max);
}

std::optional<Lookup> Lookup::decode(Reader& r, const Header& h) {
    Lookup m;
    m.id  = r.array<kTopicIdLen>();
    m.max = r.u8();
    if (!r.ok()) return std::nullopt;
    // Clamp rather than reject: asking for more than the ceiling gets the
    // ceiling.
    if (m.max == 0) m.max = kLookupDefault;
    if (m.max > kLookupMax) m.max = kLookupMax;
    m.want_meta = (h.flags & flags::kWantMeta) != 0;
    return m;
}

void LookupOk::encode(Writer& w) const {
    w.array(id);
    w.u8(static_cast<uint8_t>(mode));
    w.u16(total);
    const size_t n = entries.size() > kLookupMax ? kLookupMax : entries.size();
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) entries[i].encode(w);
}

std::optional<LookupOk> LookupOk::decode(Reader& r) {
    LookupOk m;
    m.id = r.array<kTopicIdLen>();
    if (!read_mode(r, m.mode)) return std::nullopt;
    m.total        = r.u16();
    const size_t n = r.u8();
    if (!r.ok() || n > kLookupMax) return std::nullopt;
    m.entries.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        auto e = PeerEntry::decode(r);
        if (!e) return std::nullopt;
        m.entries.push_back(std::move(*e));
    }
    return m;
}

void Resolve::encode(Writer& w) const { w.array(dev_id); }

std::optional<Resolve> Resolve::decode(Reader& r) {
    Resolve m;
    m.dev_id = r.array<kDevIdLen>();
    if (!r.ok()) return std::nullopt;
    return m;
}

void Topics::encode(Writer& w) const {
    w.u32(cursor);
    w.u8(limit);
}

std::optional<Topics> Topics::decode(Reader& r) {
    Topics m;
    m.cursor = r.u32();
    m.limit  = r.u8();
    if (!r.ok()) return std::nullopt;
    if (m.limit == 0) m.limit = 100;
    return m;
}

void TopicsOk::encode(Writer& w) const {
    w.u32(next_cursor);
    const size_t n = topics.size() > 0xFFFF ? 0xFFFF : topics.size();
    w.u16(static_cast<uint16_t>(n));
    for (size_t i = 0; i < n; ++i) topics[i].encode(w);
}

std::optional<TopicsOk> TopicsOk::decode(Reader& r) {
    TopicsOk m;
    m.next_cursor  = r.u32();
    const size_t n = r.u16();
    if (!r.ok()) return std::nullopt;
    // Each summary is 25 bytes, so a frame cannot honestly hold more than this.
    if (n > kMaxFrame / 25) return std::nullopt;
    m.topics.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        auto t = TopicSummary::decode(r);
        if (!t) return std::nullopt;
        m.topics.push_back(*t);
    }
    return m;
}

void StatsOk::encode(Writer& w) const {
    for (uint64_t v : {topics_total, topics_listed, entries_total, entries_fresh, registers,
                       lookups, connects, expired, rej_quota, rej_rate_limited, relays_open,
                       relays_allocated, relay_bytes, connections}) {
        w.u64(v);
    }
}

std::optional<StatsOk> StatsOk::decode(Reader& r) {
    StatsOk m;
    for (uint64_t* v : {&m.topics_total, &m.topics_listed, &m.entries_total, &m.entries_fresh,
                        &m.registers, &m.lookups, &m.connects, &m.expired, &m.rej_quota,
                        &m.rej_rate_limited, &m.relays_open, &m.relays_allocated,
                        &m.relay_bytes, &m.connections}) {
        *v = r.u64();
    }
    if (!r.ok()) return std::nullopt;
    return m;
}

// ---------------------------------------------------------------------------
// Introductions and relays
// ---------------------------------------------------------------------------
void Connect::encode(Writer& w) const {
    w.array(from_dev);
    w.array(to_dev);
    const size_t n = payload.size() > kMaxRelayPayload ? kMaxRelayPayload : payload.size();
    w.u16(static_cast<uint16_t>(n));
    w.bytes(payload.data(), n);
}

std::optional<Connect> Connect::decode(Reader& r) {
    Connect m;
    m.from_dev     = r.array<kDevIdLen>();
    m.to_dev       = r.array<kDevIdLen>();
    const size_t n = r.u16();
    if (!r.ok() || n > kMaxRelayPayload) return std::nullopt;
    auto s = r.bytes(n);
    if (!r.ok()) return std::nullopt;
    m.payload.assign(s.begin(), s.end());
    return m;
}

void RelayAlloc::encode(Writer& w) const {
    w.array(from_dev);
    w.array(peer_dev);
    w.u8(static_cast<uint8_t>(kind));
}

std::optional<RelayAlloc> RelayAlloc::decode(Reader& r) {
    RelayAlloc m;
    m.from_dev = r.array<kDevIdLen>();
    m.peer_dev = r.array<kDevIdLen>();
    if (!read_kind(r, m.kind) || !r.ok()) return std::nullopt;
    return m;
}

void RelayAllocOk::encode(Writer& w) const {
    w.u64(relay_id);
    w.array(token);
    w.u8(static_cast<uint8_t>(kind));
    w.u32(max_kib);
}

std::optional<RelayAllocOk> RelayAllocOk::decode(Reader& r) {
    RelayAllocOk m;
    m.relay_id = r.u64();
    m.token    = r.array<kRelayTokenLen>();
    if (!read_kind(r, m.kind)) return std::nullopt;
    m.max_kib = r.u32();
    if (!r.ok()) return std::nullopt;
    return m;
}

void RelayOffer::encode(Writer& w) const {
    w.u64(relay_id);
    w.array(token);
    w.u8(static_cast<uint8_t>(kind));
    w.array(from_dev);
    w.array(topic);
}

std::optional<RelayOffer> RelayOffer::decode(Reader& r) {
    RelayOffer m;
    m.relay_id = r.u64();
    m.token    = r.array<kRelayTokenLen>();
    if (!read_kind(r, m.kind)) return std::nullopt;
    m.from_dev = r.array<kDevIdLen>();
    m.topic    = r.array<kTopicIdLen>();
    if (!r.ok()) return std::nullopt;
    return m;
}

void RelayJoin::encode(Writer& w) const {
    w.u64(relay_id);
    w.array(token);
}

std::optional<RelayJoin> RelayJoin::decode(Reader& r) {
    RelayJoin m;
    m.relay_id = r.u64();
    m.token    = r.array<kRelayTokenLen>();
    if (!r.ok()) return std::nullopt;
    return m;
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------
void WhoAmI::encode(Writer& w) const {
    w.u64(nonce);
    // Pad to the full size: the reply goes to an unvalidated address and must
    // never be larger than this request.
    while (w.size() < kWhoAmISize && w.ok()) w.u8(0);
}

std::optional<WhoAmI> WhoAmI::decode(Reader& r) {
    WhoAmI m;
    m.nonce = r.u64();
    if (!r.ok()) return std::nullopt;
    return m;
}

void WhoAmIOk::encode(Writer& w) const {
    w.u64(nonce);
    w.endpoint(mapped);
}

std::optional<WhoAmIOk> WhoAmIOk::decode(Reader& r) {
    WhoAmIOk m;
    m.nonce  = r.u64();
    m.mapped = r.endpoint();
    if (!r.ok()) return std::nullopt;
    return m;
}

void UdpRelayBind::encode(Writer& w) const {
    w.u64(relay_id);
    w.array(token);
}

std::optional<UdpRelayBind> UdpRelayBind::decode(Reader& r) {
    UdpRelayBind m;
    m.relay_id = r.u64();
    m.token    = r.array<kRelayTokenLen>();
    if (!r.ok()) return std::nullopt;
    return m;
}

void UdpRelayBindOk::encode(Writer& w) const { w.u64(relay_id); }

std::optional<UdpRelayBindOk> UdpRelayBindOk::decode(Reader& r) {
    UdpRelayBindOk m;
    m.relay_id = r.u64();
    if (!r.ok()) return std::nullopt;
    return m;
}

}  // namespace uconnect::wire::ctl
