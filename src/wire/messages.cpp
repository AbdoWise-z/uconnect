#include "messages.hpp"

#include <utility>

namespace uconnect::wire {
namespace {

// Every decoder that reads a count must cap it before reserving, or a 2-byte
// field becomes a remote allocation primitive. Caps are protocol constants, so
// a peer that exceeds one is malformed, not merely unlucky.
template <typename T>
bool read_vec(Reader& r, std::vector<T>& out, size_t max, T (*read_one)(Reader&)) {
    size_t n = r.u8();
    if (n > max) { return false; }
    out.reserve(n);
    for (size_t i = 0; i < n && r.ok(); ++i) out.push_back(read_one(r));
    return r.ok();
}

Candidate read_candidate(Reader& r) { return r.candidate(); }

void write_cands(Writer& w, const std::vector<Candidate>& c) {
    w.u8(static_cast<uint8_t>(c.size() > kMaxCandidates ? kMaxCandidates : c.size()));
    size_t n = c.size() > kMaxCandidates ? kMaxCandidates : c.size();
    for (size_t i = 0; i < n; ++i) w.candidate(c[i]);
}

void write_blob16_capped(Writer& w, const std::vector<uint8_t>& v, size_t cap) {
    size_t n = v.size() > cap ? cap : v.size();
    w.u16(static_cast<uint16_t>(n));
    w.bytes(v.data(), n);
}

bool read_blob16_capped(Reader& r, std::vector<uint8_t>& out, size_t cap) {
    size_t n = r.u16();
    if (n > cap) return false;
    auto s = r.bytes(n);
    if (!r.ok()) return false;
    out.assign(s.begin(), s.end());
    return true;
}

// Trailing seq + mac, shared by every authenticated message. `authed` is
// captured before the mac is consumed so the caller can verify it.
void write_auth_prefix(Writer& w, const Authed& a) { w.u64(a.seq); }

bool read_auth(Reader& r, Authed& a) {
    a.seq    = r.u64();
    a.authed = r.consumed();  // header + body + seq, i.e. everything the mac covers
    a.mac    = r.array<kMacLen>();
    return r.ok();
}

}  // namespace

// --- Register --------------------------------------------------------------
void Register::encode(Writer& w) const {
    w.array(id);
    w.u8(static_cast<uint8_t>(mode));
    w.u8(key_epoch);
    write_cands(w, host_cands);
    write_blob16_capped(w, meta, kMaxMeta);
    w.blob8(cookie);
}

std::optional<Register> Register::decode(Reader& r, const Header& h) {
    Register m;
    m.id   = r.array<kTopicIdLen>();
    uint8_t mode = r.u8();
    if (mode > static_cast<uint8_t>(TopicMode::Keyed)) return std::nullopt;
    m.mode      = static_cast<TopicMode>(mode);
    m.key_epoch = r.u8();
    m.listed    = (h.flags & flags::kListed) != 0;
    if (!read_vec(r, m.host_cands, kMaxCandidates, read_candidate)) return std::nullopt;
    if (!read_blob16_capped(r, m.meta, kMaxMeta)) return std::nullopt;
    auto cookie = r.blob8();
    if (!r.ok() || cookie.size() > kMaxCookieLen) return std::nullopt;
    m.cookie.assign(cookie.begin(), cookie.end());
    return m;
}

void RegisterOk::encode(Writer& w) const {
    w.array(dev_id);
    w.array(lease_token);
    w.endpoint(srflx);
    w.u16(ttl_secs);
    w.u16(peers_in_topic);
}

std::optional<RegisterOk> RegisterOk::decode(Reader& r) {
    RegisterOk m;
    m.dev_id         = r.array<kDevIdLen>();
    m.lease_token    = r.array<kLeaseTokenLen>();
    m.srflx          = r.endpoint();
    m.ttl_secs       = r.u16();
    m.peers_in_topic = r.u16();
    if (!r.ok()) return std::nullopt;
    return m;
}

// --- DevAuth (Keepalive / Unregister) --------------------------------------
void DevAuth::encode_prefix(Writer& w) const {
    w.array(dev_id);
    write_auth_prefix(w, auth);
}

std::optional<DevAuth> DevAuth::decode(Reader& r) {
    DevAuth m;
    m.dev_id = r.array<kDevIdLen>();
    if (!read_auth(r, m.auth)) return std::nullopt;
    return m;
}

void KeepaliveOk::encode(Writer& w) const {
    w.endpoint(srflx);
    w.u16(expires_in);
}

std::optional<KeepaliveOk> KeepaliveOk::decode(Reader& r) {
    KeepaliveOk m;
    m.srflx      = r.endpoint();
    m.expires_in = r.u16();
    if (!r.ok()) return std::nullopt;
    return m;
}

// --- Update ----------------------------------------------------------------
void Update::encode_prefix(Writer& w) const {
    w.array(dev_id);
    write_cands(w, host_cands);
    write_blob16_capped(w, meta, kMaxMeta);
    write_auth_prefix(w, auth);
}

std::optional<Update> Update::decode(Reader& r) {
    Update m;
    m.dev_id = r.array<kDevIdLen>();
    if (!read_vec(r, m.host_cands, kMaxCandidates, read_candidate)) return std::nullopt;
    if (!read_blob16_capped(r, m.meta, kMaxMeta)) return std::nullopt;
    if (!read_auth(r, m.auth)) return std::nullopt;
    return m;
}

// --- Lookup ----------------------------------------------------------------
void Lookup::encode(Writer& w) const {
    w.array(id);
    w.u8(max);
    w.blob8(cookie);
}

std::optional<Lookup> Lookup::decode(Reader& r, const Header& h) {
    Lookup m;
    m.id  = r.array<kTopicIdLen>();
    m.max = r.u8();
    // Clamp rather than reject: a client asking for more than the ceiling gets
    // the ceiling, which is friendlier than an error and just as safe.
    if (m.max == 0) m.max = kLookupDefault;
    if (m.max > kLookupMax) m.max = kLookupMax;
    m.want_meta = (h.flags & flags::kWantMeta) != 0;
    auto cookie = r.blob8();
    if (!r.ok() || cookie.size() > kMaxCookieLen) return std::nullopt;
    m.cookie.assign(cookie.begin(), cookie.end());
    return m;
}

void PeerEntry::encode(Writer& w) const {
    w.array(dev_id);
    w.u16(age_secs);
    w.u8(stale ? flags::kStale : 0);
    write_cands(w, cands);
    write_blob16_capped(w, meta, kMaxMeta);
}

size_t PeerEntry::encoded_size() const {
    size_t n = kDevIdLen + 2 + 1 + 1;  // dev_id, age, flags, cand_count
    size_t c = cands.size() > kMaxCandidates ? kMaxCandidates : cands.size();
    for (size_t i = 0; i < c; ++i) n += 2 + cands[i].ep.ip.addr_len() + 2;  // kind, family, addr, port
    n += 2 + (meta.size() > kMaxMeta ? kMaxMeta : meta.size());
    return n;
}

std::optional<PeerEntry> PeerEntry::decode(Reader& r) {
    PeerEntry m;
    m.dev_id   = r.array<kDevIdLen>();
    m.age_secs = r.u16();
    m.stale    = (r.u8() & flags::kStale) != 0;
    if (!read_vec(r, m.cands, kMaxCandidates, read_candidate)) return std::nullopt;
    if (!read_blob16_capped(r, m.meta, kMaxMeta)) return std::nullopt;
    return m;
}

void LookupOk::encode(Writer& w) const {
    w.array(id);
    w.u8(static_cast<uint8_t>(mode));
    w.u16(total);
    w.u8(part);
    w.u8(parts);
    w.u8(static_cast<uint8_t>(entries.size()));
    for (const auto& e : entries) e.encode(w);
}

std::optional<LookupOk> LookupOk::decode(Reader& r) {
    LookupOk m;
    m.id = r.array<kTopicIdLen>();
    uint8_t mode = r.u8();
    if (mode > static_cast<uint8_t>(TopicMode::Keyed)) return std::nullopt;
    m.mode  = static_cast<TopicMode>(mode);
    m.total = r.u16();
    m.part  = r.u8();
    m.parts = r.u8();
    if (!r.ok() || m.parts == 0 || m.part >= m.parts) return std::nullopt;
    size_t n = r.u8();
    if (n > kLookupMax) return std::nullopt;
    m.entries.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        auto e = PeerEntry::decode(r);
        if (!e) return std::nullopt;
        m.entries.push_back(std::move(*e));
    }
    if (!r.ok()) return std::nullopt;
    return m;
}

// --- Resolve ---------------------------------------------------------------
void Resolve::encode(Writer& w) const {
    w.array(dev_id);
    w.blob8(cookie);
}

std::optional<Resolve> Resolve::decode(Reader& r) {
    Resolve m;
    m.dev_id = r.array<kDevIdLen>();
    auto c   = r.blob8();
    if (!r.ok() || c.size() > kMaxCookieLen) return std::nullopt;
    m.cookie.assign(c.begin(), c.end());
    return m;
}

// --- Stats -----------------------------------------------------------------
void Stats::encode(Writer& w) const { w.blob8(cookie); }

std::optional<Stats> Stats::decode(Reader& r) {
    Stats m;
    auto  c = r.blob8();
    if (!r.ok() || c.size() > kMaxCookieLen) return std::nullopt;
    m.cookie.assign(c.begin(), c.end());
    return m;
}

void ResolveOk::encode(Writer& w) const {
    w.u8(found ? 1 : 0);
    if (!found) return;
    w.array(topic);
    entry.encode(w);
}

std::optional<ResolveOk> ResolveOk::decode(Reader& r) {
    ResolveOk m;
    m.found = r.u8() != 0;
    if (!r.ok()) return std::nullopt;
    if (!m.found) return m;
    m.topic  = r.array<kTopicIdLen>();
    auto e   = PeerEntry::decode(r);
    if (!e) return std::nullopt;
    m.entry = std::move(*e);
    return m;
}

// --- Topics ----------------------------------------------------------------
void Topics::encode(Writer& w) const {
    w.u32(cursor);
    w.u8(limit);
    w.blob8(cookie);
}

std::optional<Topics> Topics::decode(Reader& r) {
    Topics m;
    m.cursor = r.u32();
    m.limit  = r.u8();
    if (m.limit == 0) m.limit = 100;
    auto cookie = r.blob8();
    if (!r.ok() || cookie.size() > kMaxCookieLen) return std::nullopt;
    m.cookie.assign(cookie.begin(), cookie.end());
    return m;
}

void TopicSummary::encode(Writer& w) const {
    w.array(id);
    w.u8(static_cast<uint8_t>(mode));
    w.u32(peers);
    w.u32(fresh_peers);
}

std::optional<TopicSummary> TopicSummary::decode(Reader& r) {
    TopicSummary m;
    m.id = r.array<kTopicIdLen>();
    uint8_t mode = r.u8();
    if (mode > static_cast<uint8_t>(TopicMode::Keyed)) return std::nullopt;
    m.mode        = static_cast<TopicMode>(mode);
    m.peers       = r.u32();
    m.fresh_peers = r.u32();
    if (!r.ok()) return std::nullopt;
    return m;
}

void TopicsOk::encode(Writer& w) const {
    w.u32(next_cursor);
    w.u8(part);
    w.u8(parts);
    w.u8(static_cast<uint8_t>(topics.size()));
    for (const auto& t : topics) t.encode(w);
}

std::optional<TopicsOk> TopicsOk::decode(Reader& r) {
    TopicsOk m;
    m.next_cursor = r.u32();
    m.part        = r.u8();
    m.parts       = r.u8();
    if (!r.ok() || m.parts == 0 || m.part >= m.parts) return std::nullopt;
    size_t n = r.u8();
    m.topics.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        auto t = TopicSummary::decode(r);
        if (!t) return std::nullopt;
        m.topics.push_back(*t);
    }
    if (!r.ok()) return std::nullopt;
    return m;
}

// --- Connect / Relayed -----------------------------------------------------
void Connect::encode_prefix(Writer& w) const {
    w.array(from_dev);
    w.array(to_dev);
    write_blob16_capped(w, payload, kMaxRelayPayload);
    write_auth_prefix(w, auth);
}

std::optional<Connect> Connect::decode(Reader& r) {
    Connect m;
    m.from_dev = r.array<kDevIdLen>();
    m.to_dev   = r.array<kDevIdLen>();
    if (!read_blob16_capped(r, m.payload, kMaxRelayPayload)) return std::nullopt;
    if (!read_auth(r, m.auth)) return std::nullopt;
    return m;
}

void Relayed::encode(Writer& w) const {
    w.array(from_dev);
    write_blob16_capped(w, payload, kMaxRelayPayload);
}

std::optional<Relayed> Relayed::decode(Reader& r) {
    Relayed m;
    m.from_dev = r.array<kDevIdLen>();
    if (!read_blob16_capped(r, m.payload, kMaxRelayPayload)) return std::nullopt;
    return m;
}

// --- Relay -----------------------------------------------------------------
void RelayAlloc::encode_prefix(Writer& w) const {
    w.array(from_dev);
    w.array(peer_dev);
    write_auth_prefix(w, auth);
}

std::optional<RelayAlloc> RelayAlloc::decode(Reader& r) {
    RelayAlloc m;
    m.from_dev = r.array<kDevIdLen>();
    m.peer_dev = r.array<kDevIdLen>();
    if (!read_auth(r, m.auth)) return std::nullopt;
    return m;
}

void RelayAllocOk::encode(Writer& w) const {
    w.u64(relay_id);
    w.u16(expires_in);
    w.u32(max_kib);
}

std::optional<RelayAllocOk> RelayAllocOk::decode(Reader& r) {
    RelayAllocOk m;
    m.relay_id   = r.u64();
    m.expires_in = r.u16();
    m.max_kib    = r.u32();
    if (!r.ok()) return std::nullopt;
    return m;
}

void RelayData::encode(Writer& w) const {
    w.u64(relay_id);
    write_blob16_capped(w, payload, kMaxDatagram);
}

std::optional<RelayData> RelayData::decode(Reader& r) {
    RelayData m;
    m.relay_id = r.u64();
    if (!read_blob16_capped(r, m.payload, kMaxDatagram)) return std::nullopt;
    return m;
}

// --- Retry / Error ---------------------------------------------------------
void Retry::encode(Writer& w) const { w.blob8(cookie); }

std::optional<Retry> Retry::decode(Reader& r) {
    Retry m;
    auto c = r.blob8();
    if (!r.ok() || c.size() > kMaxCookieLen) return std::nullopt;
    m.cookie.assign(c.begin(), c.end());
    return m;
}

void Error::encode(Writer& w) const {
    w.u16(static_cast<uint16_t>(code));
    size_t n = reason.size() > 255 ? 255 : reason.size();
    w.u8(static_cast<uint8_t>(n));
    w.bytes(reinterpret_cast<const uint8_t*>(reason.data()), n);
}

std::optional<Error> Error::decode(Reader& r) {
    Error m;
    m.code = static_cast<ErrorCode>(r.u16());
    auto s = r.blob8();
    if (!r.ok()) return std::nullopt;
    m.reason.assign(reinterpret_cast<const char*>(s.data()), s.size());
    return m;
}

// --- Probe -----------------------------------------------------------------
void Probe::encode(Writer& w) const {
    w.array(txn);
    w.array(tag);
}

std::optional<Probe> Probe::decode(Reader& r) {
    Probe m;
    m.txn = r.array<kProbeTxnLen>();
    m.tag = r.array<kProbeTagLen>();
    if (!r.ok()) return std::nullopt;
    return m;
}

void ProbeOk::encode(Writer& w) const {
    w.array(txn);
    w.endpoint(mapped);
    w.array(tag);
}

std::optional<ProbeOk> ProbeOk::decode(Reader& r) {
    ProbeOk m;
    m.txn    = r.array<kProbeTxnLen>();
    m.mapped = r.endpoint();
    m.tag    = r.array<kProbeTagLen>();
    if (!r.ok()) return std::nullopt;
    return m;
}

// --- Noise -----------------------------------------------------------------
void HandshakeInit::encode(Writer& w) const {
    w.u32(conn_id);
    w.array(probe_txn);
    w.bytes(noise_msg);
}

std::optional<HandshakeInit> HandshakeInit::decode(Reader& r) {
    HandshakeInit m;
    m.conn_id   = r.u32();
    m.probe_txn = r.array<kProbeTxnLen>();
    if (!r.ok()) return std::nullopt;
    auto rest = r.bytes(r.remaining());  // handshake message runs to end of datagram
    m.noise_msg.assign(rest.begin(), rest.end());
    return m;
}

void HandshakeResp::encode(Writer& w) const {
    w.u32(conn_id);
    w.bytes(noise_msg);
}

std::optional<HandshakeResp> HandshakeResp::decode(Reader& r) {
    HandshakeResp m;
    m.conn_id = r.u32();
    if (!r.ok()) return std::nullopt;
    auto rest = r.bytes(r.remaining());
    m.noise_msg.assign(rest.begin(), rest.end());
    return m;
}

void Transport::encode(Writer& w) const {
    w.u32(conn_id);
    w.u64(counter);
    w.bytes(ciphertext);
}

std::optional<Transport> Transport::decode(Reader& r) {
    Transport m;
    m.conn_id = r.u32();
    m.counter = r.u64();
    if (!r.ok()) return std::nullopt;
    m.ciphertext = r.bytes(r.remaining());  // view into the caller's datagram
    return m;
}

}  // namespace uconnect::wire
