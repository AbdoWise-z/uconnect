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

}  // namespace

// --- Directory entries -----------------------------------------------------
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

// --- Relayed ---------------------------------------------------------------
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

// --- Error -----------------------------------------------------------------
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

// --- Transport -------------------------------------------------------------
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
