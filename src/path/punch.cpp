#include "punch.hpp"

#include <algorithm>
#include <cstring>

namespace uconnect::path {
namespace {

constexpr std::string_view kProbeDomain    = "uconnect:v1:probe-req";
constexpr std::string_view kProbeOkDomain  = "uconnect:v1:probe-res";

// ICE-style type preferences. Host is most direct; relay is a last resort.
constexpr uint32_t kPrefHost  = 126;
constexpr uint32_t kPrefSrflx = 100;
constexpr uint32_t kPrefRelay = 10;

std::vector<uint8_t> encode_probe(const wire::ProbeTxn& txn, const wire::ProbeTag& tag,
                                  uint32_t txn_id) {
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Probe, wire::kVersion, 0, txn_id}.encode(w);
    wire::Probe{txn, tag}.encode(w);
    buf.resize(w.size());
    return buf;
}

std::vector<uint8_t> encode_probe_ok(const wire::ProbeTxn& txn, const Endpoint& mapped,
                                     const wire::ProbeTag& tag, uint32_t txn_id) {
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::ProbeOk, wire::kVersion, 0, txn_id}.encode(w);
    wire::ProbeOk{txn, mapped, tag}.encode(w);
    buf.resize(w.size());
    return buf;
}

}  // namespace

// ---------------------------------------------------------------------------
// Probe tags
// ---------------------------------------------------------------------------
wire::ProbeTag PunchSession::probe_tag(const crypto::SymKey* probe_key,
                                       const wire::ProbeTxn& txn, bool is_response) {
    wire::ProbeTag tag{};
    // Open topics send a zero tag. There is no shared secret, so there is
    // nothing to prove; anyone may participate, which is what "open" means.
    if (!probe_key) return tag;

    // The tag covers only the transaction id, not addresses. A NAT rewrites the
    // source address in flight, so the two ends do not agree on what it is --
    // binding addresses here would make every tag fail behind NAT, which is the
    // only case that matters.
    std::vector<uint8_t> input;
    std::string_view     domain = is_response ? kProbeOkDomain : kProbeDomain;
    input.insert(input.end(), domain.begin(), domain.end());
    input.insert(input.end(), txn.begin(), txn.end());

    crypto::Hash h = crypto::Blake2s::mac(*probe_key, input);
    std::memcpy(tag.data(), h.data(), wire::kProbeTagLen);
    return tag;
}

// ---------------------------------------------------------------------------
// Construction and ranking
// ---------------------------------------------------------------------------
PunchSession::PunchSession(PunchConfig cfg, DevId peer, std::vector<Candidate> remote_cands,
                           LocalView local, const crypto::SymKey* probe_key)
    : cfg_(cfg), peer_(peer), local_(local) {
    if (probe_key) {
        probe_key_ = *probe_key;
        keyed_     = true;
    }

    pairs_.reserve(remote_cands.size());
    for (const auto& c : remote_cands) {
        // A peer's loopback HOST address is never reachable by us. But a
        // loopback SRFLX means the rendezvous server observed us both at
        // 127.0.0.1, i.e. we are on the same machine -- which is exactly the
        // case for local testing, so that one must be kept.
        if (c.ep.ip.is_loopback() && c.kind == Candidate::Kind::Host) continue;
        if (c.ep.port == 0) continue;
        Pair p;
        p.remote   = c;
        p.priority = rank(c);
        crypto::random_bytes(p.txn);
        pairs_.push_back(p);
    }

    // Highest priority first; probes go out in this order.
    std::sort(pairs_.begin(), pairs_.end(),
              [](const Pair& a, const Pair& b) { return a.priority > b.priority; });
}

uint32_t PunchSession::rank(const Candidate& c) const {
    uint32_t type_pref = kPrefSrflx;
    switch (c.kind) {
        case Candidate::Kind::Host:  type_pref = kPrefHost; break;
        case Candidate::Kind::Srflx: type_pref = kPrefSrflx; break;
        case Candidate::Kind::Relay: type_pref = kPrefRelay; break;
    }

    // Same-NAT detection. If the peer's reflexive address has the same IP as
    // ours, we are almost certainly behind the same NAT -- and there the srflx
    // pair frequently cannot work at all, because it needs the router to
    // hairpin a packet addressed to its own external IP back inside, which many
    // consumer routers simply drop. The host candidate is not an optimisation
    // there; it is the only thing that works.
    const bool same_nat = local_.our_srflx && c.kind == Candidate::Kind::Srflx &&
                          c.ep.ip == local_.our_srflx->ip;

    uint32_t score = type_pref << 16;

    // Deprioritise a srflx candidate that shares our public IP: that is the
    // hairpin case, and it is the least likely pair to succeed.
    if (same_nat) score = kPrefRelay << 16;

    // Prefer IPv6 where available -- it is frequently unfiltered end to end when
    // IPv4 is double-NATed.
    if (c.ep.ip.family == IpAddr::Family::V6) score += 4096;

    // Prefer globally routable addresses over private ones, except for host
    // candidates where a private address is exactly the point.
    if (c.kind != Candidate::Kind::Host && !c.ep.ip.is_private()) score += 512;

    return score;
}

// ---------------------------------------------------------------------------
// Driving
// ---------------------------------------------------------------------------
Duration PunchSession::backoff_for(int attempt) const {
    auto ms = cfg_.first_retransmit.count();
    for (int i = 0; i < attempt && ms < cfg_.max_retransmit.count(); ++i) ms *= 2;
    if (ms > cfg_.max_retransmit.count()) ms = cfg_.max_retransmit.count();

    // Jitter +/-25%. Without it, two peers that started together retransmit in
    // lockstep forever, and a pattern of collisions can persist.
    auto     r      = crypto::random_array<2>();
    uint32_t raw    = static_cast<uint32_t>(r[0]) << 8 | r[1];
    int64_t  spread = ms / 2;
    int64_t  jitter = spread == 0 ? 0 : static_cast<int64_t>(raw % static_cast<uint32_t>(spread + 1)) - spread / 2;
    return Duration{ms + jitter};
}

void PunchSession::begin(Instant now) {
    if (state_ != PunchState::Idle) return;
    started_ = now;

    if (pairs_.empty()) {
        state_ = PunchState::Failed;
        events_.push_back({PunchEvent::Kind::Failed, {}, {}, {}});
        return;
    }

    state_ = PunchState::Probing;
    // Stagger the burst: a peer with 8 candidates emitting 8 packets in one
    // instant looks like a flood and can trip rate limiting on the path.
    for (size_t i = 0; i < pairs_.size(); ++i) {
        pairs_[i].next_send = now + cfg_.stagger * static_cast<int64_t>(i);
    }
    on_timeout(now);
}

void PunchSession::emit_probe(Pair& p, Instant now) {
    if (p.attempts == 0) p.first_sent = now;
    auto tag = probe_tag(keyed_ ? &probe_key_ : nullptr, p.txn, /*is_response=*/false);
    out_.push_back({p.remote.ep, encode_probe(p.txn, tag, txn_counter_++)});
    ++p.attempts;
    p.next_send = now + backoff_for(p.attempts);
}

void PunchSession::on_timeout(Instant now) {
    if (state_ != PunchState::Probing) {
        // Still honour a pending nomination deadline after the last validation.
        if (nominate_at_ && now >= *nominate_at_) maybe_nominate(now);
        return;
    }

    if (now - started_ >= cfg_.total_timeout) {
        if (!nominated_) {
            // If something validated but we never got around to nominating,
            // take it rather than failing.
            maybe_nominate(now);
        }
        if (!nominated_) {
            state_ = PunchState::Failed;
            events_.push_back({PunchEvent::Kind::Failed, {}, {}, {}});
        }
        return;
    }

    bool any_live = false;
    for (auto& p : pairs_) {
        if (p.validated || p.exhausted) continue;
        if (p.attempts >= cfg_.max_attempts_per_pair) {
            p.exhausted = true;
            continue;
        }
        any_live = true;
        if (now >= p.next_send) emit_probe(p, now);
    }

    if (nominate_at_ && now >= *nominate_at_) maybe_nominate(now);

    if (!any_live && !nominated_) {
        bool any_validated =
            std::any_of(pairs_.begin(), pairs_.end(), [](const Pair& p) { return p.validated; });
        if (any_validated) {
            maybe_nominate(now);
        } else {
            state_ = PunchState::Failed;
            events_.push_back({PunchEvent::Kind::Failed, {}, {}, {}});
        }
    }
}

void PunchSession::on_datagram(const Endpoint& from, std::span<const uint8_t> dgram,
                               Instant now) {
    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h) return;

    if (h->type == wire::MsgType::Probe) {
        // The peer is punching us. Answering is what opens our NAT toward them,
        // so this matters even mid-attempt.
        auto reply = answer_probe(from, dgram, keyed_ ? &probe_key_ : nullptr, txn_counter_++);
        if (reply) out_.push_back(std::move(*reply));

        // Their probe arriving proves they are live and that the path works in
        // at least one direction. Bring our next probe to that address forward
        // instead of waiting out the backoff.
        for (auto& p : pairs_) {
            if (p.remote.ep == from && !p.validated && !p.exhausted) p.next_send = now;
        }
        return;
    }

    if (h->type != wire::MsgType::ProbeOk) return;

    auto ok = wire::ProbeOk::decode(r);
    if (!ok) return;

    auto expect = probe_tag(keyed_ ? &probe_key_ : nullptr, ok->txn, /*is_response=*/true);
    if (keyed_ && !crypto::ct_equal(expect, ok->tag)) return;  // drop silently

    for (size_t i = 0; i < pairs_.size(); ++i) {
        auto& p = pairs_[i];
        // Match on the transaction id, not the source address: a NAT may map
        // the reply from a different port than we sent to.
        if (!crypto::ct_equal(p.txn, ok->txn)) continue;
        if (p.validated) return;  // duplicate ProbeOk, ignore

        p.validated = true;
        p.rtt       = std::chrono::duration_cast<Duration>(now - p.first_sent);
        events_.push_back({PunchEvent::Kind::PathValidated, p.remote.ep, p.txn, p.rtt});

        if (!nominated_) {
            // Nothing can outrank the top pair, so take it immediately.
            bool is_best = (i == 0);
            if (is_best) {
                maybe_nominate(now);
            } else if (!nominate_at_) {
                nominate_at_ = now + cfg_.nomination_grace;
            }
        }
        return;
    }
}

void PunchSession::maybe_nominate(Instant now) {
    (void)now;
    if (nominated_) return;

    std::optional<size_t> best;
    for (size_t i = 0; i < pairs_.size(); ++i) {
        if (!pairs_[i].validated) continue;
        if (!best || pairs_[i].priority > pairs_[*best].priority) best = i;
    }
    if (!best) return;

    nominated_   = best;
    nominate_at_ = std::nullopt;
    state_       = PunchState::Nominated;
    events_.push_back({PunchEvent::Kind::Nominated, pairs_[*best].remote.ep, pairs_[*best].txn,
                       pairs_[*best].rtt});
}

// ---------------------------------------------------------------------------
// Responding to a peer's probe
// ---------------------------------------------------------------------------
std::optional<Outgoing> PunchSession::answer_probe(const Endpoint& from,
                                                   std::span<const uint8_t> dgram,
                                                   const crypto::SymKey* probe_key,
                                                   uint32_t txn_id) {
    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h || h->type != wire::MsgType::Probe) return std::nullopt;

    auto probe = wire::Probe::decode(r);
    if (!probe) return std::nullopt;

    if (probe_key) {
        auto expect = probe_tag(probe_key, probe->txn, /*is_response=*/false);
        // Drop silently. Any error response would turn this into an oracle for
        // topic membership: a scanner could learn that the key it guessed is
        // wrong, or worse, that this host is in some topic at all.
        if (!crypto::ct_equal(expect, probe->tag)) return std::nullopt;
    }

    auto tag = probe_tag(probe_key, probe->txn, /*is_response=*/true);
    // `from` is what we observed as their source -- report it back so they can
    // learn their own mapping on this path, which may differ from what the
    // rendezvous server saw if the NAT is symmetric.
    return Outgoing{from, encode_probe_ok(probe->txn, from, tag, txn_id)};
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------
std::optional<Outgoing> PunchSession::poll_transmit() {
    if (out_.empty()) return std::nullopt;
    Outgoing o = std::move(out_.front());
    out_.erase(out_.begin());
    return o;
}

std::optional<PunchEvent> PunchSession::poll_event() {
    if (events_.empty()) return std::nullopt;
    PunchEvent e = events_.front();
    events_.erase(events_.begin());
    return e;
}

std::optional<Instant> PunchSession::next_timeout() const {
    if (state_ != PunchState::Probing) {
        if (nominate_at_) return nominate_at_;
        return std::nullopt;
    }

    std::optional<Instant> soonest = started_ + cfg_.total_timeout;
    for (const auto& p : pairs_) {
        if (p.validated || p.exhausted) continue;
        if (p.attempts >= cfg_.max_attempts_per_pair) continue;
        if (!soonest || p.next_send < *soonest) soonest = p.next_send;
    }
    if (nominate_at_ && (!soonest || *nominate_at_ < *soonest)) soonest = nominate_at_;
    return soonest;
}

std::optional<Endpoint> PunchSession::nominated_path() const {
    if (!nominated_) return std::nullopt;
    return pairs_[*nominated_].remote.ep;
}

std::optional<wire::ProbeTxn> PunchSession::nominated_txn() const {
    if (!nominated_) return std::nullopt;
    return pairs_[*nominated_].txn;
}

}  // namespace uconnect::path
