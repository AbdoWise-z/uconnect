#pragma once
// NAT hole punching: candidate ranking, probe fan-out, path validation and
// nomination. Sans-IO -- it consumes datagrams and a clock reading, and
// produces datagrams and events. No sockets.
//
// This is the layer that cannot be debugged against the real internet, which is
// precisely why it takes `now` as a parameter: tests/test_punch.cpp drives it
// through four NAT behaviours, packet loss and reordering, deterministically,
// in microseconds.
//
// Shape of an attempt:
//
//   1. Rank the remote candidates. Host first when both peers report the same
//      srflx address (same-NAT), because many consumer routers will not hairpin
//      and the srflx pair simply cannot work there.
//   2. Fire probes at every candidate, staggered so one peer with 8 candidates
//      does not emit 8 packets in the same instant.
//   3. Retransmit with jittered exponential backoff. The first packets are
//      EXPECTED to be dropped -- until both sides have sent, neither NAT has a
//      reason to let the other in.
//   4. A pair is validated when a ProbeOk echoes our transaction id. That round
//      trip is the challenge-response, and it is what a handshake is later
//      gated on.
//   5. Nominate the best validated pair after a short grace window, so a host
//      path that validates 5ms later than a relayed one still wins.

#include <optional>
#include <vector>

#include "kdf.hpp"
#include "messages.hpp"
#include "primitives.hpp"
#include "uconnect/types.hpp"

namespace uconnect::path {

enum class PunchState : uint8_t {
    Idle,       // constructed, not started
    Probing,    // probes in flight
    Nominated,  // a path won; the session layer may now handshake on it
    Failed,     // every candidate exhausted
};

struct PunchConfig {
    // Initial retransmit interval. Doubles each attempt, jittered.
    Duration first_retransmit{std::chrono::milliseconds(100)};
    Duration max_retransmit{std::chrono::milliseconds(1600)};

    // Gap between probes to different candidates in one burst.
    Duration stagger{std::chrono::milliseconds(20)};

    // How long to keep trying before declaring failure. Punching commonly needs
    // several seconds: the two sides have to overlap, and the early packets are
    // lost by design.
    Duration total_timeout{std::chrono::seconds(8)};

    // After the first validation, wait this long for a better-ranked path
    // before nominating. Skipped when the validated pair is already the
    // top-ranked one, since nothing can beat it.
    Duration nomination_grace{std::chrono::milliseconds(50)};

    int max_attempts_per_pair = 7;
};

struct Outgoing {
    Endpoint             to;
    std::vector<uint8_t> data;
};

struct PunchEvent {
    enum class Kind : uint8_t {
        PathValidated,  // a candidate answered; more may still be in flight
        Nominated,      // this is the path to handshake on
        Failed,         // no candidate answered before the timeout
    };

    Kind           kind{};
    Endpoint       path{};
    wire::ProbeTxn txn{};  // the validated transaction -- binds the handshake
    Duration       rtt{};
};

// Ranking inputs that the caller knows and this layer does not.
struct LocalView {
    // Our own reflexive address, as the rendezvous server reported it. Used
    // only to detect the same-NAT case by comparing IPs with the peer.
    std::optional<Endpoint> our_srflx;
};

class PunchSession {
public:
    // probe_key is HKDF(K, "uconnect:v1:probe") for a keyed topic, or nullptr
    // for an open one. When present, a non-member cannot produce a valid probe
    // and therefore cannot even elicit a response -- you never confirm your
    // existence to a scanner.
    PunchSession(PunchConfig cfg, DevId peer, std::vector<Candidate> remote_cands,
                 LocalView local, const crypto::SymKey* probe_key);

    void begin(Instant now);

    // Feed every datagram whose first byte classifies as MsgClass::Probe.
    void on_datagram(const Endpoint& from, std::span<const uint8_t> dgram, Instant now);

    void on_timeout(Instant now);

    std::optional<Outgoing>   poll_transmit();
    std::optional<PunchEvent> poll_event();
    std::optional<Instant>    next_timeout() const;

    PunchState              state() const { return state_; }
    const DevId&            peer() const { return peer_; }
    std::optional<Endpoint> nominated_path() const;
    std::optional<wire::ProbeTxn> nominated_txn() const;

    // Answer a probe from a peer that is punching us. Responding is what opens
    // our NAT toward them, so this must happen even for a peer we have no
    // pending attempt for -- which is the responder side of a simultaneous
    // punch.
    static std::optional<Outgoing> answer_probe(const Endpoint& from,
                                                std::span<const uint8_t> dgram,
                                                const crypto::SymKey* probe_key,
                                                uint32_t txn_id);

    // Exposed for tests and for the session layer's freshness check.
    static wire::ProbeTag probe_tag(const crypto::SymKey* probe_key,
                                    const wire::ProbeTxn& txn, bool is_response);

    size_t pair_count() const { return pairs_.size(); }

private:
    struct Pair {
        Candidate      remote{};
        uint32_t       priority = 0;
        wire::ProbeTxn txn{};
        Instant        next_send{};
        Instant        first_sent{};
        int            attempts  = 0;
        bool           validated = false;
        bool           exhausted = false;
        Duration       rtt{};
    };

    uint32_t rank(const Candidate&) const;
    void     emit_probe(Pair&, Instant now);
    void     maybe_nominate(Instant now);
    Duration backoff_for(int attempt) const;

    PunchConfig            cfg_;
    DevId                  peer_{};
    LocalView              local_{};
    bool                   keyed_ = false;
    crypto::SymKey         probe_key_{};
    std::vector<Pair>      pairs_;
    PunchState             state_ = PunchState::Idle;

    Instant                started_{};
    std::optional<Instant> nominate_at_;
    std::optional<size_t>  nominated_;

    std::vector<Outgoing>   out_;
    std::vector<PunchEvent> events_;
    uint32_t                txn_counter_ = 1;
};

}  // namespace uconnect::path
