#pragma once
// A secure session with one peer: Noise handshake bound to a validated path,
// then authenticated transport with replay protection and path migration.
// Sans-IO, like everything below the io layer.
//
// Handshake binding. The Noise prologue is
//
//     "uconnect:v1" || topic_id || key_epoch || probe_txn
//
// so both sides must agree on the topic, the key epoch and the exact probe
// transaction, or the handshake fails cryptographically rather than through a
// check someone remembered to write. The probe_txn term is what makes a
// replayed HandshakeInit useless: it arrives bound to a transaction the
// responder never issued.
//
// Forward secrecy over time. There is no in-place rekey in v1. Rekeying
// requires both ends to step in lockstep, and getting that wrong desynchronises
// a session in a way that looks like packet loss. Instead a session has a hard
// lifetime, after which it asks the layer above for a fresh handshake --
// the same approach WireGuard takes.

#include <deque>
#include <optional>
#include <vector>

#include "kdf.hpp"
#include "messages.hpp"
#include "noise.hpp"
#include "uconnect/types.hpp"

namespace uconnect::session {

enum class SessionState : uint8_t {
    Handshaking,
    Established,
    NeedsRehandshake,  // lifetime expired; the path is still good
    Closed,
};

struct SessionConfig {
    // Holds the NAT binding open on this specific path. The keepalive to the
    // rendezvous server does nothing for peer paths -- on many NATs those are
    // separate mappings with separate timers, so an idle peer session dies in
    // ~30s while the server record stays perfectly healthy.
    Duration keepalive{std::chrono::seconds(20)};

    // Declare the peer gone after this much silence.
    Duration idle_timeout{std::chrono::seconds(90)};

    // Re-handshake for forward secrecy. Short enough that a key compromise
    // exposes a bounded window.
    Duration max_lifetime{std::chrono::minutes(15)};

    Duration handshake_timeout{std::chrono::seconds(5)};
    int      handshake_retries = 4;
};

struct Outgoing {
    Endpoint             to;
    std::vector<uint8_t> data;
};

struct SessionEvent {
    enum class Kind : uint8_t {
        Established,
        Data,
        PathChanged,       // peer arrived from a new address; session survived
        NeedsRehandshake,
        Closed,
    };

    Kind                 kind{};
    std::vector<uint8_t> data;      // Kind::Data
    Endpoint             path{};    // Kind::PathChanged
};

// Anti-replay, IPsec style: a high-water mark plus a bitmap of the 64 counters
// below it. UDP reorders, so a strictly-increasing check would drop legitimate
// packets; accepting anything would let an attacker replay them.
class ReplayWindow {
public:
    static constexpr size_t kWidth = 64;

    // Returns false if this counter is a replay or too old to judge.
    bool accept(uint64_t counter);

    uint64_t highest() const { return highest_; }

private:
    uint64_t highest_ = 0;
    uint64_t bitmap_  = 0;
    bool     seen_    = false;
};

class Session {
public:
    // psk is null for an open topic (Noise_NN), non-null for keyed
    // (Noise_NNpsk0). A Session constructed with a psk NEVER falls back --
    // silent downgrade is how sound protocols get broken.
    static Session initiate(SessionConfig cfg, const TopicId&, uint8_t key_epoch,
                            const crypto::SymKey* psk, const DevId& peer, Endpoint path,
                            const wire::ProbeTxn& probe_txn, Instant now);

    // Responder side. Returns nullopt on any failure -- a bad PSK, an unknown
    // probe_txn, a malformed message. The caller must drop silently and send
    // nothing: any error response makes this an oracle for topic membership.
    static std::optional<Session> accept(SessionConfig cfg, const TopicId&, uint8_t key_epoch,
                                         const crypto::SymKey* psk, const DevId& peer,
                                         Endpoint from, const wire::ProbeTxn& probe_txn,
                                         std::span<const uint8_t> handshake_init_dgram,
                                         Instant now);

    void on_datagram(const Endpoint& from, std::span<const uint8_t> dgram, Instant now);
    void on_timeout(Instant now);

    // Queues an encrypted transport datagram. Returns false if not established.
    bool send(std::span<const uint8_t> payload, Instant now);
    void close(Instant now);

    std::optional<Outgoing>     poll_transmit();
    std::optional<SessionEvent> poll_event();
    std::optional<Instant>      next_timeout() const;

    SessionState   state() const { return state_; }
    wire::ConnId   conn_id() const { return conn_id_; }
    const DevId&   peer() const { return peer_; }
    const Endpoint& path() const { return path_; }
    bool           is_authenticated() const { return keyed_; }

    // Unique to this session, identical on both ends, unpredictable to anyone
    // who was not in it.
    //
    // The application layer MUST bind its identity proofs to this value. Signing
    // it is what stops an insider -- which on a keyed topic means anyone holding
    // K -- from capturing A's identity proof in one session and replaying it
    // into a second session to impersonate A to B.
    const crypto::Hash& handshake_hash() const { return handshake_hash_; }

    // Short Authentication String for open topics. Compare out of band; a
    // matching string proves no MITM, because an interposed attacker produces
    // two different handshake hashes.
    std::string sas() const;

    uint64_t messages_sent() const { return send_counter_; }
    uint64_t messages_received() const { return received_; }

private:
    Session(SessionConfig cfg, const DevId& peer, Endpoint path, bool keyed,
            wire::ConnId conn_id);

    static std::vector<uint8_t> make_prologue(const TopicId&, uint8_t key_epoch,
                                              const wire::ProbeTxn&);
    void  emit_handshake_init(Instant now);
    void  finish_handshake(crypto::Split, Instant now);
    void  queue_keepalive(Instant now);

    SessionConfig cfg_;
    DevId         peer_{};
    Endpoint      path_{};
    bool          keyed_    = false;
    wire::ConnId  conn_id_  = 0;
    SessionState  state_    = SessionState::Handshaking;
    bool          initiator_ = false;

    std::optional<crypto::HandshakeState> handshake_;
    std::vector<uint8_t>                  handshake_msg_;  // retransmit buffer
    int                                   handshake_attempts_ = 0;
    Instant                               handshake_next_{};

    crypto::CipherState send_cs_;
    crypto::CipherState recv_cs_;
    crypto::Hash        handshake_hash_{};
    ReplayWindow        replay_;

    uint64_t send_counter_ = 0;
    uint64_t received_     = 0;

    Instant established_at_{};
    Instant last_recv_{};
    Instant next_keepalive_{};

    std::vector<Outgoing>     out_;
    std::deque<SessionEvent>  events_;
};

}  // namespace uconnect::session
