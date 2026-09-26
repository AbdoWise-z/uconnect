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

    // Ratchet the transport keys every 2^rekey_shift packets.
    //
    // Driven by the packet counter rather than a clock, and that is the whole
    // trick: the counter travels in every header, so both ends compute the same
    // generation from data that arrived with the packet. There is no switch to
    // coordinate and therefore nothing to desynchronise -- which is the failure
    // this avoids, because a key mismatch shows up as a failed AEAD tag, and a
    // failed tag is dropped silently. Disagreeing about the current key looks
    // exactly like total packet loss, with no counter or log line to say so.
    //
    // 2^16 packets is roughly 78 MB at 1200-byte payloads. It must stay above
    // ReplayWindow::kWidth: the replay window will not accept a packet more
    // than 64 counters behind the high-water mark, which is what guarantees a
    // straggler is at most ONE generation old and so only the previous key has
    // to be kept.
    uint8_t  rekey_shift = 16;

    // How far ahead a received counter may jump before the packet is dropped
    // unread. A legitimate jump of one generation means 2^rekey_shift
    // consecutive packets lost, long after PTO would have given up.
    //
    // The cap exists because key selection necessarily happens BEFORE the AEAD
    // can verify anything -- a key is needed to attempt decryption at all -- so
    // an unauthenticated counter decides how much derivation work to do. Left
    // unbounded, a packet claiming counter 2^60 would walk the ratchet 2^44
    // times.
    uint64_t max_generations_ahead = 2;
};

struct Outgoing {
    Endpoint             to;
    std::vector<uint8_t> data;
};

// Why a session ended. Set by us, never by the peer -- a peer supplies only
// `peer_reason`, so a hostile one cannot make its own disappearance look like
// our idle timer or our own call to close().
enum class CloseCause : uint8_t {
    Local,       // we tore it down
    TimedOut,    // silence past the idle timeout, or a handshake that gave up
    PeerNotice,  // the peer sent a Close; peer_reason carries its code
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

    // The session packet number this datagram arrived in. The stream layer
    // above needs it to acknowledge the datagram; the session has already
    // guaranteed it is free of duplicates, so it is trustworthy for that.
    uint64_t packet_number = 0;

    // Kind::Closed only.
    CloseCause cause       = CloseCause::Local;
    uint16_t   peer_reason = 0;   // meaningful only when cause == PeerNotice
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
    // `self` is our own dev_id. It travels in message 1's payload -- which was
    // padding anyway, so it costs nothing on the wire, and on a keyed topic it
    // is encrypted under the PSK and covered by the AEAD tag.
    //
    // The responder needs it because it cannot reliably identify us by source
    // address: behind a symmetric NAT the address a handshake ARRIVES from is
    // not the address we ADVERTISED, so address matching silently fails and the
    // session gets filed under a synthetic identity.
    static Session initiate(SessionConfig cfg, const TopicId&, uint8_t key_epoch,
                            const crypto::SymKey* psk, const DevId& self, const DevId& peer,
                            Endpoint path, const wire::ProbeTxn& probe_txn, Instant now);

    // Responder side. Returns nullopt on any failure -- a bad PSK, an unknown
    // probe_txn, a malformed message. The caller must drop silently and send
    // nothing: any error response makes this an oracle for topic membership.
    // The peer's dev_id is LEARNED from the authenticated handshake payload and
    // exposed via peer(); `fallback_peer` is used only if the initiator sent a
    // zero dev_id (i.e. it had not registered yet).
    static std::optional<Session> accept(SessionConfig cfg, const TopicId&, uint8_t key_epoch,
                                         const crypto::SymKey* psk, const DevId& fallback_peer,
                                         Endpoint from, const wire::ProbeTxn& probe_txn,
                                         std::span<const uint8_t> handshake_init_dgram,
                                         Instant now);

    void on_datagram(const Endpoint& from, std::span<const uint8_t> dgram, Instant now);
    void on_timeout(Instant now);

    // Returns the packet number used, or nullopt if not established. The
    // caller must know the number BEFORE building a payload that references
    // it, so next_send_counter() lets it peek first.
    std::optional<uint64_t> send(std::span<const uint8_t> payload, Instant now);
    uint64_t next_send_counter() const { return send_counter_; }

    // Local teardown. Nothing goes on the wire, so the peer only finds out when
    // its idle timeout expires.
    void close(Instant now);

    // Tell the peer first, then tear down. Best effort by construction: the
    // notice is unacknowledged, so it is sent a few times and the peer's idle
    // timeout remains the backstop. Use this for a deliberate disconnect --
    // the difference between "goodbye" and a cable being pulled is worth 90
    // seconds of the peer holding a NAT binding and possibly a relay slot.
    void close_with_notice(uint16_t reason, Instant now);

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
    void  queue_close(uint16_t reason);
    void  close_with_cause(Instant now, CloseCause, uint16_t peer_reason);

    // Ratchet the send key forward to whatever generation `counter` belongs to.
    // The counter advances by one per packet, so this steps at most once and
    // forgets the old key immediately -- which is what makes past traffic
    // unrecoverable after a later compromise.
    void advance_send_keys(uint64_t counter);

    // Decrypt a transport-class payload: pick the generation, verify, replay
    // check, and only then adopt a new generation. Returns plaintext length, or
    // nullopt if the packet must be dropped.
    //
    // Everything that mutates state lives after the AEAD here, deliberately.
    // Key selection has to happen on an unauthenticated counter, so a forged
    // packet must be able to cost a dropped packet and nothing more -- not a
    // discarded key that real traffic still needed.
    std::optional<size_t> open_packet(uint64_t counter, std::span<const uint8_t> ad,
                                      std::span<const uint8_t> ciphertext,
                                      std::span<uint8_t> out);

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

    // Key generation, derived from the packet counter rather than tracked.
    // recv_cs_ is generation recv_gen_; recv_cs_prev_ is the one before it and
    // exists only so a straggler from just before a boundary still decrypts.
    // One previous generation is provably enough -- see rekey_shift.
    crypto::CipherState recv_cs_prev_;
    uint64_t            send_gen_ = 0;
    uint64_t            recv_gen_ = 0;
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
