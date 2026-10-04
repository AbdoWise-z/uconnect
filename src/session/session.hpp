#pragma once
// The UDP datagram channel with one peer: AEAD-sealed datagrams with replay
// protection, a counter-driven key ratchet and path migration. Sans-IO, like
// everything below the io layer.
//
// There is no handshake here. The peer connection's TcpSession runs Noise and
// hands this channel its keys (TcpSession::datagram_keys()), so the two
// channels authenticate the same peer and share nothing a compromise of one
// could reach the other through. A Session exists only while that TCP session
// does.
//
// The path is set by the layer above -- a punched address, or the rendezvous
// server's UDP relay -- and may change under a live session: the counters, and
// so the nonces, carry on, and a nonce is never used twice under one key.

#include <deque>
#include <optional>
#include <vector>

#include "kdf.hpp"
#include "messages.hpp"
#include "noise.hpp"
#include "uconnect/types.hpp"

namespace uconnect::session {

enum class SessionState : uint8_t {
    Established,
    Closed,
};

struct SessionConfig {
    // Holds the NAT binding open on this specific path. The TCP connection's
    // traffic does nothing for it -- a UDP mapping has its own timer, often
    // around 30 seconds.
    Duration keepalive{std::chrono::seconds(20)};

    // Declare the path dead after this much silence.
    Duration idle_timeout{std::chrono::seconds(90)};

    // Ratchet the keys every 2^rekey_shift packets.
    //
    // Both ends must agree on this shift before traffic starts. After that,
    // the counter in each packet selects its generation without a separate
    // switch message. Disagreeing about the schedule fails authentication and
    // silently drops valid packets, looking exactly like packet loss.
    //
    // 2^16 packets is roughly 78 MB at 1200-byte payloads. It must stay above
    // ReplayWindow::kWidth: the replay window will not accept a packet more
    // than 64 counters behind the high-water mark, which is what guarantees a
    // straggler is at most ONE generation old and so only the previous key has
    // to be kept.
    uint8_t rekey_shift = 16;

    // How far ahead a received counter may jump and still be tried at once. A
    // legitimate jump of one generation means 2^rekey_shift consecutive
    // packets lost.
    //
    // The cap exists because key selection necessarily happens BEFORE the AEAD
    // can verify anything -- a key is needed to attempt decryption at all -- so
    // an unauthenticated counter decides how much derivation work to do. Left
    // unbounded, a packet claiming counter 2^60 would walk the ratchet 2^44
    // times.
    uint64_t max_generations_ahead = 2;

    // A longer jump is still tried, but at most once per far_jump_interval and
    // never beyond max_generations_far. Without it a loss of a few generations
    // -- a few hundred packets at the smallest schedule -- stranded the
    // receiver for good: every later packet was further ahead still. With it,
    // the first packet after the gap resyncs, while forged counters can spend
    // only that budget, not the CPU.
    uint64_t max_generations_far = 4096;
    Duration far_jump_interval{std::chrono::milliseconds(250)};
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
    TimedOut,    // silence past the idle timeout
    PeerNotice,  // the peer sent a Close; peer_reason carries its code
};

struct SessionEvent {
    enum class Kind : uint8_t {
        Data,
        PathChanged,  // peer arrived from a new address; session survived
        Closed,
    };

    Kind                 kind{};
    std::vector<uint8_t> data;    // Kind::Data
    Endpoint             path{};  // Kind::PathChanged

    // Kind::Closed only.
    CloseCause cause       = CloseCause::Local;
    uint16_t   peer_reason = 0;  // meaningful only when cause == PeerNotice
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
    // `send` and `recv` are this side's two directions; the peer's are the
    // other way round. `conn_id` is the same on both ends and travels in every
    // packet, so a packet finds its session whatever address it came from.
    Session(SessionConfig cfg, const DevId& peer, Endpoint path, const crypto::SymKey& send,
            const crypto::SymKey& recv, wire::ConnId conn_id, Instant now);

    void on_datagram(const Endpoint& from, std::span<const uint8_t> dgram, Instant now);
    void on_timeout(Instant now);

    // Returns the packet number used, or nullopt if closed or payload is empty.
    std::optional<uint64_t> send(std::span<const uint8_t> payload, Instant now);

    // Send from now on to `path`. The counters carry on: the keys are the same.
    void set_path(const Endpoint& path, Instant now);

    // Agree a schedule before exchanging any packets. Once used, the channel's
    // keys/counters must never be reinterpreted under a different schedule.
    bool configure_rekey_shift(uint8_t shift);

    // Local teardown. Nothing goes on the wire, so the peer only finds out when
    // its idle timeout expires.
    void close(Instant now);

    // Tell the peer first, then tear down. Best effort by construction: the
    // notice is unacknowledged, so it is sent a few times and the peer's idle
    // timeout remains the backstop.
    void close_with_notice(uint16_t reason, Instant now);

    std::optional<Outgoing>     poll_transmit();
    std::optional<SessionEvent> poll_event();
    std::optional<Instant>      next_timeout() const;

    SessionState    state() const { return state_; }
    wire::ConnId    conn_id() const { return conn_id_; }
    const DevId&    peer() const { return peer_; }
    const Endpoint& path() const { return path_; }

    uint64_t messages_sent() const { return send_counter_; }
    uint64_t messages_received() const { return received_; }

    // When the peer last proved itself -- a packet that passed the AEAD. A
    // peer that is alive refreshes this at least every keepalive interval.
    Instant last_received() const { return last_recv_; }

private:
    std::optional<uint64_t> send_packet(std::span<const uint8_t>, Instant now);
    void queue_keepalive(Instant now);
    void queue_close(uint16_t reason);
    void close_with_cause(Instant now, CloseCause, uint16_t peer_reason);

    // The key generation `counter` belongs to. A shift of 64 or more would be
    // undefined behaviour -- on x86 it wraps to a shift by zero, a new key per
    // packet -- so it is taken at its word instead: generations wider than the
    // counter, i.e. never rekey.
    uint64_t generation(uint64_t counter) const {
        return cfg_.rekey_shift >= 64 ? 0 : counter >> cfg_.rekey_shift;
    }

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
                                      std::span<uint8_t> out, Instant now);

    SessionConfig cfg_;
    DevId         peer_{};
    Endpoint      path_{};
    wire::ConnId  conn_id_ = 0;
    SessionState  state_   = SessionState::Established;

    crypto::CipherState send_cs_;
    crypto::CipherState recv_cs_;

    // Key generation, derived from the packet counter rather than tracked.
    // recv_cs_ is generation recv_gen_; recv_cs_prev_ is the one before it and
    // exists only so a straggler from just before a boundary still decrypts.
    // One previous generation is provably enough -- see rekey_shift.
    crypto::CipherState recv_cs_prev_;
    uint64_t            send_gen_ = 0;
    uint64_t            recv_gen_ = 0;
    ReplayWindow        replay_;
    Instant             next_far_jump_{};  // when a jump past max_generations_ahead may next be tried

    uint64_t send_counter_ = 0;
    uint64_t received_     = 0;

    Instant last_recv_{};
    Instant next_keepalive_{};

    std::vector<Outgoing>    out_;
    std::deque<SessionEvent> events_;
};

}  // namespace uconnect::session
