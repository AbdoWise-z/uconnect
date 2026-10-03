#pragma once
// A secure session with one peer over a TCP connection: the Noise handshake,
// then AEAD-sealed records. Sans-IO like the UDP Session beside it -- it takes
// the bytes read from the socket and `now`, and hands back bytes to write and
// events.
//
// This is the primary channel. It carries the handshake, so its keys are the
// session's keys; the optional UDP datagram channel is keyed from it
// (datagram_keys()), never the other way round.
//
// Wire format, after the TCP connection is up:
//
//   initiator -> responder   u16 len | attempt(16) | Noise message 1
//   responder -> initiator   u16 len | Noise message 2
//   then, both ways          u32 len | AEAD(kind(1) | body)
//
// The attempt nonce names which introduction this connection answers. The
// server gave it to both sides with the CONNECT, it is bound into the Noise
// prologue, and the responder uses it to find the topic, peer and key before
// it can read anything else. It travels in the clear; what makes it safe is
// that the node accepts each one once, for the peer it was issued for.
//
// Roles do not follow the TCP connection: with a simultaneous open neither
// side "connected" to the other. The numerically smaller dev_id is always
// the Noise initiator -- the same tie-break used everywhere else.
//
// Nonces are sequential per direction: TCP is in order and loses nothing, so
// no counter travels on the wire and no replay window is needed.

#include <deque>
#include <optional>
#include <span>
#include <vector>

#include "kdf.hpp"
#include "noise.hpp"
#include "session.hpp"  // CloseCause
#include "uconnect/types.hpp"

namespace uconnect::session {

inline constexpr size_t kAttemptLen = 16;
using AttemptNonce = std::array<uint8_t, kAttemptLen>;

struct TcpSessionConfig {
    // Sent when nothing else has gone out for this long. TCP needs it too:
    // a NAT that sees no traffic drops the mapping, and nothing tells us.
    Duration keepalive{std::chrono::seconds(20)};

    // Declare the peer gone after this much silence.
    Duration idle_timeout{std::chrono::seconds(90)};

    Duration handshake_timeout{std::chrono::seconds(10)};

    // Largest record body accepted. A length above it is an attack or a bug,
    // and either way the connection ends rather than buffer it.
    size_t max_record = 1u << 20;

    // Ratchet each direction's key after this many records (Noise rekey).
    // Both ends count the same records, so there is nothing to coordinate.
    uint64_t rekey_every = 1ull << 20;
};

struct TcpEvent {
    enum class Kind : uint8_t {
        Established,
        Record,  // a record of a kind the layer above owns
        Closed,
    };

    Kind                 kind{};
    uint8_t              record_kind = 0;
    std::vector<uint8_t> body;

    CloseCause cause       = CloseCause::Local;  // Kind::Closed only
    uint16_t   peer_reason = 0;
};

class TcpSession {
public:
    ~TcpSession() { crypto::secure_zero(exported_); }
    TcpSession(TcpSession&&) noexcept = default;
    TcpSession& operator=(TcpSession&&) noexcept = default;
    TcpSession(const TcpSession&) = delete;
    TcpSession& operator=(const TcpSession&) = delete;
    enum class State : uint8_t { Handshaking, Established, Closed };

    // Record kinds below this are the session's own; the layer above uses
    // the rest, and sees only those.
    static constexpr uint8_t kFirstUserKind = 0x10;

    // `psk` null means an open topic (Noise NN); non-null a keyed one
    // (NNpsk0). A session never falls back from one to the other.
    static TcpSession initiate(TcpSessionConfig, const TopicId&, uint8_t key_epoch,
                               const crypto::SymKey* psk, const DevId& self, const DevId& peer,
                               const AttemptNonce&, Instant now);
    static TcpSession respond(TcpSessionConfig, const TopicId&, uint8_t key_epoch,
                              const crypto::SymKey* psk, const DevId& self, const DevId& peer,
                              const AttemptNonce&, Instant now);

    // The attempt an initiator's first frame names, once enough of it has
    // arrived. A responder needs this before it can build its session.
    static std::optional<AttemptNonce> peek_attempt(std::span<const uint8_t> received);

    // A responder that dialed opens with a hello -- 'U' 'C' and the attempt --
    // so an initiator holding a connection it ACCEPTED can tell who is calling.
    // It is not part of the handshake, and an initiator skips it wherever it
    // lands before message 2: after a TCP simultaneous open both ends think
    // they dialed, so the hello can arrive after message 1 has gone out --
    // and, when both introduced themselves at once, name the peer's attempt
    // rather than ours.
    static constexpr size_t kHelloLen = 2 + kAttemptLen;
    static std::vector<uint8_t>        hello(const AttemptNonce&);
    // The attempt a hello names, once all of it has arrived; nullopt if
    // `received` does not start with one (or has not got all of it yet).
    static std::optional<AttemptNonce> peek_hello(std::span<const uint8_t> received);

    // Everything read from the socket, in order.
    void on_bytes(std::span<const uint8_t>, Instant now);
    // The socket ended without a Close record: the peer vanished.
    void on_eof(Instant now);
    void on_timeout(Instant now);

    // Seal and queue a record. False if not established, `kind` is one of the
    // session's own, or the body is over max_record.
    bool send(uint8_t kind, std::span<const uint8_t> body, Instant now);

    // Tell the peer why, then end. Nothing more goes out after the Close.
    void close(uint16_t reason, Instant now);

    // Bytes to write to the socket, in order. Empties the queue.
    std::vector<uint8_t>        take_output();
    bool                        has_output() const { return !out_.empty(); }
    std::optional<TcpEvent>     poll_event();
    std::optional<Instant>      next_timeout() const;

    State                state() const { return state_; }
    bool                 is_initiator() const { return initiator_; }
    const DevId&         peer() const { return peer_; }
    const crypto::Hash&  handshake_hash() const { return handshake_hash_; }
    std::string          sas() const { return crypto::sas_string(handshake_hash_); }
    Instant              last_received() const { return last_recv_; }

    // Keys for the optional UDP datagram channel, derived from this handshake
    // under their own labels so the two channels share no key. `send` is this
    // side's sending direction; both ends compute the same conn_id.
    //
    // Each channel opened on this session uses a new `epoch`. The UDP channel
    // numbers its packets from zero, so opening a second one under the first
    // one's keys would reuse every nonce; a new epoch means new keys.
    struct DatagramKeys {
        crypto::SymKey send{};
        crypto::SymKey recv{};
        crypto::SymKey probe{};  // tags UDP probes: only the peer can elicit an answer
        uint32_t       conn_id = 0;
        ~DatagramKeys() {
            crypto::secure_zero(send);
            crypto::secure_zero(recv);
            crypto::secure_zero(probe);
        }
    };
    // Consumes the epoch's derivation secret. Old epochs cannot be derived
    // again; jumps are bounded to prevent a peer forcing unbounded KDF work.
    std::optional<DatagramKeys> datagram_keys(uint32_t epoch = 0);
    static constexpr uint64_t max_datagram_epoch_skip = 64;

private:
    TcpSession(TcpSessionConfig, bool initiator, const DevId& self, const DevId& peer,
               Instant now);

    static std::vector<uint8_t> prologue(const TopicId&, uint8_t key_epoch, const AttemptNonce&);
    void finish(crypto::Split, Instant now);
    void seal(uint8_t kind, std::span<const uint8_t> body);
    void fail(CloseCause, Instant now);
    void handle_record(std::span<const uint8_t> plain, Instant now);

    TcpSessionConfig cfg_;
    bool             initiator_ = false;
    DevId            self_{};
    DevId            peer_{};
    AttemptNonce     attempt_{};
    State            state_ = State::Handshaking;

    std::optional<crypto::HandshakeState> hs_;
    crypto::CipherState                   send_cs_;
    crypto::CipherState                   recv_cs_;
    uint64_t                              sent_records_ = 0;
    uint64_t                              recv_records_ = 0;
    crypto::Hash                          handshake_hash_{};
    crypto::Hash                          exported_{};
    uint64_t                              next_datagram_epoch_ = 0;

    std::vector<uint8_t> in_;
    std::vector<uint8_t> out_;
    std::deque<TcpEvent> events_;

    Instant started_{};
    Instant last_recv_{};
    Instant last_sent_{};
};

}  // namespace uconnect::session
