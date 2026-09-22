#pragma once
// StreamConnection: reliable, ordered, flow-controlled, multiplexed streams
// over the unreliable datagrams that session::Session provides.
//
// This is the layer that supplies what the session layer deliberately does not:
//
//                      session::Session        StreamConnection
//   confidentiality         yes                      (inherited)
//   authentication          yes                      (inherited)
//   deduplication           yes                      (inherited)
//   reliability             no                       YES
//   ordering                no                       YES (per stream)
//   flow control            no                       YES (per stream + connection)
//   congestion control      no                       YES (NewReno)
//   byte-stream framing     no                       YES
//
// Sans-IO, like everything below the io layer: it consumes a datagram payload
// plus `now` and produces datagram payloads plus events. It never sees a
// socket, and a full lossy exchange runs deterministically in microseconds.
//
// Head-of-line blocking is per stream, not per connection -- the point of
// multiplexing. A lost packet on stream 4 stalls stream 4; stream 8 keeps
// flowing. That is the property TCP cannot offer and the reason this is built
// on datagrams rather than on a single ordered pipe.

#include <functional>
#include <map>
#include <optional>
#include <vector>

#include "buffers.hpp"
#include "frame.hpp"
#include "recovery.hpp"
#include "uconnect/types.hpp"

namespace uconnect::stream {

struct StreamConfig {
    // Per-stream receive window. The send side is bounded by whatever the peer
    // advertises, so this is the only knob that costs us memory.
    uint64_t stream_recv_window = 256 * 1024;

    // Connection-wide receive window, across all streams. Stops many idle-ish
    // streams from together pinning far more memory than any single one could.
    uint64_t conn_recv_window = 1024 * 1024;

    // How much unacknowledged application data one stream may hold. Bounds
    // memory on the send side, which the peer's window alone does not.
    size_t stream_send_cap = 1024 * 1024;

    // Usable payload inside one session datagram. The session adds a header
    // and an AEAD tag on top of this.
    size_t max_payload = 1100;

    // Give up on a peer that acknowledges nothing for this long.
    Duration idle_timeout{std::chrono::seconds(30)};

    // Consecutive probe timeouts before the connection is declared dead.
    uint32_t max_pto_count = 6;

    // Cap on live PEER-opened streams. The peer decides how many stream ids it
    // puts on the wire, and each one costs a recv and a send buffer, so without
    // this an authenticated peer can pin unbounded memory just by sending one
    // byte to each of a few million stream ids.
    //
    // Frames for streams beyond the cap are dropped rather than answered: any
    // reply would need per-id state, which is the thing being rationed. A
    // well-behaved peer never reaches the cap.
    uint64_t max_concurrent_streams = 64;
};

enum class StreamEventKind : uint8_t {
    Opened,      // the peer opened a stream
    Readable,    // ordered bytes are available
    Writable,    // flow control opened up after being blocked
    Finished,    // peer sent FIN and all data has been delivered
    Reset,       // peer aborted the stream
    Closed,      // stream fully done, both directions; state has been retired
    ConnDead,    // the whole connection failed (idle or too many PTOs)
};

struct StreamEvent {
    StreamEventKind kind{};
    StreamId        id         = 0;
    uint64_t        error_code = 0;
};

class StreamConnection {
public:
    // `role` must differ between the two ends, so concurrently-opened streams
    // never collide on an id. Derive it from the session's initiator role.
    StreamConnection(StreamConfig cfg, Role role);

    // --- application side --------------------------------------------------
    // Nullopt when max_concurrent_streams locally-opened streams are already
    // live. Retiring a finished stream frees a slot.
    std::optional<StreamId> open(bool bidirectional = true);

    // Returns bytes accepted. A short count means flow control or the send cap
    // is applying backpressure; wait for a Writable event.
    size_t write(StreamId, std::span<const uint8_t> data);

    // Reads the contiguous prefix only, so the application always sees bytes
    // in the order they were written.
    size_t read(StreamId, std::span<uint8_t> out);

    void finish(StreamId);                       // half-close: no more writes
    void reset(StreamId, uint64_t error_code);   // abort, discard pending data
    void stop_sending(StreamId, uint64_t error_code);

    bool   readable(StreamId) const;
    size_t readable_bytes(StreamId) const;
    bool   finished(StreamId) const;
    bool   writable(StreamId) const;
    bool   exists(StreamId) const;
    std::vector<StreamId> active_streams() const;

    // --- transport side ----------------------------------------------------
    // Feed a decrypted datagram payload together with the session packet
    // number it arrived in. The session layer guarantees no duplicates, so the
    // packet number is trustworthy for ack purposes.
    void on_datagram(uint64_t packet_number, std::span<const uint8_t> payload, Instant now);

    void on_timeout(Instant now);

    // Build the next datagram payload to send. Returns the number of bytes
    // written into `out`, or 0 when nothing is due -- either everything is
    // sent and acknowledged, or the congestion window is full.
    //
    // `packet_number` must be the number the session will actually use, so
    // loss recovery can match it against incoming acks.
    size_t poll_datagram(uint64_t packet_number, std::span<uint8_t> out, Instant now);

    std::optional<StreamEvent> poll_event();
    std::optional<Instant>     next_timeout() const;

    bool is_dead() const { return dead_; }

    // --- introspection -----------------------------------------------------
    size_t   congestion_window() const { return cc_.window(); }
    size_t   bytes_in_flight() const { return cc_.in_flight(); }
    Duration smoothed_rtt() const { return rtt_.smoothed(); }
    bool     in_slow_start() const { return cc_.in_slow_start(); }
    uint64_t packets_lost() const { return packets_lost_; }
    uint64_t packets_sent() const { return packets_sent_; }

private:
    struct StreamState {
        StreamId   id = 0;
        RecvBuffer recv;
        SendBuffer send;

        bool     send_reset      = false;
        uint64_t send_reset_code = 0;
        bool     reset_sent      = false;

        bool     send_stop       = false;
        uint64_t send_stop_code  = 0;
        bool     stop_sent       = false;

        bool peer_reset     = false;
        bool was_blocked    = false;
        bool fin_notified   = false;
        bool open_notified  = false;
        bool reset_notified = false;

        StreamState(StreamId i, uint64_t recv_window, uint64_t peer_window)
            : id(i), recv(recv_window), send(peer_window) {}
    };

    StreamState* find(StreamId);
    const StreamState* find(StreamId) const;

    // Null when the frame must be ignored: the id is over the peer's stream
    // cap, names a locally-opened stream we never opened, or refers to one
    // already retired. Callers drop the frame.
    StreamState* ensure_peer_stream(StreamId, Instant now);

    // A stream is retired once both directions are done and the application
    // has been told. Without this, streams_ grows for the life of the
    // connection and the stream cap could only ever be hit once.
    bool side_send_done(const StreamState&) const;
    bool side_recv_done(const StreamState&) const;
    void retire_done_streams();
    size_t live_streams(Role opened_by) const;

    void handle_frame(const Frame&, Instant now);
    void on_packet_acked(const SentPacket&);
    void on_packet_lost(const SentPacket&);
    void arm_loss_timer(Instant now);
    bool has_outstanding_work() const;
    void emit(StreamEventKind, StreamId, uint64_t code = 0);

    StreamConfig cfg_;
    Role         role_;

    std::map<StreamId, StreamState> streams_;
    uint64_t                        next_index_ = 0;

    // Retirement high-water mark for peer-opened streams. Indices are handed
    // out monotonically, so an id below the mark that is absent from the map is
    // a late frame for a retired stream, not a new one. A single counter, not
    // per-id tombstones, which would be unbounded again. Locally-opened ids
    // need no mark: an absent one is always refused.
    uint64_t retired_hwm_peer_ = 0;

    RttEstimator rtt_;
    Congestion   cc_;
    SentPackets  sent_;
    AckTracker   acks_;

    // Connection-level flow control, layered above the per-stream windows.
    uint64_t conn_recv_consumed_  = 0;
    uint64_t conn_recv_announced_ = 0;
    uint64_t conn_send_max_       = 0;
    uint64_t conn_send_used_      = 0;
    bool     send_max_data_       = false;

    std::vector<StreamEvent> events_;
    std::vector<Frame>       scratch_;

    uint32_t pto_count_   = 0;
    Instant  last_ack_rx_{};
    Instant  loss_timer_{};
    bool     loss_timer_armed_ = false;
    bool     dead_             = false;
    bool     started_          = false;

    uint64_t packets_sent_ = 0;
    uint64_t packets_lost_ = 0;
};

}  // namespace uconnect::stream
