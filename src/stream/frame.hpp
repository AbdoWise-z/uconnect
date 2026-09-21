#pragma once
// Frames carried inside a Session datagram.
//
// The session layer gives us an authenticated, encrypted, deduplicated
// datagram with a packet number (the AEAD counter). It gives us nothing else:
// datagrams are lost, reordered, and unacknowledged. This layer builds the
// missing half -- reliability, ordering and flow control -- by packing typed
// frames into those datagrams, in the manner of QUIC (RFC 9000).
//
// One datagram carries many frames. A single write of 4 KB becomes several
// STREAM frames across several datagrams; an ACK usually rides along with
// whatever data was going out anyway rather than costing a packet of its own.
//
// Why frames rather than one-message-per-datagram: acknowledgement and flow
// control have to travel continuously and in both directions. Giving them
// their own packets would roughly double packet count on a request/response
// workload.

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "buffer.hpp"
#include "uconnect/types.hpp"

namespace uconnect::stream {

// A stream identifier encodes who opened it and whether it is bidirectional,
// so the two ends can allocate ids concurrently without ever colliding --
// there is no central allocator in a peer-to-peer session.
//
//   bit 0 : 0 = opened by role A, 1 = opened by role B
//   bit 1 : 0 = bidirectional,    1 = unidirectional
//
// Role A is the session's designated initiator (the peer with the numerically
// smaller dev_id -- the same tie-break that settles handshake glare), so both
// ends agree on roles without negotiating.
using StreamId = uint64_t;

enum class Role : uint8_t { A = 0, B = 1 };

constexpr bool     is_bidi(StreamId id) { return (id & 0x2) == 0; }
constexpr Role     opener(StreamId id) { return static_cast<Role>(id & 0x1); }
constexpr StreamId make_stream_id(Role r, bool bidi, uint64_t index) {
    return (index << 2) | (bidi ? 0 : 0x2) | static_cast<uint64_t>(r);
}

enum class FrameType : uint8_t {
    Padding       = 0x00,
    Ping          = 0x01,
    Ack           = 0x02,
    ResetStream   = 0x03,
    StopSending   = 0x04,
    MaxData       = 0x05,
    MaxStreamData = 0x06,
    DataBlocked   = 0x07,
    // 0x08..0x0F are STREAM, with the low three bits carrying flags.
    StreamBase    = 0x08,
};

namespace stream_flags {
inline constexpr uint8_t kFin    = 0x01;  // this is the last byte of the stream
inline constexpr uint8_t kLen    = 0x02;  // an explicit length follows
inline constexpr uint8_t kOffset = 0x04;  // an explicit offset follows (absent => 0)
}  // namespace stream_flags

// --- frames ----------------------------------------------------------------
struct StreamFrame {
    StreamId                 id     = 0;
    uint64_t                 offset = 0;
    bool                     fin    = false;
    std::span<const uint8_t> data{};  // view into the enclosing datagram
};

// A contiguous run of acknowledged packet numbers, newest first.
struct AckRange {
    uint64_t gap   = 0;  // unacked packets between this range and the previous
    uint64_t len   = 0;  // additional packets in this range beyond the first
};

struct AckFrame {
    uint64_t              largest = 0;
    uint64_t              delay_us = 0;   // how long the receiver sat on this ack
    uint64_t              first_range = 0;
    std::vector<AckRange> ranges;

    // Smallest packet number this frame acknowledges.
    uint64_t smallest() const;

    // Invoke fn(packet_number) for every acknowledged packet, newest first.
    //
    // Ranges are encoded descending and relative, per RFC 9000 s19.3.1. The
    // first range is [largest - first_range, largest]; thereafter each `gap`
    // counts the unacknowledged packets between ranges, offset by two because
    // a gap of zero still means one missing packet. Every step is guarded
    // against underflow -- these values come off the wire from a peer that is
    // authenticated but not trusted to be sane.
    template <typename F>
    void for_each(F&& fn) const {
        if (first_range > largest) return;

        uint64_t hi = largest;
        uint64_t lo = largest - first_range;
        for (uint64_t p = hi;; --p) {
            fn(p);
            if (p == lo) break;
        }

        uint64_t prev_lo = lo;
        for (const auto& r : ranges) {
            if (prev_lo < r.gap + 2) return;
            uint64_t range_hi = prev_lo - r.gap - 2;
            if (r.len > range_hi) return;
            uint64_t range_lo = range_hi - r.len;
            for (uint64_t p = range_hi;; --p) {
                fn(p);
                if (p == range_lo) break;
            }
            prev_lo = range_lo;
        }
    }
};

struct ResetStreamFrame {
    StreamId id         = 0;
    uint64_t error_code = 0;
    uint64_t final_size = 0;
};

struct StopSendingFrame {
    StreamId id         = 0;
    uint64_t error_code = 0;
};

struct MaxDataFrame {
    uint64_t max = 0;
};

struct MaxStreamDataFrame {
    StreamId id  = 0;
    uint64_t max = 0;
};

struct DataBlockedFrame {
    uint64_t limit = 0;
};

// A decoded frame. Deliberately a tagged union rather than std::variant: the
// decoder runs per datagram on the hot path and this keeps it allocation-free.
struct Frame {
    FrameType type = FrameType::Padding;
    union {
        StreamFrame        stream;
        ResetStreamFrame   reset;
        StopSendingFrame   stop;
        MaxDataFrame       max_data;
        MaxStreamDataFrame max_stream_data;
        DataBlockedFrame   blocked;
    };
    AckFrame ack;  // outside the union: it owns a vector

    Frame() : type(FrameType::Padding), stream{} {}
};

// --- encoding --------------------------------------------------------------
// Each returns false if the frame did not fit; the caller then flushes the
// datagram and retries. Partial writes never happen.
bool encode_padding(wire::Writer&, size_t count);
bool encode_ping(wire::Writer&);
bool encode_ack(wire::Writer&, const AckFrame&);
bool encode_reset_stream(wire::Writer&, const ResetStreamFrame&);
bool encode_stop_sending(wire::Writer&, const StopSendingFrame&);
bool encode_max_data(wire::Writer&, const MaxDataFrame&);
bool encode_max_stream_data(wire::Writer&, const MaxStreamDataFrame&);
bool encode_data_blocked(wire::Writer&, const DataBlockedFrame&);

// Writes as much of `data` as fits, and reports how much that was. Returning a
// short count is normal, not an error: it is how a large write is split across
// datagrams.
size_t encode_stream(wire::Writer&, StreamId, uint64_t offset, bool fin,
                     std::span<const uint8_t> data);

// Bytes of framing overhead a STREAM frame costs, excluding its payload.
size_t stream_frame_overhead(StreamId, uint64_t offset);

size_t ack_frame_size(const AckFrame&);

// --- decoding --------------------------------------------------------------
// Decodes every frame in a datagram payload. Returns false on any malformed
// frame, in which case `out` must be discarded entirely -- a partially parsed
// datagram is exactly the kind of thing that turns a bug into a vulnerability.
bool decode_frames(std::span<const uint8_t> payload, std::vector<Frame>& out);

}  // namespace uconnect::stream
