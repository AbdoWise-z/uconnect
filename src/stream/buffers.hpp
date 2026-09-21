#pragma once
// Per-stream send and receive buffers.
//
// These are where TCP's two headline guarantees actually get implemented:
//
//   RecvBuffer  ORDERING. Datagrams arrive out of order; this holds the
//               out-of-order pieces and releases only the contiguous prefix,
//               so the application sees a byte stream.
//
//   SendBuffer  RELIABILITY. Written bytes are retained until acknowledged,
//               and a lost range is queued for retransmission ahead of new
//               data.
//
// Both are pure data structures: no clock, no sockets, no knowledge of frames.

#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace uconnect::stream {

// A half-open byte range [start, end).
struct ByteRange {
    uint64_t start = 0;
    uint64_t end   = 0;

    uint64_t length() const { return end > start ? end - start : 0; }
    bool     empty() const { return end <= start; }
};

// --- receive ---------------------------------------------------------------
class RecvBuffer {
public:
    explicit RecvBuffer(uint64_t window) : window_(window) {}

    // Accepts a chunk at an absolute stream offset. Returns false if it would
    // exceed the advertised flow-control limit -- a peer doing that is either
    // broken or hostile, and the caller should tear the stream down.
    bool insert(uint64_t offset, std::span<const uint8_t> data, bool fin);

    // Copies out the contiguous prefix, which is the only part the application
    // is allowed to see. Returns bytes copied.
    size_t read(std::span<uint8_t> out);

    size_t   readable() const { return static_cast<size_t>(ready_.size()); }
    uint64_t consumed() const { return consumed_; }

    // True once every byte up to the FIN has been read.
    bool finished() const { return fin_offset_.has_value() && consumed_ >= *fin_offset_; }
    bool fin_known() const { return fin_offset_.has_value(); }

    // Flow control: the largest offset the peer may send. Advances as the
    // application consumes, which is what makes the window slide.
    uint64_t max_offset() const { return consumed_ + window_; }

    // Announce a new limit only when it has moved enough to be worth a frame.
    // Sending MAX_STREAM_DATA for every byte read would flood the return path.
    bool should_update_window() const {
        return max_offset() >= announced_max_ + window_ / 2;
    }
    void window_announced() { announced_max_ = max_offset(); }
    uint64_t announced_max() const { return announced_max_; }

private:
    uint64_t                           window_;
    uint64_t                           consumed_ = 0;   // bytes handed to the application
    uint64_t                           announced_max_ = 0;
    std::deque<uint8_t>                ready_;          // contiguous, unread
    std::map<uint64_t, std::vector<uint8_t>> pending_;  // out-of-order, by offset
    std::optional<uint64_t>            fin_offset_;

    void drain_pending();
};

// --- send ------------------------------------------------------------------
class SendBuffer {
public:
    // Bytes the application has written but that are not yet acknowledged are
    // retained here, so `limit` bounds memory as well as being a courtesy to
    // the peer.
    explicit SendBuffer(uint64_t peer_window) : peer_max_(peer_window) {}

    // Appends application data. Returns bytes accepted; a short result means
    // the buffer is full and the caller must wait.
    size_t write(std::span<const uint8_t> data, size_t cap);

    void finish() { fin_written_ = true; }
    bool fin_written() const { return fin_written_; }

    // Next range to transmit, preferring retransmissions over new data: a
    // lost byte blocks the receiver's whole stream, so it is always more
    // urgent than a byte the receiver has never seen.
    struct Chunk {
        uint64_t offset = 0;
        std::span<const uint8_t> data{};
        bool     fin        = false;
        bool     retransmit = false;
    };
    std::optional<Chunk> next_chunk(size_t max_len);

    void on_sent(uint64_t offset, uint64_t length);
    void on_acked(uint64_t offset, uint64_t length);
    void on_lost(uint64_t offset, uint64_t length);

    void set_peer_max(uint64_t m) { if (m > peer_max_) peer_max_ = m; }
    uint64_t peer_max() const { return peer_max_; }

    // True when there is nothing more to send and everything is acknowledged.
    bool complete() const {
        return fin_written_ && sent_ >= written_ && unacked_.empty() && retransmit_.empty();
    }
    bool has_pending() const { return !retransmit_.empty() || sent_ < written_ || fin_pending(); }
    bool blocked() const { return sent_ >= peer_max_ && sent_ < written_; }

    uint64_t written() const { return written_; }
    uint64_t sent() const { return sent_; }
    uint64_t acked_prefix() const { return acked_prefix_; }
    size_t   buffered() const { return buf_.size(); }

private:
    bool fin_pending() const { return fin_written_ && !fin_sent_; }
    std::span<const uint8_t> slice(uint64_t offset, uint64_t length) const;

    std::vector<uint8_t> buf_;          // data from base_ onward
    uint64_t             base_         = 0;  // stream offset of buf_[0]
    uint64_t             written_      = 0;  // total bytes accepted
    uint64_t             sent_         = 0;  // high-water mark transmitted
    uint64_t             acked_prefix_ = 0;  // contiguous acked prefix
    uint64_t             peer_max_     = 0;
    bool                 fin_written_  = false;
    bool                 fin_sent_     = false;
    bool                 fin_acked_    = false;

    std::map<uint64_t, uint64_t> unacked_;    // offset -> length, in flight
    std::map<uint64_t, uint64_t> acked_;      // offset -> length, for prefix computation
    std::map<uint64_t, uint64_t> retransmit_; // offset -> length, known lost

    void recompute_prefix();
    void release_acked();
};

}  // namespace uconnect::stream
