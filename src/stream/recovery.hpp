#pragma once
// Loss recovery and congestion control: RFC 9002, trimmed to what this
// transport actually needs.
//
// Three pieces that are easy to conflate:
//
//   RttEstimator   how long a round trip takes, and how variable it is
//   Congestion     how many bytes may be in flight (NewReno)
//   SentPackets    which packets are outstanding, and which are now lost
//
// Congestion control is the part people leave out, and it is the part that
// makes a transport safe to deploy. Without it a sender fills every buffer on
// the path, and two such senders sharing a bottleneck collapse into loss
// rather than sharing it. A library that only ever moves chat messages can get
// away without one; a library that might move a file cannot.

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

#include "uconnect/types.hpp"

namespace uconnect::stream {

// --- RTT -------------------------------------------------------------------
class RttEstimator {
public:
    // Before any sample, assume a pessimistic-but-not-absurd round trip.
    static constexpr Duration kInitialRtt{std::chrono::milliseconds(333)};
    static constexpr Duration kGranularity{std::chrono::milliseconds(1)};

    void sample(Duration latest, Duration ack_delay);

    bool     has_sample() const { return has_sample_; }
    Duration smoothed() const { return srtt_; }
    Duration variation() const { return rttvar_; }
    Duration minimum() const { return min_rtt_; }
    Duration latest() const { return latest_; }

    // Probe timeout: how long to wait before assuming the tail of a flight was
    // lost. Backs off exponentially per consecutive expiry.
    Duration pto(uint32_t backoff_exponent) const;

private:
    bool     has_sample_ = false;
    Duration srtt_{kInitialRtt};
    Duration rttvar_{kInitialRtt / 2};
    Duration min_rtt_{Duration::max()};
    Duration latest_{kInitialRtt};
};

// --- congestion ------------------------------------------------------------
// NewReno rather than CUBIC or BBR: it is simple enough to read and reason
// about in a page, and its behaviour under loss is well understood. The
// interface leaves room to swap it later.
class Congestion {
public:
    explicit Congestion(size_t max_datagram);

    size_t window() const { return cwnd_; }
    size_t in_flight() const { return in_flight_; }
    bool   can_send(size_t bytes) const { return in_flight_ + bytes <= cwnd_; }
    size_t available() const { return cwnd_ > in_flight_ ? cwnd_ - in_flight_ : 0; }

    void on_sent(size_t bytes);
    void on_acked(size_t bytes, Instant sent_at, Instant now);
    void on_lost(size_t bytes, Instant sent_at, Instant now);

    // A PTO firing means the tail of a flight went unacknowledged. That is a
    // strong signal the network is worse than we think, so collapse the window
    // to the minimum and rebuild.
    void on_persistent_congestion();

    bool   in_slow_start() const { return cwnd_ < ssthresh_; }
    size_t ssthresh() const { return ssthresh_; }

private:
    size_t  max_datagram_;
    size_t  cwnd_;
    size_t  ssthresh_;
    size_t  in_flight_ = 0;
    Instant recovery_start_{};
    bool    in_recovery_ = false;

    size_t min_window() const { return 2 * max_datagram_; }
};

// --- sent packet tracking --------------------------------------------------
struct SentPacket {
    uint64_t number      = 0;
    Instant  sent_at{};
    size_t   size        = 0;     // bytes on the wire, for congestion accounting
    bool     ack_eliciting = false;  // carries anything worth retransmitting
    bool     in_flight     = false;  // counts against the congestion window

    // What this packet carried, so it can be resent if it is lost. Pure-ACK
    // packets carry nothing: acks are never retransmitted, they are simply
    // superseded by the next one.
    struct StreamChunk {
        uint64_t stream_id = 0;
        uint64_t offset    = 0;
        uint64_t length    = 0;
        bool     fin       = false;
    };
    std::vector<StreamChunk> chunks;
};

// Outcome of processing one incoming ACK frame.
struct AckOutcome {
    std::vector<SentPacket> newly_acked;
    std::vector<SentPacket> lost;
    bool                    has_rtt_sample = false;
    Duration                rtt_sample{};
};

class SentPackets {
public:
    // A packet is declared lost once this many packets with higher numbers
    // have been acknowledged. Reordering below this threshold is tolerated.
    static constexpr uint64_t kPacketThreshold = 3;

    void on_sent(SentPacket p);

    // Feeds an ACK. `largest` must already have been validated as a packet we
    // actually sent.
    AckOutcome on_ack(uint64_t largest, Duration ack_delay,
                      const std::vector<uint64_t>& acked_numbers,
                      const RttEstimator& rtt, Instant now);

    // Packets that have now aged out, independent of any ACK arriving.
    std::vector<SentPacket> detect_lost(const RttEstimator& rtt, Instant now);

    // Called when a probe timeout fires. Releases the oldest outstanding
    // ack-eliciting packet so its contents can be retransmitted and its bytes
    // leave the congestion window.
    //
    // detect_lost() cannot do this job: it refuses to act before the first
    // acknowledgement arrives, and a PTO is precisely the case where nothing
    // has been acknowledged. Without an explicit release the in-flight count
    // never falls, the window stays full, and the connection wedges.
    std::vector<SentPacket> on_pto();

    // Oldest unacknowledged ack-eliciting packet, which is what a PTO timer
    // should be armed against.
    std::optional<Instant> oldest_in_flight() const;

    bool   empty() const { return sent_.empty(); }
    size_t outstanding() const { return sent_.size(); }
    uint64_t largest_acked() const { return largest_acked_; }
    bool     any_acked() const { return any_acked_; }

private:
    // Ordered by packet number so loss detection can walk "everything below
    // the largest ack" without scanning.
    std::map<uint64_t, SentPacket> sent_;
    uint64_t                       largest_acked_ = 0;
    bool                           any_acked_     = false;
    Instant                        largest_acked_at_{};
};

// --- receiver-side ack bookkeeping -----------------------------------------
// Tracks which packet numbers have arrived so an ACK frame can be built.
class AckTracker {
public:
    void on_received(uint64_t packet_number, bool ack_eliciting, Instant now);

    bool     should_ack() const { return ack_pending_; }
    void     acked(Instant now);

    // Build an ACK frame describing everything received so far.
    // Returns nullopt when nothing has been received yet.
    struct Built {
        uint64_t                          largest;
        uint64_t                          first_range;
        std::vector<std::pair<uint64_t, uint64_t>> extra;  // (gap, len)
        Duration                          delay;
    };
    std::optional<Built> build(Instant now) const;

    // An ack should not be delayed past this, or the sender's RTT estimate
    // inflates and its loss detection turns sluggish.
    static constexpr Duration kMaxAckDelay{std::chrono::milliseconds(25)};

    std::optional<Instant> ack_deadline() const;

private:
    // Contiguous runs of received packet numbers, kept newest-first.
    struct Range {
        uint64_t lo = 0;
        uint64_t hi = 0;
    };
    std::vector<Range> ranges_;
    uint64_t           largest_      = 0;
    Instant            largest_at_{};
    bool               ack_pending_  = false;
    bool               have_any_     = false;
    Instant            first_pending_{};
    uint32_t           since_ack_    = 0;
};

}  // namespace uconnect::stream
