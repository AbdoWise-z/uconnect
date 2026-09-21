#include "recovery.hpp"

namespace uconnect::stream {

// ---------------------------------------------------------------------------
// RttEstimator -- RFC 9002 s5
// ---------------------------------------------------------------------------
void RttEstimator::sample(Duration latest, Duration ack_delay) {
    latest_ = latest;

    if (!has_sample_) {
        has_sample_ = true;
        min_rtt_    = latest;
        srtt_       = latest;
        rttvar_     = latest / 2;
        return;
    }

    min_rtt_ = std::min(min_rtt_, latest);

    // Subtract the peer's self-reported ack delay, but never below min_rtt --
    // a peer that over-reports its delay would otherwise drive our estimate to
    // zero and make everything look lost.
    Duration adjusted = latest;
    if (adjusted > ack_delay && adjusted - ack_delay >= min_rtt_) {
        adjusted -= ack_delay;
    }

    auto diff = srtt_ > adjusted ? srtt_ - adjusted : adjusted - srtt_;
    rttvar_   = (rttvar_ * 3 + diff) / 4;
    srtt_     = (srtt_ * 7 + adjusted) / 8;
}

Duration RttEstimator::pto(uint32_t backoff_exponent) const {
    Duration base = srtt_ + std::max(rttvar_ * 4, kGranularity) + AckTracker::kMaxAckDelay;
    // Cap the shift: a long outage should not push the next probe years out.
    uint32_t shift = std::min<uint32_t>(backoff_exponent, 10);
    return base * (uint64_t{1} << shift);
}

// ---------------------------------------------------------------------------
// Congestion -- NewReno, RFC 9002 s7
// ---------------------------------------------------------------------------
Congestion::Congestion(size_t max_datagram)
    : max_datagram_(max_datagram),
      // 10 datagrams is the standard initial window: enough to get an RTT
      // sample quickly without a burst that a small buffer cannot absorb.
      cwnd_(10 * max_datagram),
      ssthresh_(SIZE_MAX) {}

void Congestion::on_sent(size_t bytes) { in_flight_ += bytes; }

void Congestion::on_acked(size_t bytes, Instant sent_at, Instant now) {
    (void)now;
    in_flight_ = in_flight_ > bytes ? in_flight_ - bytes : 0;

    // A packet sent before recovery began tells us nothing new about the
    // congestion event that started it.
    if (in_recovery_ && sent_at <= recovery_start_) return;
    in_recovery_ = false;

    if (cwnd_ < ssthresh_) {
        cwnd_ += bytes;  // slow start: double every round trip
    } else {
        // Congestion avoidance: roughly one extra datagram per round trip.
        cwnd_ += max_datagram_ * bytes / cwnd_;
    }
}

void Congestion::on_lost(size_t bytes, Instant sent_at, Instant now) {
    in_flight_ = in_flight_ > bytes ? in_flight_ - bytes : 0;

    // One congestion event per round trip. Without this guard a burst of
    // losses in a single flight would halve the window several times over.
    if (in_recovery_ && sent_at <= recovery_start_) return;

    in_recovery_    = true;
    recovery_start_ = now;
    ssthresh_       = std::max(cwnd_ / 2, min_window());
    cwnd_           = ssthresh_;
}

void Congestion::on_persistent_congestion() {
    cwnd_        = min_window();
    ssthresh_    = std::max(ssthresh_, min_window());
    in_recovery_ = false;
}

// ---------------------------------------------------------------------------
// SentPackets
// ---------------------------------------------------------------------------
void SentPackets::on_sent(SentPacket p) { sent_[p.number] = std::move(p); }

AckOutcome SentPackets::on_ack(uint64_t largest, Duration ack_delay,
                               const std::vector<uint64_t>& acked_numbers,
                               const RttEstimator& rtt, Instant now) {
    AckOutcome out;

    for (uint64_t n : acked_numbers) {
        auto it = sent_.find(n);
        if (it == sent_.end()) continue;  // already acked, or never sent

        // An RTT sample is only valid from the largest newly-acked packet, and
        // only if it elicited the ack. Sampling from an older packet in the
        // same frame would measure how long it sat waiting, not the path.
        if (n == largest && it->second.ack_eliciting) {
            out.has_rtt_sample = true;
            out.rtt_sample     = std::chrono::duration_cast<Duration>(now - it->second.sent_at);
        }
        out.newly_acked.push_back(it->second);
        sent_.erase(it);
    }

    if (!out.newly_acked.empty()) {
        if (!any_acked_ || largest > largest_acked_) {
            largest_acked_    = largest;
            largest_acked_at_ = now;
        }
        any_acked_ = true;
    }

    out.lost = detect_lost(rtt, now);
    (void)ack_delay;
    return out;
}

std::vector<SentPacket> SentPackets::detect_lost(const RttEstimator& rtt, Instant now) {
    std::vector<SentPacket> lost;
    if (!any_acked_) return lost;

    // Time threshold: 9/8 of the larger of the smoothed and latest RTT, per
    // RFC 9002. Generous enough that ordinary reordering is not mistaken for
    // loss, tight enough to recover before a PTO fires.
    Duration max_rtt   = std::max(rtt.smoothed(), rtt.latest());
    Duration threshold = (max_rtt * 9) / 8;
    if (threshold < RttEstimator::kGranularity) threshold = RttEstimator::kGranularity;

    for (auto it = sent_.begin(); it != sent_.end();) {
        const auto& p = it->second;
        if (p.number >= largest_acked_) break;  // map is ordered; nothing later qualifies

        const bool by_packet_count = largest_acked_ >= p.number + kPacketThreshold;
        const bool by_time         = now >= p.sent_at + threshold;

        if (by_packet_count || by_time) {
            lost.push_back(p);
            it = sent_.erase(it);
        } else {
            ++it;
        }
    }
    return lost;
}

std::vector<SentPacket> SentPackets::on_pto() {
    std::vector<SentPacket> out;
    for (auto it = sent_.begin(); it != sent_.end(); ++it) {
        if (!it->second.ack_eliciting) continue;
        out.push_back(it->second);
        sent_.erase(it);
        break;  // one probe's worth at a time; further PTOs release more
    }
    return out;
}

std::optional<Instant> SentPackets::oldest_in_flight() const {
    for (const auto& [n, p] : sent_) {
        (void)n;
        if (p.ack_eliciting) return p.sent_at;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// AckTracker
// ---------------------------------------------------------------------------
void AckTracker::on_received(uint64_t pn, bool ack_eliciting, Instant now) {
    // Insert into the newest-first range list, merging where adjacent.
    bool merged = false;
    for (size_t i = 0; i < ranges_.size(); ++i) {
        auto& r = ranges_[i];
        if (pn >= r.lo && pn <= r.hi) return;  // duplicate; session dedup should have caught it
        if (pn == r.hi + 1) {
            r.hi   = pn;
            merged = true;
            // May now touch the range above it.
            if (i > 0 && ranges_[i - 1].lo == r.hi + 1) {
                r.hi = ranges_[i - 1].hi;
                ranges_.erase(ranges_.begin() + static_cast<ptrdiff_t>(i) - 1);
            }
            break;
        }
        if (pn + 1 == r.lo) {
            r.lo   = pn;
            merged = true;
            if (i + 1 < ranges_.size() && ranges_[i + 1].hi + 1 == r.lo) {
                r.lo = ranges_[i + 1].lo;
                ranges_.erase(ranges_.begin() + static_cast<ptrdiff_t>(i) + 1);
            }
            break;
        }
        if (pn > r.hi) {
            ranges_.insert(ranges_.begin() + static_cast<ptrdiff_t>(i), Range{pn, pn});
            merged = true;
            break;
        }
    }
    if (!merged) ranges_.push_back(Range{pn, pn});

    // Bound the history. Acknowledging very old packets is pointless -- the
    // sender has long since given up on them -- and an unbounded list is a
    // memory leak a peer could drive.
    if (ranges_.size() > 32) ranges_.resize(32);

    if (!have_any_ || pn > largest_) {
        largest_    = pn;
        largest_at_ = now;
    }
    have_any_ = true;

    if (ack_eliciting) {
        if (!ack_pending_) first_pending_ = now;
        ack_pending_ = true;
        ++since_ack_;
        // Acknowledge immediately every second packet, as TCP and QUIC do:
        // waiting on all of them starves the sender's congestion window.
        if (since_ack_ >= 2) first_pending_ = Instant{};
    }
}

void AckTracker::acked(Instant now) {
    (void)now;
    ack_pending_ = false;
    since_ack_   = 0;
}

std::optional<Instant> AckTracker::ack_deadline() const {
    if (!ack_pending_) return std::nullopt;
    if (since_ack_ >= 2) return Instant{};  // send now
    if (first_pending_ == Instant{}) return Instant{};
    return first_pending_ + kMaxAckDelay;
}

std::optional<AckTracker::Built> AckTracker::build(Instant now) const {
    if (!have_any_ || ranges_.empty()) return std::nullopt;

    Built b;
    b.largest     = ranges_.front().hi;
    b.first_range = ranges_.front().hi - ranges_.front().lo;
    b.delay       = std::chrono::duration_cast<Duration>(now - largest_at_);

    uint64_t prev_lo = ranges_.front().lo;
    for (size_t i = 1; i < ranges_.size(); ++i) {
        const auto& r = ranges_[i];
        if (prev_lo < r.hi + 2) break;  // malformed ordering; stop rather than emit nonsense
        uint64_t gap = prev_lo - r.hi - 2;
        b.extra.emplace_back(gap, r.hi - r.lo);
        prev_lo = r.lo;
    }
    return b;
}

}  // namespace uconnect::stream
