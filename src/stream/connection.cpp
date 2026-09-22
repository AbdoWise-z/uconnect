#include "connection.hpp"

#include <algorithm>

namespace uconnect::stream {

StreamConnection::StreamConnection(StreamConfig cfg, Role role)
    : cfg_(cfg),
      role_(role),
      cc_(cfg.max_payload),
      conn_recv_announced_(cfg.conn_recv_window),
      // Until the peer tells us its window, assume it will grant at least the
      // default. Starting at zero would deadlock: neither side could send the
      // MAX_DATA that unblocks the other.
      conn_send_max_(cfg.conn_recv_window) {}

// ---------------------------------------------------------------------------
// Stream lookup / creation
// ---------------------------------------------------------------------------
StreamConnection::StreamState* StreamConnection::find(StreamId id) {
    auto it = streams_.find(id);
    return it == streams_.end() ? nullptr : &it->second;
}

const StreamConnection::StreamState* StreamConnection::find(StreamId id) const {
    auto it = streams_.find(id);
    return it == streams_.end() ? nullptr : &it->second;
}

StreamId StreamConnection::open(bool bidirectional) {
    StreamId id = make_stream_id(role_, bidirectional, next_index_++);
    // The initial peer window is the PER-STREAM default, not the connection
    // window. Both ends run the same config, so they agree on it until the
    // first MAX_STREAM_DATA arrives.
    //
    // Seeding this from conn_send_max_ instead let a sender believe it had the
    // whole connection window for one stream: it overran the receiver's
    // per-stream buffer, which refused the excess and reset the stream. A
    // 512 KB transfer stopped dead at exactly 256 KB.
    streams_.emplace(id, StreamState{id, cfg_.stream_recv_window, cfg_.stream_recv_window});
    return id;
}

StreamConnection::StreamState& StreamConnection::ensure_peer_stream(StreamId id, Instant now) {
    (void)now;
    auto it = streams_.find(id);
    if (it != streams_.end()) return it->second;

    auto [pos, _] = streams_.emplace(
        id, StreamState{id, cfg_.stream_recv_window, cfg_.stream_recv_window});
    if (!pos->second.open_notified) {
        pos->second.open_notified = true;
        emit(StreamEventKind::Opened, id);
    }
    return pos->second;
}

void StreamConnection::emit(StreamEventKind k, StreamId id, uint64_t code) {
    events_.push_back(StreamEvent{k, id, code});
}

// ---------------------------------------------------------------------------
// Application API
// ---------------------------------------------------------------------------
size_t StreamConnection::write(StreamId id, std::span<const uint8_t> data) {
    auto* s = find(id);
    if (!s || s->peer_reset || s->send_reset) return 0;

    // Connection-level flow control caps the aggregate, so many streams cannot
    // together exceed what one stream alone would be refused.
    const uint64_t conn_room = conn_send_max_ > conn_send_used_
                                   ? conn_send_max_ - conn_send_used_
                                   : 0;
    if (conn_room == 0) {
        s->was_blocked = true;
        return 0;
    }

    size_t cap = cfg_.stream_send_cap;
    size_t n   = s->send.write(data.first(std::min<uint64_t>(data.size(), conn_room)), cap);
    conn_send_used_ += n;
    if (n < data.size()) s->was_blocked = true;
    return n;
}

size_t StreamConnection::read(StreamId id, std::span<uint8_t> out) {
    auto* s = find(id);
    if (!s) return 0;

    size_t n = s->recv.read(out);
    if (n > 0) conn_recv_consumed_ += n;

    // Consuming data slides both windows. Announce only when they have moved
    // enough to be worth the frame.
    if (conn_recv_consumed_ + cfg_.conn_recv_window >=
        conn_recv_announced_ + cfg_.conn_recv_window / 2) {
        send_max_data_ = true;
    }

    if (n > 0 && s->recv.finished() && !s->fin_notified) {
        s->fin_notified = true;
        emit(StreamEventKind::Finished, id);
    }
    return n;
}

void StreamConnection::finish(StreamId id) {
    if (auto* s = find(id)) s->send.finish();
}

void StreamConnection::reset(StreamId id, uint64_t code) {
    if (auto* s = find(id)) {
        s->send_reset      = true;
        s->send_reset_code = code;
    }
}

void StreamConnection::stop_sending(StreamId id, uint64_t code) {
    if (auto* s = find(id)) {
        s->send_stop      = true;
        s->send_stop_code = code;
    }
}

bool StreamConnection::readable(StreamId id) const {
    auto* s = find(id);
    return s && s->recv.readable() > 0;
}

size_t StreamConnection::readable_bytes(StreamId id) const {
    auto* s = find(id);
    return s ? s->recv.readable() : 0;
}

bool StreamConnection::finished(StreamId id) const {
    auto* s = find(id);
    return s && s->recv.finished();
}

bool StreamConnection::writable(StreamId id) const {
    auto* s = find(id);
    if (!s || s->send_reset || s->peer_reset) return false;
    if (s->send.fin_written()) return false;
    return s->send.buffered() < cfg_.stream_send_cap && conn_send_used_ < conn_send_max_;
}

bool StreamConnection::exists(StreamId id) const { return find(id) != nullptr; }

std::vector<StreamId> StreamConnection::active_streams() const {
    std::vector<StreamId> out;
    out.reserve(streams_.size());
    for (const auto& [id, s] : streams_) {
        (void)s;
        out.push_back(id);
    }
    return out;
}

std::optional<StreamEvent> StreamConnection::poll_event() {
    if (events_.empty()) return std::nullopt;
    StreamEvent e = events_.front();
    events_.erase(events_.begin());
    return e;
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------
void StreamConnection::on_datagram(uint64_t pn, std::span<const uint8_t> payload, Instant now) {
    if (dead_) return;
    if (!started_) {
        started_     = true;
        last_ack_rx_ = now;
    }

    if (!decode_frames(payload, scratch_)) {
        // A malformed datagram from an authenticated peer is a bug or an
        // attack; either way the safe move is to ignore it entirely rather
        // than act on the frames that happened to parse first.
        return;
    }

    bool ack_eliciting = false;
    for (const auto& f : scratch_) {
        if (f.type != FrameType::Ack) ack_eliciting = true;
    }
    acks_.on_received(pn, ack_eliciting, now);

    for (const auto& f : scratch_) handle_frame(f, now);

    arm_loss_timer(now);
}

void StreamConnection::handle_frame(const Frame& f, Instant now) {
    switch (f.type) {
        case FrameType::Padding:
        case FrameType::Ping:
            break;

        case FrameType::Ack: {
            std::vector<uint64_t> acked;
            f.ack.for_each([&](uint64_t pn) { acked.push_back(pn); });
            if (acked.empty()) break;

            auto outcome = sent_.on_ack(f.ack.largest,
                                        Duration{static_cast<int64_t>(f.ack.delay_us / 1000)},
                                        acked, rtt_, now);

            if (outcome.has_rtt_sample) {
                rtt_.sample(outcome.rtt_sample,
                            Duration{static_cast<int64_t>(f.ack.delay_us / 1000)});
            }

            for (const auto& p : outcome.newly_acked) {
                cc_.on_acked(p.size, p.sent_at, now);
                on_packet_acked(p);
            }
            for (const auto& p : outcome.lost) {
                cc_.on_lost(p.size, p.sent_at, now);
                on_packet_lost(p);
                ++packets_lost_;
            }

            if (!outcome.newly_acked.empty()) {
                pto_count_   = 0;
                last_ack_rx_ = now;
            }
            break;
        }

        case FrameType::StreamBase: {
            auto& s = ensure_peer_stream(f.stream.id, now);
            if (s.peer_reset) break;

            const size_t before = s.recv.readable();
            if (!s.recv.insert(f.stream.offset, f.stream.data, f.stream.fin)) {
                // Flow-control violation. Tear the stream down rather than
                // grow a buffer the peer controls the size of.
                s.send_reset      = true;
                s.send_reset_code = 1;
                emit(StreamEventKind::Reset, f.stream.id, 1);
                break;
            }
            if (s.recv.readable() > before) emit(StreamEventKind::Readable, f.stream.id);
            if (s.recv.readable() == 0 && s.recv.finished() && !s.fin_notified) {
                s.fin_notified = true;
                emit(StreamEventKind::Finished, f.stream.id);
            }
            break;
        }

        case FrameType::ResetStream: {
            auto& s      = ensure_peer_stream(f.reset.id, now);
            s.peer_reset = true;
            emit(StreamEventKind::Reset, f.reset.id, f.reset.error_code);
            break;
        }

        case FrameType::StopSending: {
            auto& s = ensure_peer_stream(f.stop.id, now);
            // The peer does not want the rest. Stop producing and tell it we
            // have stopped, rather than continuing to burn the window.
            s.send_reset      = true;
            s.send_reset_code = f.stop.error_code;
            break;
        }

        case FrameType::MaxData: {
            if (f.max_data.max > conn_send_max_) {
                conn_send_max_ = f.max_data.max;
                for (auto& [id, s] : streams_) {
                    (void)s;
                    emit(StreamEventKind::Writable, id);
                }
            }
            break;
        }

        case FrameType::MaxStreamData: {
            auto& s = ensure_peer_stream(f.max_stream_data.id, now);
            if (f.max_stream_data.max > s.send.peer_max()) {
                s.send.set_peer_max(f.max_stream_data.max);
                if (s.was_blocked) {
                    s.was_blocked = false;
                    emit(StreamEventKind::Writable, f.max_stream_data.id);
                }
            }
            break;
        }

        case FrameType::DataBlocked:
            // The peer says our window is holding it back. Re-announce, which
            // also repairs the case where a MAX_DATA frame was lost.
            send_max_data_ = true;
            break;
    }
}

void StreamConnection::on_packet_acked(const SentPacket& p) {
    for (const auto& c : p.chunks) {
        if (auto* s = find(c.stream_id)) {
            s->send.on_acked(c.offset, c.length);
            if (s->send.complete() && !s->open_notified) {
                // nothing further; Closed is emitted from the send path
            }
        }
    }
}

void StreamConnection::on_packet_lost(const SentPacket& p) {
    for (const auto& c : p.chunks) {
        if (auto* s = find(c.stream_id)) s->send.on_lost(c.offset, c.length);
    }
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------
size_t StreamConnection::poll_datagram(uint64_t pn, std::span<uint8_t> out, Instant now) {
    if (dead_) return 0;
    if (!started_) {
        started_     = true;
        last_ack_rx_ = now;
    }

    const size_t budget = std::min(out.size(), cfg_.max_payload);
    wire::Writer w{out.first(budget)};

    SentPacket rec;
    rec.number  = pn;
    rec.sent_at = now;

    bool any = false;

    // ACK first: it is small, it is time-critical, and putting it at the front
    // means it survives even when the rest of the datagram is full of data.
    if (acks_.should_ack()) {
        if (auto built = acks_.build(now)) {
            AckFrame a;
            a.largest     = built->largest;
            a.first_range = built->first_range;
            a.delay_us    = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(built->delay).count());
            for (const auto& [gap, len] : built->extra) a.ranges.push_back(AckRange{gap, len});
            if (encode_ack(w, a)) {
                acks_.acked(now);
                any = true;
            }
        }
    }

    // Connection-level window update.
    if (send_max_data_) {
        MaxDataFrame m;
        m.max = conn_recv_consumed_ + cfg_.conn_recv_window;
        if (encode_max_data(w, m)) {
            conn_recv_announced_ = m.max;
            send_max_data_       = false;
            any                  = true;
            rec.ack_eliciting    = true;
        }
    }

    // Per-stream control frames, then data.
    for (auto& [id, s] : streams_) {
        if (s.send_reset && !s.reset_sent) {
            ResetStreamFrame f{id, s.send_reset_code, s.send.written()};
            if (encode_reset_stream(w, f)) {
                s.reset_sent      = true;
                any               = true;
                rec.ack_eliciting = true;
            }
            continue;
        }
        if (s.send_stop && !s.stop_sent) {
            StopSendingFrame f{id, s.send_stop_code};
            if (encode_stop_sending(w, f)) {
                s.stop_sent       = true;
                any               = true;
                rec.ack_eliciting = true;
            }
        }
        if (s.recv.should_update_window()) {
            MaxStreamDataFrame f{id, s.recv.max_offset()};
            if (encode_max_stream_data(w, f)) {
                s.recv.window_announced();
                any               = true;
                rec.ack_eliciting = true;
            }
        }
    }

    // Data, but only if the congestion window allows another packet in flight.
    // This is the check that keeps a sender from overrunning the path.
    const bool cc_ok = cc_.can_send(cfg_.max_payload);

    if (cc_ok) {
        for (auto& [id, s] : streams_) {
            if (s.send_reset || s.peer_reset) continue;

            while (w.remaining() > 16) {
                const size_t overhead = stream_frame_overhead(id, s.send.sent());
                if (w.remaining() <= overhead) break;

                auto chunk = s.send.next_chunk(w.remaining() - overhead);
                if (!chunk) break;

                size_t wrote = encode_stream(w, id, chunk->offset, chunk->fin, chunk->data);
                if (wrote == 0 && !chunk->fin) break;

                if (!chunk->retransmit) {
                    s.send.on_sent(chunk->offset, wrote);
                } else {
                    // Retransmitted bytes are back in flight; track them again
                    // so a second loss is also detected.
                    s.send.on_sent(chunk->offset, wrote);
                }

                SentPacket::StreamChunk sc;
                sc.stream_id = id;
                sc.offset    = chunk->offset;
                sc.length    = wrote;
                sc.fin       = chunk->fin && wrote == chunk->data.size();
                rec.chunks.push_back(sc);

                rec.ack_eliciting = true;
                any               = true;

                if (wrote < chunk->data.size()) break;  // datagram is full
            }
            if (w.remaining() <= 16) break;
        }
    }

    if (!any) return 0;
    if (!w.ok()) return 0;

    rec.size      = w.size();
    rec.in_flight = rec.ack_eliciting;
    if (rec.in_flight) cc_.on_sent(rec.size);
    sent_.on_sent(rec);
    ++packets_sent_;

    arm_loss_timer(now);
    return w.size();
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------
bool StreamConnection::has_outstanding_work() const {
    if (!sent_.empty()) return true;
    for (const auto& [id, s] : streams_) {
        (void)id;
        if (s.send_reset || s.peer_reset) continue;
        // Bytes written that the peer has not acknowledged, including data
        // still queued for a retransmission that has not gone out yet.
        if (s.send.written() > s.send.acked_prefix()) return true;
    }
    return false;
}

void StreamConnection::arm_loss_timer(Instant now) {
    auto oldest = sent_.oldest_in_flight();
    if (!oldest) {
        loss_timer_armed_ = false;
        return;
    }

    Instant deadline = *oldest + rtt_.pto(pto_count_);

    // Never schedule in the past. Arming from an old packet's send time means
    // that once the deadline has slipped by, the timer fires on every single
    // tick -- racing pto_count_ to its limit within a few milliseconds and
    // killing a connection that was merely slow.
    if (deadline <= now) deadline = now + rtt_.pto(pto_count_);

    loss_timer_       = deadline;
    loss_timer_armed_ = true;
}

void StreamConnection::on_timeout(Instant now) {
    if (dead_) return;

    // Time-threshold loss detection runs regardless of whether an ack arrived.
    auto lost = sent_.detect_lost(rtt_, now);
    for (const auto& p : lost) {
        cc_.on_lost(p.size, p.sent_at, now);
        on_packet_lost(p);
        ++packets_lost_;
    }

    if (loss_timer_armed_ && now >= loss_timer_) {
        ++pto_count_;
        if (pto_count_ >= cfg_.max_pto_count) {
            // Repeated probe timeouts with nothing acknowledged: the path is
            // gone. Better to surface that than to keep probing forever.
            dead_ = true;
            emit(StreamEventKind::ConnDead, 0);
            return;
        }
        // Release the oldest outstanding packet so its bytes leave the
        // congestion window and its contents are queued for retransmission.
        auto probe = sent_.on_pto();
        for (const auto& p : probe) {
            cc_.on_lost(p.size, p.sent_at, now);
            on_packet_lost(p);
            ++packets_lost_;
        }

        // Only collapse the window after repeated probes go unanswered. Doing
        // it on the first PTO punishes a single late ack far too harshly and
        // makes recovery from ordinary loss glacial.
        if (pto_count_ >= 2) cc_.on_persistent_congestion();

        arm_loss_timer(now);
    }

    // Idle liveness. The condition is "we are trying to make progress and
    // nothing is coming back", which is NOT the same as "packets are in
    // flight": a probe timeout releases the flight, so keying off in-flight
    // packets alone means a peer that vanishes mid-transfer is never reported
    // at all -- the connection just sits there with data it will never deliver.
    if (started_ && now - last_ack_rx_ >= cfg_.idle_timeout && has_outstanding_work()) {
        dead_ = true;
        emit(StreamEventKind::ConnDead, 0);
    }
}

std::optional<Instant> StreamConnection::next_timeout() const {
    std::optional<Instant> soonest;
    auto consider = [&](std::optional<Instant> t) {
        if (t && (!soonest || *t < *soonest)) soonest = t;
    };

    if (loss_timer_armed_) consider(loss_timer_);
    consider(acks_.ack_deadline());
    if (started_ && !sent_.empty()) consider(last_ack_rx_ + cfg_.idle_timeout);
    return soonest;
}

}  // namespace uconnect::stream
