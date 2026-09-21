#include "buffers.hpp"

#include <algorithm>

namespace uconnect::stream {

// ---------------------------------------------------------------------------
// RecvBuffer
// ---------------------------------------------------------------------------
bool RecvBuffer::insert(uint64_t offset, std::span<const uint8_t> data, bool fin) {
    const uint64_t end = offset + data.size();

    // Enforce the window we advertised. A peer exceeding it is not merely
    // impolite: honouring it would let one stream consume unbounded memory.
    if (end > max_offset()) return false;

    if (fin) {
        // A peer must not move the FIN once declared, nor place it before data
        // it already sent.
        if (fin_offset_ && *fin_offset_ != end) return false;
        fin_offset_ = end;
    }

    const uint64_t contiguous_end = consumed_ + ready_.size();

    // Entirely in the past: a retransmission of data we already hold.
    if (end <= contiguous_end) return true;

    if (offset <= contiguous_end) {
        // Overlaps or extends the contiguous region. Append only the new tail.
        const uint64_t skip = contiguous_end - offset;
        ready_.insert(ready_.end(), data.begin() + static_cast<ptrdiff_t>(skip), data.end());
        drain_pending();
        return true;
    }

    // A genuine gap: hold it until the missing piece arrives. This is the
    // structure that turns "datagrams arrive in any order" into "the
    // application sees an ordered stream".
    auto& slot = pending_[offset];
    if (slot.size() < data.size()) slot.assign(data.begin(), data.end());
    return true;
}

void RecvBuffer::drain_pending() {
    // Repeatedly absorb any held chunk that now begins at or before the edge
    // of the contiguous region.
    bool progressed = true;
    while (progressed) {
        progressed = false;
        const uint64_t edge = consumed_ + ready_.size();

        for (auto it = pending_.begin(); it != pending_.end();) {
            const uint64_t off = it->first;
            const uint64_t end = off + it->second.size();

            if (end <= edge) {
                it = pending_.erase(it);  // fully superseded
                continue;
            }
            if (off <= edge) {
                const uint64_t skip = edge - off;
                ready_.insert(ready_.end(),
                              it->second.begin() + static_cast<ptrdiff_t>(skip),
                              it->second.end());
                it         = pending_.erase(it);
                progressed = true;
                break;  // edge moved; restart the scan
            }
            ++it;
        }
    }
}

size_t RecvBuffer::read(std::span<uint8_t> out) {
    const size_t n = std::min(out.size(), ready_.size());
    for (size_t i = 0; i < n; ++i) out[i] = ready_[i];
    ready_.erase(ready_.begin(), ready_.begin() + static_cast<ptrdiff_t>(n));
    consumed_ += n;
    return n;
}

// ---------------------------------------------------------------------------
// SendBuffer
// ---------------------------------------------------------------------------
size_t SendBuffer::write(std::span<const uint8_t> data, size_t cap) {
    if (fin_written_) return 0;  // stream is closed for writing

    const size_t held = buf_.size();
    if (held >= cap) return 0;

    const size_t room = cap - held;
    const size_t take = std::min(room, data.size());
    buf_.insert(buf_.end(), data.begin(), data.begin() + static_cast<ptrdiff_t>(take));
    written_ += take;
    return take;
}

std::span<const uint8_t> SendBuffer::slice(uint64_t offset, uint64_t length) const {
    if (offset < base_) return {};
    const uint64_t rel = offset - base_;
    if (rel >= buf_.size()) return {};
    const uint64_t avail = std::min<uint64_t>(length, buf_.size() - rel);
    return {buf_.data() + rel, static_cast<size_t>(avail)};
}

std::optional<SendBuffer::Chunk> SendBuffer::next_chunk(size_t max_len) {
    if (max_len == 0) return std::nullopt;

    // Retransmissions first. A hole in the receiver's stream stalls everything
    // behind it, so re-sending a lost byte is strictly more valuable than
    // sending a new one.
    if (!retransmit_.empty()) {
        auto it = retransmit_.begin();
        const uint64_t off = it->first;
        const uint64_t len = std::min<uint64_t>(it->second, max_len);
        auto data = slice(off, len);
        if (data.empty() && len > 0) {
            // The underlying bytes were already released as acknowledged;
            // nothing to resend.
            retransmit_.erase(it);
            return next_chunk(max_len);
        }

        Chunk c;
        c.offset     = off;
        c.data       = data;
        c.retransmit = true;
        c.fin        = fin_written_ && (off + data.size() == written_);

        if (len < it->second) {
            const uint64_t rest_off = off + len;
            const uint64_t rest_len = it->second - len;
            retransmit_.erase(it);
            retransmit_[rest_off] = rest_len;
        } else {
            retransmit_.erase(it);
        }
        return c;
    }

    // New data, bounded by the peer's flow-control limit.
    if (sent_ < written_) {
        const uint64_t allowed = peer_max_ > sent_ ? peer_max_ - sent_ : 0;
        if (allowed == 0) return std::nullopt;  // flow-control blocked

        const uint64_t len = std::min<uint64_t>({static_cast<uint64_t>(max_len),
                                                 written_ - sent_, allowed});
        auto data = slice(sent_, len);
        if (data.empty()) return std::nullopt;

        Chunk c;
        c.offset = sent_;
        c.data   = data;
        c.fin    = fin_written_ && (sent_ + data.size() == written_);
        return c;
    }

    // Nothing left but an empty FIN to deliver.
    if (fin_pending()) {
        Chunk c;
        c.offset = written_;
        c.data   = {};
        c.fin    = true;
        return c;
    }

    return std::nullopt;
}

void SendBuffer::on_sent(uint64_t offset, uint64_t length) {
    if (length > 0) unacked_[offset] = length;
    sent_ = std::max(sent_, offset + length);
    if (fin_written_ && offset + length >= written_) fin_sent_ = true;
}

void SendBuffer::on_acked(uint64_t offset, uint64_t length) {
    unacked_.erase(offset);
    // A retransmission may have been queued before this ack arrived.
    retransmit_.erase(offset);
    if (length > 0) acked_[offset] = std::max(acked_[offset], length);
    if (fin_written_ && offset + length >= written_) fin_acked_ = true;
    recompute_prefix();
    release_acked();
}

void SendBuffer::on_lost(uint64_t offset, uint64_t length) {
    if (length == 0) {
        // A lost FIN-only frame: re-arm the FIN rather than a byte range.
        fin_sent_ = false;
        return;
    }
    // Already acknowledged by a later ack that crossed with the loss
    // declaration -- nothing to do.
    if (offset + length <= acked_prefix_) return;
    unacked_.erase(offset);
    retransmit_[offset] = length;
}

void SendBuffer::recompute_prefix() {
    // Walk the acked ranges from the current prefix, extending while they are
    // contiguous. Ranges never overlap partially: a chunk is acked exactly as
    // it was sent.
    bool progressed = true;
    while (progressed) {
        progressed = false;
        auto it    = acked_.find(acked_prefix_);
        if (it != acked_.end()) {
            acked_prefix_ += it->second;
            acked_.erase(it);
            progressed = true;
        }
    }
}

void SendBuffer::release_acked() {
    // Drop bytes below the acknowledged prefix; they can never be needed
    // again. Without this the send buffer grows for the life of the stream.
    if (acked_prefix_ <= base_) return;
    const uint64_t drop = std::min<uint64_t>(acked_prefix_ - base_, buf_.size());
    buf_.erase(buf_.begin(), buf_.begin() + static_cast<ptrdiff_t>(drop));
    base_ += drop;
}

}  // namespace uconnect::stream
