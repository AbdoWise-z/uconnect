#include "frame.hpp"

namespace uconnect::stream {
namespace {

using wire::Writer;
using wire::Reader;

// Every encoder follows the same shape: measure first, bail if it will not
// fit, only then write. A half-written frame would corrupt the datagram, and
// since the caller flushes and retries on `false`, a clean refusal is cheap.
bool fits(const Writer& w, size_t need) { return w.remaining() >= need; }

}  // namespace

uint64_t AckFrame::smallest() const {
    uint64_t lo = first_range > largest ? 0 : largest - first_range;
    for (const auto& r : ranges) {
        if (lo < r.gap + 2) break;
        uint64_t hi = lo - r.gap - 2;
        if (r.len > hi) break;
        lo = hi - r.len;
    }
    return lo;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------
bool encode_padding(Writer& w, size_t count) {
    if (!fits(w, count)) return false;
    for (size_t i = 0; i < count; ++i) w.u8(static_cast<uint8_t>(FrameType::Padding));
    return w.ok();
}

bool encode_ping(Writer& w) {
    if (!fits(w, 1)) return false;
    w.u8(static_cast<uint8_t>(FrameType::Ping));
    return w.ok();
}

size_t ack_frame_size(const AckFrame& a) {
    size_t n = 1;
    n += Writer::varint_size(a.largest);
    n += Writer::varint_size(a.delay_us);
    n += Writer::varint_size(a.ranges.size());
    n += Writer::varint_size(a.first_range);
    for (const auto& r : a.ranges) {
        n += Writer::varint_size(r.gap);
        n += Writer::varint_size(r.len);
    }
    return n;
}

bool encode_ack(Writer& w, const AckFrame& a) {
    if (!fits(w, ack_frame_size(a))) return false;
    w.u8(static_cast<uint8_t>(FrameType::Ack));
    w.varint(a.largest);
    w.varint(a.delay_us);
    w.varint(a.ranges.size());
    w.varint(a.first_range);
    for (const auto& r : a.ranges) {
        w.varint(r.gap);
        w.varint(r.len);
    }
    return w.ok();
}

bool encode_reset_stream(Writer& w, const ResetStreamFrame& f) {
    size_t n = 1 + Writer::varint_size(f.id) + Writer::varint_size(f.error_code) +
               Writer::varint_size(f.final_size);
    if (!fits(w, n)) return false;
    w.u8(static_cast<uint8_t>(FrameType::ResetStream));
    w.varint(f.id);
    w.varint(f.error_code);
    w.varint(f.final_size);
    return w.ok();
}

bool encode_stop_sending(Writer& w, const StopSendingFrame& f) {
    size_t n = 1 + Writer::varint_size(f.id) + Writer::varint_size(f.error_code);
    if (!fits(w, n)) return false;
    w.u8(static_cast<uint8_t>(FrameType::StopSending));
    w.varint(f.id);
    w.varint(f.error_code);
    return w.ok();
}

bool encode_max_data(Writer& w, const MaxDataFrame& f) {
    size_t n = 1 + Writer::varint_size(f.max);
    if (!fits(w, n)) return false;
    w.u8(static_cast<uint8_t>(FrameType::MaxData));
    w.varint(f.max);
    return w.ok();
}

bool encode_max_stream_data(Writer& w, const MaxStreamDataFrame& f) {
    size_t n = 1 + Writer::varint_size(f.id) + Writer::varint_size(f.max);
    if (!fits(w, n)) return false;
    w.u8(static_cast<uint8_t>(FrameType::MaxStreamData));
    w.varint(f.id);
    w.varint(f.max);
    return w.ok();
}

bool encode_data_blocked(Writer& w, const DataBlockedFrame& f) {
    size_t n = 1 + Writer::varint_size(f.limit);
    if (!fits(w, n)) return false;
    w.u8(static_cast<uint8_t>(FrameType::DataBlocked));
    w.varint(f.limit);
    return w.ok();
}

size_t stream_frame_overhead(StreamId id, uint64_t offset) {
    // type + id + optional offset + an explicit length. The length is always
    // written here: omitting it only pays off for the last frame in a
    // datagram, and the packer does not know in advance that it is last.
    size_t n = 1 + Writer::varint_size(id);
    if (offset > 0) n += Writer::varint_size(offset);
    n += 2;  // length varint, sized below
    return n;
}

size_t encode_stream(Writer& w, StreamId id, uint64_t offset, bool fin,
                     std::span<const uint8_t> data) {
    uint8_t type = static_cast<uint8_t>(FrameType::StreamBase) | stream_flags::kLen;
    size_t  head = 1 + Writer::varint_size(id);
    if (offset > 0) {
        type |= stream_flags::kOffset;
        head += Writer::varint_size(offset);
    }

    // Reserve room for the length varint itself. Two bytes covers any payload
    // that fits in a datagram, and using a fixed width keeps the arithmetic
    // honest -- computing capacity against a variable-width length is how
    // off-by-one truncation bugs get written.
    constexpr size_t kLenWidth = 2;
    if (w.remaining() < head + kLenWidth + 1) return 0;

    size_t room = w.remaining() - head - kLenWidth;
    size_t take = data.size() < room ? data.size() : room;

    // Only set FIN when the whole remainder fits; a truncated frame is not the
    // end of the stream.
    if (fin && take == data.size()) type |= stream_flags::kFin;

    w.u8(type);
    w.varint(id);
    if (offset > 0) w.varint(offset);
    // Two-byte varint form (0x4000 | value), valid for 0..16383.
    w.u16(static_cast<uint16_t>(take) | 0x4000u);
    w.bytes(data.data(), take);
    return w.ok() ? take : 0;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------
bool decode_frames(std::span<const uint8_t> payload, std::vector<Frame>& out) {
    out.clear();
    Reader r{payload};

    while (r.remaining() > 0) {
        uint8_t type = r.u8();
        if (!r.ok()) return false;

        // STREAM occupies exactly 0x08..0x0F: the base type plus three flag
        // bits. An open-ended `>= StreamBase` would swallow every higher type
        // value and parse arbitrary bytes as a stream frame, which is both a
        // correctness bug and a decoder that never rejects garbage.
        constexpr uint8_t kStreamLo = static_cast<uint8_t>(FrameType::StreamBase);
        constexpr uint8_t kStreamHi = kStreamLo | stream_flags::kFin |
                                      stream_flags::kLen | stream_flags::kOffset;
        if (type >= kStreamLo && type <= kStreamHi) {
            Frame f;
            f.type          = FrameType::StreamBase;
            f.stream        = StreamFrame{};
            f.stream.id     = r.varint();
            if (type & stream_flags::kOffset) f.stream.offset = r.varint();
            f.stream.fin = (type & stream_flags::kFin) != 0;

            size_t len;
            if (type & stream_flags::kLen) {
                len = static_cast<size_t>(r.varint());
            } else {
                len = r.remaining();  // extends to the end of the datagram
            }
            if (!r.ok()) return false;
            auto d = r.bytes(len);
            if (!r.ok() || d.size() != len) return false;
            f.stream.data = d;
            out.push_back(f);
            continue;
        }

        switch (static_cast<FrameType>(type)) {
            case FrameType::Padding:
                continue;  // padding is a no-op; do not even record it

            case FrameType::Ping: {
                Frame f;
                f.type = FrameType::Ping;
                out.push_back(f);
                break;
            }

            case FrameType::Ack: {
                Frame f;
                f.type          = FrameType::Ack;
                f.ack.largest   = r.varint();
                f.ack.delay_us  = r.varint();
                uint64_t count  = r.varint();
                f.ack.first_range = r.varint();
                if (!r.ok()) return false;
                // A range count is attacker-influenced; cap it before
                // reserving so a 4-byte varint cannot demand gigabytes.
                if (count > 512) return false;
                f.ack.ranges.reserve(static_cast<size_t>(count));
                for (uint64_t i = 0; i < count; ++i) {
                    AckRange range;
                    range.gap = r.varint();
                    range.len = r.varint();
                    if (!r.ok()) return false;
                    f.ack.ranges.push_back(range);
                }
                out.push_back(std::move(f));
                break;
            }

            case FrameType::ResetStream: {
                Frame f;
                f.type             = FrameType::ResetStream;
                f.reset            = ResetStreamFrame{};
                f.reset.id         = r.varint();
                f.reset.error_code = r.varint();
                f.reset.final_size = r.varint();
                if (!r.ok()) return false;
                out.push_back(f);
                break;
            }

            case FrameType::StopSending: {
                Frame f;
                f.type            = FrameType::StopSending;
                f.stop            = StopSendingFrame{};
                f.stop.id         = r.varint();
                f.stop.error_code = r.varint();
                if (!r.ok()) return false;
                out.push_back(f);
                break;
            }

            case FrameType::MaxData: {
                Frame f;
                f.type         = FrameType::MaxData;
                f.max_data     = MaxDataFrame{};
                f.max_data.max = r.varint();
                if (!r.ok()) return false;
                out.push_back(f);
                break;
            }

            case FrameType::MaxStreamData: {
                Frame f;
                f.type                = FrameType::MaxStreamData;
                f.max_stream_data     = MaxStreamDataFrame{};
                f.max_stream_data.id  = r.varint();
                f.max_stream_data.max = r.varint();
                if (!r.ok()) return false;
                out.push_back(f);
                break;
            }

            case FrameType::DataBlocked: {
                Frame f;
                f.type          = FrameType::DataBlocked;
                f.blocked       = DataBlockedFrame{};
                f.blocked.limit = r.varint();
                if (!r.ok()) return false;
                out.push_back(f);
                break;
            }

            default:
                // An unknown frame type cannot be skipped, because frames are
                // not length-prefixed. Refuse the whole datagram rather than
                // guess at the remainder.
                return false;
        }
    }

    return r.ok();
}

}  // namespace uconnect::stream
