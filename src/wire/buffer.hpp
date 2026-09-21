#pragma once
// Bounds-checked, big-endian cursor over a byte range.
//
// Failure model: a sticky `ok_` flag. Every read past the end returns zero and
// latches the flag; every write past the end is dropped and latches the flag.
// Callers check ok() once at the end instead of testing every field, which is
// what keeps the codecs readable and — more importantly — keeps a malformed
// packet from ever producing a partially-trusted struct.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#include "uconnect/types.hpp"

namespace uconnect::wire {

class Writer {
public:
    explicit Writer(std::span<uint8_t> buf) : buf_(buf) {}

    void u8(uint8_t v) {
        if (!room(1)) return;
        buf_[pos_++] = v;
    }
    void u16(uint16_t v) {
        if (!room(2)) return;
        buf_[pos_++] = static_cast<uint8_t>(v >> 8);
        buf_[pos_++] = static_cast<uint8_t>(v);
    }
    void u32(uint32_t v) {
        if (!room(4)) return;
        for (int s = 24; s >= 0; s -= 8) buf_[pos_++] = static_cast<uint8_t>(v >> s);
    }
    void u64(uint64_t v) {
        if (!room(8)) return;
        for (int s = 56; s >= 0; s -= 8) buf_[pos_++] = static_cast<uint8_t>(v >> s);
    }
    void bytes(const uint8_t* p, size_t n) {
        if (!room(n)) return;
        if (n) std::memcpy(buf_.data() + pos_, p, n);
        pos_ += n;
    }
    void bytes(std::span<const uint8_t> s) { bytes(s.data(), s.size()); }

    template <size_t N>
    void array(const std::array<uint8_t, N>& a) { bytes(a.data(), N); }

    // QUIC-style variable-length integer (RFC 9000 s16). The top two bits of
    // the first byte give the encoded length, so small values are cheap:
    //
    //   00xxxxxx                    1 byte   0 .. 63
    //   01xxxxxx +1                 2 bytes  0 .. 16383
    //   10xxxxxx +3                 4 bytes  0 .. 2^30-1
    //   11xxxxxx +7                 8 bytes  0 .. 2^62-1
    //
    // This matters for stream frames: an offset early in a stream costs one
    // byte rather than eight, and a frame header is mostly offsets.
    void varint(uint64_t v) {
        if (v <= 63) {
            u8(static_cast<uint8_t>(v));
        } else if (v <= 16383) {
            u16(static_cast<uint16_t>(v) | 0x4000u);
        } else if (v <= 0x3FFFFFFFu) {
            u32(static_cast<uint32_t>(v) | 0x80000000u);
        } else if (v <= 0x3FFFFFFFFFFFFFFFull) {
            u64(v | 0xC000000000000000ull);
        } else {
            ok_ = false;  // not representable; refuse rather than truncate
        }
    }

    static constexpr size_t varint_size(uint64_t v) {
        if (v <= 63) return 1;
        if (v <= 16383) return 2;
        if (v <= 0x3FFFFFFFu) return 4;
        return 8;
    }

    // Length-prefixed blobs. u8 prefix caps at 255, u16 at 65535.
    void blob8(std::span<const uint8_t> s) {
        if (s.size() > 0xFF) { ok_ = false; return; }
        u8(static_cast<uint8_t>(s.size()));
        bytes(s);
    }
    void blob16(std::span<const uint8_t> s) {
        if (s.size() > 0xFFFF) { ok_ = false; return; }
        u16(static_cast<uint16_t>(s.size()));
        bytes(s);
    }

    void endpoint(const Endpoint& ep) {
        u8(static_cast<uint8_t>(ep.ip.family));
        bytes(ep.ip.bytes.data(), ep.ip.addr_len());
        u16(ep.port);
    }
    void candidate(const Candidate& c) {
        u8(static_cast<uint8_t>(c.kind));
        endpoint(c.ep);
    }

    bool   ok() const { return ok_; }
    size_t size() const { return pos_; }
    size_t capacity() const { return buf_.size(); }
    size_t remaining() const { return buf_.size() - pos_; }
    std::span<const uint8_t> written() const { return buf_.first(pos_); }

    // Reserve a slot now, fill it after the fact (used for part counts and for
    // MACs that cover the bytes preceding them).
    size_t mark() const { return pos_; }
    void patch_u8(size_t at, uint8_t v) {
        if (at < pos_) buf_[at] = v;
        else ok_ = false;
    }

private:
    bool room(size_t n) {
        if (!ok_ || pos_ + n > buf_.size()) { ok_ = false; return false; }
        return true;
    }

    std::span<uint8_t> buf_;
    size_t             pos_ = 0;
    bool               ok_  = true;
};

class Reader {
public:
    explicit Reader(std::span<const uint8_t> buf) : buf_(buf) {}

    uint8_t u8() {
        if (!have(1)) return 0;
        return buf_[pos_++];
    }
    uint16_t u16() {
        if (!have(2)) return 0;
        uint16_t v = static_cast<uint16_t>(buf_[pos_] << 8 | buf_[pos_ + 1]);
        pos_ += 2;
        return v;
    }
    uint32_t u32() {
        if (!have(4)) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = v << 8 | buf_[pos_ + static_cast<size_t>(i)];
        pos_ += 4;
        return v;
    }
    uint64_t u64() {
        if (!have(8)) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = v << 8 | buf_[pos_ + static_cast<size_t>(i)];
        pos_ += 8;
        return v;
    }

    // Returns a view into the source buffer; valid only while that buffer is.
    std::span<const uint8_t> bytes(size_t n) {
        if (!have(n)) return {};
        auto s = buf_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

    template <size_t N>
    std::array<uint8_t, N> array() {
        std::array<uint8_t, N> out{};
        auto s = bytes(N);
        if (s.size() == N) std::memcpy(out.data(), s.data(), N);
        return out;
    }

    // QUIC-style varint. See Writer::varint for the encoding.
    uint64_t varint() {
        if (!have(1)) return 0;
        uint8_t first = buf_[pos_];
        switch (first >> 6) {
            case 0:
                return u8();
            case 1:
                return u16() & 0x3FFFull;
            case 2:
                return u32() & 0x3FFFFFFFull;
            default:
                return u64() & 0x3FFFFFFFFFFFFFFFull;
        }
    }

    std::span<const uint8_t> blob8()  { return bytes(u8()); }
    std::span<const uint8_t> blob16() { return bytes(u16()); }

    Endpoint endpoint() {
        Endpoint ep;
        uint8_t fam = u8();
        if (fam != 4 && fam != 6) { ok_ = false; return {}; }
        ep.ip.family = static_cast<IpAddr::Family>(fam);
        auto a = bytes(ep.ip.addr_len());
        if (a.size() == ep.ip.addr_len()) std::memcpy(ep.ip.bytes.data(), a.data(), a.size());
        ep.port = u16();
        return ep;
    }
    Candidate candidate() {
        Candidate c;
        uint8_t k = u8();
        if (k > static_cast<uint8_t>(Candidate::Kind::Relay)) { ok_ = false; return {}; }
        c.kind = static_cast<Candidate::Kind>(k);
        c.ep   = endpoint();
        return c;
    }

    bool   ok() const { return ok_; }
    size_t pos() const { return pos_; }
    size_t remaining() const { return ok_ ? buf_.size() - pos_ : 0; }
    bool   empty() const { return remaining() == 0; }

    // Everything consumed so far — the input to a MAC that covers the message
    // up to (but not including) the MAC field itself.
    std::span<const uint8_t> consumed() const { return buf_.first(pos_); }

private:
    bool have(size_t n) {
        if (!ok_ || pos_ + n > buf_.size()) { ok_ = false; return false; }
        return true;
    }

    std::span<const uint8_t> buf_;
    size_t                   pos_ = 0;
    bool                     ok_  = true;
};

}  // namespace uconnect::wire
