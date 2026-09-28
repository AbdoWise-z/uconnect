#include "tcp_session.hpp"

#include <cstring>
#include <string_view>

namespace uconnect::session {
namespace {

constexpr std::string_view kPrologueTag = "uconnect:v2:tcp";

// The session's own record kinds; everything from kFirstUserKind up belongs
// to the layer above.
constexpr uint8_t kKeepalive = 0x01;
constexpr uint8_t kClose     = 0x02;

// Handshake frames are small and fixed in shape; anything longer is not one.
constexpr size_t kMaxHandshakeFrame = 512;

// Message 1's payload: the initiator's dev_id and padding. Under psk0 it is
// sealed with a key from the PSK alone, before any DH -- no forward secrecy,
// which is fine for a dev_id the server hands out to anyone who looks.
constexpr size_t kInitPadding = 16;

void put_u16(std::vector<uint8_t>& v, size_t n) {
    v.push_back(static_cast<uint8_t>(n >> 8));
    v.push_back(static_cast<uint8_t>(n));
}

void put_u32(std::vector<uint8_t>& v, size_t n) {
    for (int s = 24; s >= 0; s -= 8) v.push_back(static_cast<uint8_t>(n >> s));
}

size_t get_u16(const std::vector<uint8_t>& v) {
    return static_cast<size_t>(v[0]) << 8 | v[1];
}

size_t get_u32(const std::vector<uint8_t>& v) {
    return static_cast<size_t>(v[0]) << 24 | static_cast<size_t>(v[1]) << 16 |
           static_cast<size_t>(v[2]) << 8 | v[3];
}

void consume(std::vector<uint8_t>& v, size_t n) {
    v.erase(v.begin(), v.begin() + static_cast<ptrdiff_t>(n));
}

}  // namespace

TcpSession::TcpSession(TcpSessionConfig cfg, bool initiator, const DevId& self,
                       const DevId& peer, Instant now)
    : cfg_(cfg), initiator_(initiator), self_(self), peer_(peer), started_(now),
      last_recv_(now), last_sent_(now) {}

std::vector<uint8_t> TcpSession::prologue(const TopicId& topic, uint8_t key_epoch,
                                          const AttemptNonce& attempt) {
    // Both ends must agree on all of it or the handshake fails
    // cryptographically -- the topic, the key epoch, and the one introduction
    // this connection answers.
    std::vector<uint8_t> p(kPrologueTag.begin(), kPrologueTag.end());
    p.insert(p.end(), topic.begin(), topic.end());
    p.push_back(key_epoch);
    p.insert(p.end(), attempt.begin(), attempt.end());
    return p;
}

TcpSession TcpSession::initiate(TcpSessionConfig cfg, const TopicId& topic, uint8_t key_epoch,
                                const crypto::SymKey* psk, const DevId& self, const DevId& peer,
                                const AttemptNonce& attempt, Instant now) {
    TcpSession s{cfg, true, self, peer, now};
    s.attempt_ = attempt;
    s.hs_      = crypto::HandshakeState::initiator(
        psk ? crypto::Pattern::NNpsk0 : crypto::Pattern::NN, prologue(topic, key_epoch, attempt),
        psk);

    std::vector<uint8_t> payload(kDevIdLen + kInitPadding);
    std::memcpy(payload.data(), self.data(), kDevIdLen);
    crypto::random_bytes(std::span(payload).subspan(kDevIdLen));

    std::vector<uint8_t> msg(256);
    auto n = s.hs_->write_message(payload, msg);
    if (!n) {
        s.fail(CloseCause::Local, now);
        return s;
    }
    put_u16(s.out_, kAttemptLen + *n);
    s.out_.insert(s.out_.end(), attempt.begin(), attempt.end());
    s.out_.insert(s.out_.end(), msg.begin(), msg.begin() + static_cast<ptrdiff_t>(*n));
    return s;
}

TcpSession TcpSession::respond(TcpSessionConfig cfg, const TopicId& topic, uint8_t key_epoch,
                               const crypto::SymKey* psk, const DevId& self, const DevId& peer,
                               const AttemptNonce& attempt, Instant now) {
    TcpSession s{cfg, false, self, peer, now};
    s.attempt_ = attempt;
    s.hs_      = crypto::HandshakeState::responder(
        psk ? crypto::Pattern::NNpsk0 : crypto::Pattern::NN, prologue(topic, key_epoch, attempt),
        psk);
    return s;
}

std::optional<AttemptNonce> TcpSession::peek_attempt(std::span<const uint8_t> received) {
    if (received.size() < 2 + kAttemptLen) return std::nullopt;
    const size_t len = static_cast<size_t>(received[0]) << 8 | received[1];
    if (len < kAttemptLen || len > kMaxHandshakeFrame) return std::nullopt;
    AttemptNonce a{};
    std::memcpy(a.data(), received.data() + 2, kAttemptLen);
    return a;
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------
void TcpSession::on_bytes(std::span<const uint8_t> bytes, Instant now) {
    if (state_ == State::Closed) return;
    in_.insert(in_.end(), bytes.begin(), bytes.end());

    while (state_ != State::Closed) {
        if (state_ == State::Handshaking) {
            if (in_.size() < 2) return;
            const size_t len = get_u16(in_);
            if (len > kMaxHandshakeFrame || (!initiator_ && len < kAttemptLen)) {
                fail(CloseCause::Local, now);
                return;
            }
            if (in_.size() < 2 + len) return;
            std::vector<uint8_t> frame(in_.begin() + 2, in_.begin() + 2 + static_cast<ptrdiff_t>(len));
            consume(in_, 2 + len);

            std::vector<uint8_t> payload(256);
            if (!initiator_) {
                // Message 1, for the attempt this session was built for.
                if (std::memcmp(frame.data(), attempt_.data(), kAttemptLen) != 0) {
                    fail(CloseCause::Local, now);
                    return;
                }
                auto n = hs_->read_message(std::span(frame).subspan(kAttemptLen), payload);
                // The claimed dev_id must be the peer this attempt introduced.
                // On a keyed topic the claim is sealed under the PSK; on an
                // open one it is not, but the attempt was issued for this
                // peer alone, so a mismatch is simply not our peer.
                if (!n || *n < kDevIdLen || std::memcmp(payload.data(), peer_.data(), kDevIdLen) != 0) {
                    fail(CloseCause::Local, now);
                    return;
                }
                std::vector<uint8_t> msg(256);
                auto m = hs_->write_message(std::span<const uint8_t>(self_.data(), kDevIdLen), msg);
                if (!m) {
                    fail(CloseCause::Local, now);
                    return;
                }
                put_u16(out_, *m);
                out_.insert(out_.end(), msg.begin(), msg.begin() + static_cast<ptrdiff_t>(*m));
                finish(hs_->split(), now);
            } else {
                // Message 2.
                auto n = hs_->read_message(frame, payload);
                if (!n || *n < kDevIdLen || std::memcmp(payload.data(), peer_.data(), kDevIdLen) != 0) {
                    fail(CloseCause::Local, now);
                    return;
                }
                finish(hs_->split(), now);
            }
            continue;
        }

        // Established: sealed records.
        if (in_.size() < 4) return;
        const size_t len = get_u32(in_);
        if (len < 1 + crypto::kTagLen || len > cfg_.max_record + 1 + crypto::kTagLen) {
            fail(CloseCause::Local, now);
            return;
        }
        if (in_.size() < 4 + len) return;
        std::vector<uint8_t> plain(len - crypto::kTagLen);
        auto n = recv_cs_.decrypt_with_ad({}, std::span<const uint8_t>(in_.data() + 4, len), plain);
        consume(in_, 4 + len);
        if (!n) {
            // TCP does not lose or reorder, so a record that fails its tag was
            // tampered with, or this is not our peer. Either way, done.
            fail(CloseCause::Local, now);
            return;
        }
        if (++recv_records_ % cfg_.rekey_every == 0) recv_cs_.rekey();
        last_recv_ = now;
        handle_record(plain, now);
    }
}

void TcpSession::handle_record(std::span<const uint8_t> plain, Instant now) {
    (void)now;
    if (plain.empty()) return;
    const uint8_t kind = plain[0];
    auto          body = plain.subspan(1);

    if (kind == kKeepalive) return;
    if (kind == kClose) {
        const uint16_t reason =
            body.size() >= 2 ? static_cast<uint16_t>(body[0] << 8 | body[1]) : 0;
        state_ = State::Closed;
        send_cs_.clear();
        recv_cs_.clear();
        TcpEvent e;
        e.kind        = TcpEvent::Kind::Closed;
        e.cause       = CloseCause::PeerNotice;
        e.peer_reason = reason;
        events_.push_back(std::move(e));
        return;
    }
    if (kind < kFirstUserKind) return;  // a session kind we do not know: ignore

    TcpEvent e;
    e.kind        = TcpEvent::Kind::Record;
    e.record_kind = kind;
    e.body.assign(body.begin(), body.end());
    events_.push_back(std::move(e));
}

void TcpSession::finish(crypto::Split split, Instant now) {
    send_cs_        = split.send;
    recv_cs_        = split.recv;
    handshake_hash_ = split.handshake_hash;
    exported_       = split.exported;
    hs_.reset();
    state_     = State::Established;
    last_recv_ = now;
    last_sent_ = now;
    events_.push_back(TcpEvent{TcpEvent::Kind::Established, 0, {}, CloseCause::Local, 0});
}

void TcpSession::on_eof(Instant now) {
    if (state_ != State::Closed) fail(CloseCause::TimedOut, now);
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------
void TcpSession::seal(uint8_t kind, std::span<const uint8_t> body) {
    std::vector<uint8_t> plain;
    plain.reserve(body.size() + 1);
    plain.push_back(kind);
    plain.insert(plain.end(), body.begin(), body.end());

    std::vector<uint8_t> ct(plain.size() + crypto::kTagLen);
    send_cs_.encrypt_with_ad({}, plain, ct);
    put_u32(out_, ct.size());
    out_.insert(out_.end(), ct.begin(), ct.end());
    if (++sent_records_ % cfg_.rekey_every == 0) send_cs_.rekey();
}

bool TcpSession::send(uint8_t kind, std::span<const uint8_t> body, Instant now) {
    if (state_ != State::Established || kind < kFirstUserKind || body.size() > cfg_.max_record) {
        return false;
    }
    seal(kind, body);
    last_sent_ = now;
    return true;
}

void TcpSession::close(uint16_t reason, Instant now) {
    (void)now;
    if (state_ == State::Closed) return;
    if (state_ == State::Established) {
        const uint8_t r[2] = {static_cast<uint8_t>(reason >> 8), static_cast<uint8_t>(reason)};
        seal(kClose, r);
    }
    state_ = State::Closed;
    send_cs_.clear();
    recv_cs_.clear();
    TcpEvent e;
    e.kind  = TcpEvent::Kind::Closed;
    e.cause = CloseCause::Local;
    events_.push_back(std::move(e));
}

void TcpSession::fail(CloseCause cause, Instant now) {
    (void)now;
    if (state_ == State::Closed) return;
    state_ = State::Closed;
    hs_.reset();
    send_cs_.clear();
    recv_cs_.clear();
    in_.clear();
    TcpEvent e;
    e.kind  = TcpEvent::Kind::Closed;
    e.cause = cause;
    events_.push_back(std::move(e));
}

// ---------------------------------------------------------------------------
// Timers and polling
// ---------------------------------------------------------------------------
void TcpSession::on_timeout(Instant now) {
    if (state_ == State::Handshaking) {
        if (now - started_ >= cfg_.handshake_timeout) fail(CloseCause::TimedOut, now);
        return;
    }
    if (state_ != State::Established) return;
    if (now - last_recv_ >= cfg_.idle_timeout) {
        fail(CloseCause::TimedOut, now);
        return;
    }
    if (now - last_sent_ >= cfg_.keepalive) {
        seal(kKeepalive, {});
        last_sent_ = now;
    }
}

std::optional<Instant> TcpSession::next_timeout() const {
    switch (state_) {
        case State::Handshaking:
            return started_ + cfg_.handshake_timeout;
        case State::Established: {
            const Instant idle = last_recv_ + cfg_.idle_timeout;
            const Instant ka   = last_sent_ + cfg_.keepalive;
            return idle < ka ? idle : ka;
        }
        case State::Closed:
            return std::nullopt;
    }
    return std::nullopt;
}

std::vector<uint8_t> TcpSession::take_output() {
    std::vector<uint8_t> out;
    out.swap(out_);
    return out;
}

std::optional<TcpEvent> TcpSession::poll_event() {
    if (events_.empty()) return std::nullopt;
    TcpEvent e = std::move(events_.front());
    events_.pop_front();
    return e;
}

TcpSession::DatagramKeys TcpSession::datagram_keys(uint32_t epoch) const {
    // Each from the exported secret under its own label: the UDP channel
    // shares no key with this one, and its two directions share none either.
    // The epoch is the salt, so every channel opened on this session gets
    // keys of its own.
    const std::array<uint8_t, 4> salt{static_cast<uint8_t>(epoch >> 24),
                                      static_cast<uint8_t>(epoch >> 16),
                                      static_cast<uint8_t>(epoch >> 8),
                                      static_cast<uint8_t>(epoch)};
    DatagramKeys k;
    crypto::SymKey i2r{}, r2i{};
    crypto::hkdf(exported_, salt, "uconnect:v2:udp:i2r", i2r);
    crypto::hkdf(exported_, salt, "uconnect:v2:udp:r2i", r2i);
    crypto::hkdf(exported_, salt, "uconnect:v2:udp:probe", k.probe);
    std::array<uint8_t, 4> id{};
    crypto::hkdf(exported_, salt, "uconnect:v2:udp:conn", id);
    k.conn_id = static_cast<uint32_t>(id[0]) << 24 | static_cast<uint32_t>(id[1]) << 16 |
                static_cast<uint32_t>(id[2]) << 8 | id[3];
    k.send = initiator_ ? i2r : r2i;
    k.recv = initiator_ ? r2i : i2r;
    crypto::secure_zero(i2r);
    crypto::secure_zero(r2i);
    return k;
}

}  // namespace uconnect::session
