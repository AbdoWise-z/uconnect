#include "session.hpp"

#include <cstring>

namespace uconnect::session {
namespace {

constexpr std::string_view kPrologueTag = "uconnect:v1";

// Message 1 carries only random padding. Under psk0 its payload is encrypted
// with a key derived from the PSK alone, before any DH has happened, so it has
// no forward secrecy. Real data goes in the first transport message.
constexpr size_t kInitPadding = 32;

std::vector<uint8_t> encode_handshake_init(wire::ConnId conn_id, const wire::ProbeTxn& txn,
                                           std::span<const uint8_t> noise_msg,
                                           uint32_t txn_id) {
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::HandshakeInit, wire::kVersion, 0, txn_id}.encode(w);
    wire::HandshakeInit hi;
    hi.conn_id   = conn_id;
    hi.probe_txn = txn;
    hi.noise_msg.assign(noise_msg.begin(), noise_msg.end());
    hi.encode(w);
    buf.resize(w.size());
    return buf;
}

std::vector<uint8_t> encode_handshake_resp(wire::ConnId conn_id,
                                           std::span<const uint8_t> noise_msg,
                                           uint32_t txn_id) {
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::HandshakeResp, wire::kVersion, 0, txn_id}.encode(w);
    wire::HandshakeResp hr;
    hr.conn_id = conn_id;
    hr.noise_msg.assign(noise_msg.begin(), noise_msg.end());
    hr.encode(w);
    buf.resize(w.size());
    return buf;
}

}  // namespace

// ---------------------------------------------------------------------------
// ReplayWindow
// ---------------------------------------------------------------------------
bool ReplayWindow::accept(uint64_t counter) {
    if (!seen_) {
        seen_    = true;
        highest_ = counter;
        bitmap_  = 1;
        return true;
    }

    if (counter > highest_) {
        uint64_t shift = counter - highest_;
        if (shift >= kWidth) bitmap_ = 0;
        else bitmap_ <<= shift;
        bitmap_ |= 1;
        highest_ = counter;
        return true;
    }

    uint64_t behind = highest_ - counter;
    // Too old to judge. Accepting would permit unbounded replay; rejecting may
    // drop a genuinely ancient reorder, which is the right trade.
    if (behind >= kWidth) return false;

    uint64_t mask = uint64_t{1} << behind;
    if (bitmap_ & mask) return false;  // already seen
    bitmap_ |= mask;
    return true;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
Session::Session(SessionConfig cfg, const DevId& peer, Endpoint path, bool keyed,
                 wire::ConnId conn_id)
    : cfg_(cfg), peer_(peer), path_(path), keyed_(keyed), conn_id_(conn_id) {}

std::vector<uint8_t> Session::make_prologue(const TopicId& topic, uint8_t key_epoch,
                                            const wire::ProbeTxn& txn) {
    std::vector<uint8_t> p;
    p.reserve(kPrologueTag.size() + kTopicIdLen + 1 + wire::kProbeTxnLen);
    p.insert(p.end(), kPrologueTag.begin(), kPrologueTag.end());
    p.insert(p.end(), topic.begin(), topic.end());
    p.push_back(key_epoch);
    p.insert(p.end(), txn.begin(), txn.end());
    return p;
}

Session Session::initiate(SessionConfig cfg, const TopicId& topic, uint8_t key_epoch,
                          const crypto::SymKey* psk, const DevId& peer, Endpoint path,
                          const wire::ProbeTxn& probe_txn, Instant now) {
    auto id_bytes = crypto::random_array<4>();
    wire::ConnId conn_id = static_cast<wire::ConnId>(id_bytes[0]) << 24 |
                           static_cast<wire::ConnId>(id_bytes[1]) << 16 |
                           static_cast<wire::ConnId>(id_bytes[2]) << 8 |
                           static_cast<wire::ConnId>(id_bytes[3]);

    Session s{cfg, peer, path, psk != nullptr, conn_id};
    s.initiator_ = true;

    auto prologue = make_prologue(topic, key_epoch, probe_txn);
    s.handshake_  = crypto::HandshakeState::initiator(
        psk ? crypto::Pattern::NNpsk0 : crypto::Pattern::NN, prologue, psk);

    std::vector<uint8_t> padding(kInitPadding);
    crypto::random_bytes(padding);

    std::vector<uint8_t> msg(256);
    auto n = s.handshake_->write_message(padding, msg);
    if (!n) {
        s.state_ = SessionState::Closed;
        return s;
    }
    msg.resize(*n);
    s.handshake_msg_ = encode_handshake_init(conn_id, probe_txn, msg, 1);
    s.emit_handshake_init(now);
    return s;
}

void Session::emit_handshake_init(Instant now) {
    out_.push_back({path_, handshake_msg_});
    ++handshake_attempts_;
    handshake_next_ = now + cfg_.handshake_timeout;
}

std::optional<Session> Session::accept(SessionConfig cfg, const TopicId& topic,
                                       uint8_t key_epoch, const crypto::SymKey* psk,
                                       const DevId& peer, Endpoint from,
                                       const wire::ProbeTxn& probe_txn,
                                       std::span<const uint8_t> dgram, Instant now) {
    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h || h->type != wire::MsgType::HandshakeInit) return std::nullopt;

    auto hi = wire::HandshakeInit::decode(r);
    if (!hi) return std::nullopt;

    // The caller has already checked that probe_txn was issued by us on this
    // path, is unused, and is recent. Re-check the binding here so a session
    // can never be built on a transaction it does not match.
    if (!crypto::ct_equal(hi->probe_txn, probe_txn)) return std::nullopt;

    Session s{cfg, peer, from, psk != nullptr, hi->conn_id};
    s.initiator_ = false;

    auto prologue = make_prologue(topic, key_epoch, probe_txn);
    s.handshake_  = crypto::HandshakeState::responder(
        psk ? crypto::Pattern::NNpsk0 : crypto::Pattern::NN, prologue, psk);

    std::vector<uint8_t> payload(256);
    if (!s.handshake_->read_message(hi->noise_msg, payload)) {
        // Wrong PSK, wrong prologue, or tampering. Drop silently.
        return std::nullopt;
    }

    std::vector<uint8_t> msg(256);
    auto n = s.handshake_->write_message({}, msg);
    if (!n) return std::nullopt;
    msg.resize(*n);

    s.out_.push_back({from, encode_handshake_resp(hi->conn_id, msg, h->txn_id)});
    s.finish_handshake(s.handshake_->split(), now);
    return s;
}

void Session::finish_handshake(crypto::Split split, Instant now) {
    send_cs_        = split.send;
    recv_cs_        = split.recv;
    handshake_hash_ = split.handshake_hash;
    handshake_.reset();

    state_          = SessionState::Established;
    established_at_ = now;
    last_recv_      = now;
    next_keepalive_ = now + cfg_.keepalive;
    events_.push_back({SessionEvent::Kind::Established, {}, path_});
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------
void Session::on_datagram(const Endpoint& from, std::span<const uint8_t> dgram, Instant now) {
    if (state_ == SessionState::Closed) return;

    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h) return;

    if (h->type == wire::MsgType::HandshakeResp) {
        if (!initiator_ || state_ != SessionState::Handshaking || !handshake_) return;
        auto hr = wire::HandshakeResp::decode(r);
        if (!hr || hr->conn_id != conn_id_) return;

        std::vector<uint8_t> payload(256);
        if (!handshake_->read_message(hr->noise_msg, payload)) return;  // drop silently
        if (!handshake_->is_finished()) return;
        finish_handshake(handshake_->split(), now);
        return;
    }

    if (h->type != wire::MsgType::Transport) return;
    if (state_ != SessionState::Established && state_ != SessionState::NeedsRehandshake) return;

    auto t = wire::Transport::decode(r);
    if (!t || t->conn_id != conn_id_) return;

    std::vector<uint8_t> plain(t->ciphertext.size());
    auto n = recv_cs_.decrypt_at(t->counter, {}, t->ciphertext, plain);
    if (!n) return;  // forged or corrupt: drop, say nothing

    // Only after the AEAD verifies is the counter trustworthy enough to feed
    // the replay window -- otherwise an attacker could poison it with forged
    // high counters and lock out the real peer.
    if (!replay_.accept(t->counter)) return;

    ++received_;
    last_recv_ = now;

    if (!(from == path_)) {
        // The AEAD verified, so this really is our peer arriving from a new
        // address: a NAT rebind or a Wi-Fi/LTE handoff. Matching on conn_id
        // rather than the 4-tuple is what lets the session survive it.
        path_ = from;
        events_.push_back({SessionEvent::Kind::PathChanged, {}, from});
    }

    plain.resize(*n);
    if (plain.empty()) return;  // keepalive
    events_.push_back({SessionEvent::Kind::Data, std::move(plain), {}});
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------
bool Session::send(std::span<const uint8_t> payload, Instant now) {
    if (state_ != SessionState::Established) return false;

    std::vector<uint8_t> ct(payload.size() + crypto::kTagLen);
    send_cs_.encrypt_at(send_counter_, {}, payload, ct);

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Transport, wire::kVersion, 0, 0}.encode(w);
    wire::Transport t;
    t.conn_id    = conn_id_;
    t.counter    = send_counter_;
    t.ciphertext = ct;
    t.encode(w);
    if (!w.ok()) return false;
    buf.resize(w.size());

    ++send_counter_;
    out_.push_back({path_, std::move(buf)});
    next_keepalive_ = now + cfg_.keepalive;
    return true;
}

void Session::queue_keepalive(Instant now) {
    send({}, now);  // an empty payload; the peer treats it as a keepalive
}

void Session::close(Instant now) {
    (void)now;
    if (state_ == SessionState::Closed) return;
    state_ = SessionState::Closed;
    send_cs_.clear();
    recv_cs_.clear();
    events_.push_back({SessionEvent::Kind::Closed, {}, {}});
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------
void Session::on_timeout(Instant now) {
    if (state_ == SessionState::Closed) return;

    if (state_ == SessionState::Handshaking) {
        if (now < handshake_next_) return;
        if (handshake_attempts_ >= cfg_.handshake_retries) {
            close(now);
            return;
        }
        if (initiator_) emit_handshake_init(now);
        return;
    }

    if (now - last_recv_ >= cfg_.idle_timeout) {
        close(now);
        return;
    }

    if (state_ == SessionState::Established && now - established_at_ >= cfg_.max_lifetime) {
        // No in-place rekey: ask the layer above for a fresh handshake instead.
        // The path is still good, so this is cheap.
        state_ = SessionState::NeedsRehandshake;
        events_.push_back({SessionEvent::Kind::NeedsRehandshake, {}, path_});
        return;
    }

    if (state_ == SessionState::Established && now >= next_keepalive_) {
        queue_keepalive(now);
    }
}

std::optional<Instant> Session::next_timeout() const {
    switch (state_) {
        case SessionState::Handshaking:
            return handshake_next_;
        case SessionState::Established: {
            Instant idle    = last_recv_ + cfg_.idle_timeout;
            Instant life    = established_at_ + cfg_.max_lifetime;
            Instant soonest = next_keepalive_;
            if (idle < soonest) soonest = idle;
            if (life < soonest) soonest = life;
            return soonest;
        }
        case SessionState::NeedsRehandshake:
            return last_recv_ + cfg_.idle_timeout;
        case SessionState::Closed:
            return std::nullopt;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------
std::optional<Outgoing> Session::poll_transmit() {
    if (out_.empty()) return std::nullopt;
    Outgoing o = std::move(out_.front());
    out_.erase(out_.begin());
    return o;
}

std::optional<SessionEvent> Session::poll_event() {
    if (events_.empty()) return std::nullopt;
    SessionEvent e = std::move(events_.front());
    events_.pop_front();
    return e;
}

std::string Session::sas() const { return crypto::sas_string(handshake_hash_); }

}  // namespace uconnect::session
