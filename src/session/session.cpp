#include "session.hpp"

#include <cstring>
#include <span>
#include <utility>

namespace uconnect::session {

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
Session::Session(SessionConfig cfg, const DevId& peer, Endpoint path, const crypto::SymKey& send,
                 const crypto::SymKey& recv, wire::ConnId conn_id, Instant now)
    : cfg_(cfg),
      peer_(peer),
      path_(path),
      conn_id_(conn_id),
      send_cs_(send),
      recv_cs_(recv),
      last_recv_(now),
      next_keepalive_(now + cfg.keepalive) {}

void Session::set_path(const Endpoint& path, Instant now) {
    path_ = path;
    // A new path needs its NAT mapping opened and held from our side too.
    next_keepalive_ = now;
}

bool Session::configure_rekey_shift(uint8_t shift) {
    if (state_ != SessionState::Established || send_counter_ != 0 || received_ != 0 ||
        shift < 7 || shift > 63) return false;
    cfg_.rekey_shift = shift;
    return true;
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------
void Session::on_datagram(const Endpoint& from, std::span<const uint8_t> dgram, Instant now) {
    if (state_ == SessionState::Closed) return;

    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h) return;

    if (h->type == wire::MsgType::Close) {
        auto m = wire::Close::decode(r);
        if (!m || m->conn_id != conn_id_) return;

        // Sealed against its own type byte, so a re-typed data packet fails
        // here rather than tearing the session down.
        const uint8_t        ad = static_cast<uint8_t>(wire::MsgType::Close);
        std::vector<uint8_t> plain(m->ciphertext.size());
        // Key generation, AEAD and replay window, in that order, inside
        // open_packet. Forged or corrupt: drop, say nothing.
        auto n = open_packet(m->counter, std::span<const uint8_t>(&ad, 1),
                             m->ciphertext, plain, now);
        if (!n) return;

        plain.resize(*n);
        const uint16_t peer_reason =
            plain.size() >= 2 ? static_cast<uint16_t>((plain[0] << 8) | plain[1])
                              : wire::close_reason::kUnspecified;

        last_recv_ = now;
        close_with_cause(now, CloseCause::PeerNotice, peer_reason);
        return;
    }

    if (h->type != wire::MsgType::Transport) return;

    auto t = wire::Transport::decode(r);
    if (!t || t->conn_id != conn_id_) return;

    std::vector<uint8_t> plain(t->ciphertext.size());
    // The counter selects a key generation, decrypts under it, and only then
    // feeds the replay window and adopts a new generation -- nothing before the
    // AEAD verifies, or a forged counter could poison the window or discard a
    // key that real traffic still needs. Forged or corrupt: drop, say nothing.
    auto n = open_packet(t->counter, {}, t->ciphertext, plain, now);
    if (!n) return;

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
void Session::advance_send_keys(uint64_t counter) {
    const uint64_t g = generation(counter);
    while (send_gen_ < g) {
        send_cs_.rekey();   // Noise s11.3; one-way, so the old key is gone
        ++send_gen_;
    }
}

std::optional<size_t> Session::open_packet(uint64_t counter, std::span<const uint8_t> ad,
                                           std::span<const uint8_t> ciphertext,
                                           std::span<uint8_t> out, Instant now) {
    const uint64_t g = generation(counter);

    // --- select, without touching any state ------------------------------
    const crypto::CipherState* use = nullptr;
    crypto::CipherState        derived;   // only populated for a forward jump
    bool                       jumped = false;

    if (g == recv_gen_) {
        use = &recv_cs_;
    } else if (recv_gen_ > 0 && g + 1 == recv_gen_) {
        // A straggler from just before the last boundary.
        use = &recv_cs_prev_;
    } else if (g > recv_gen_ && (g - recv_gen_ <= cfg_.max_generations_ahead ||
                                 (g - recv_gen_ <= cfg_.max_generations_far && now >= next_far_jump_))) {
        // A long jump -- a burst of loss spanning generations -- is tried as
        // well, or the receiver would never catch up: every later packet is
        // further ahead still (#69). But sparingly, and the attempt is spent
        // whether or not the packet verifies, so forged counters cost a
        // bounded handful of derivations a second, not whatever they ask.
        if (g - recv_gen_ > cfg_.max_generations_ahead) next_far_jump_ = now + cfg_.far_jump_interval;
        derived = recv_cs_;
        for (uint64_t i = recv_gen_; i < g; ++i) derived.rekey();
        use    = &derived;
        jumped = true;
    } else {
        // Older than any key still held, further ahead than a real peer could
        // legitimately be, or a long jump before its next turn. The bound is
        // the point: `g` came from an unauthenticated header and decides how
        // much work we do.
        return std::nullopt;
    }

    // --- verify ----------------------------------------------------------
    auto n = use->decrypt_at(counter, ad, ciphertext, out);
    if (!n) return std::nullopt;
    if (!replay_.accept(counter)) return std::nullopt;

    // --- only now adopt --------------------------------------------------
    if (jumped) {
        // The generation immediately below g becomes the one we keep for
        // stragglers. Re-derived from the old current rather than kept from
        // the probe, which is at g itself.
        crypto::CipherState prev = recv_cs_;
        for (uint64_t i = recv_gen_; i + 1 < g; ++i) prev.rekey();
        recv_cs_prev_ = prev;
        recv_cs_      = derived;
        recv_gen_     = g;
    }
    return n;
}

std::optional<uint64_t> Session::send(std::span<const uint8_t> payload, Instant now) {
    if (state_ != SessionState::Established) return std::nullopt;

    advance_send_keys(send_counter_);
    std::vector<uint8_t> ct(payload.size() + crypto::kTagLen);
    send_cs_.encrypt_at(send_counter_, {}, payload, ct);

    std::vector<uint8_t> buf(wire::kMaxDatagram + 64);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Transport, wire::kVersion, 0, 0}.encode(w);
    wire::Transport t;
    t.conn_id    = conn_id_;
    t.counter    = send_counter_;
    t.ciphertext = ct;
    t.encode(w);
    if (!w.ok()) return std::nullopt;
    buf.resize(w.size());

    const uint64_t used = send_counter_++;
    out_.push_back({path_, std::move(buf)});
    next_keepalive_ = now + cfg_.keepalive;
    return used;
}

void Session::queue_keepalive(Instant now) {
    send({}, now);  // an empty payload; the peer treats it as a keepalive
}

namespace {
// Enough that losing every copy takes a burst failure rather than one drop.
// There is nothing to acknowledge a close, so retrying on a timer would mean
// keeping a session alive purely to announce that it is not -- the peer's idle
// timeout already covers the case where all of these are lost.
constexpr int kCloseCopies = 3;
}  // namespace

void Session::queue_close(uint16_t reason) {
    const uint8_t plain[2] = {static_cast<uint8_t>(reason >> 8),
                              static_cast<uint8_t>(reason & 0xFF)};

    // The type byte is the associated data. See wire::Close: this is what stops
    // a data packet being re-typed into a close by anyone on path.
    const uint8_t ad = static_cast<uint8_t>(wire::MsgType::Close);

    // Shares the transport counter space, so it shares the key schedule too.
    advance_send_keys(send_counter_);
    std::vector<uint8_t> ct(sizeof(plain) + crypto::kTagLen);
    send_cs_.encrypt_at(send_counter_, std::span<const uint8_t>(&ad, 1),
                        std::span<const uint8_t>(plain, sizeof(plain)), ct);

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Close, wire::kVersion, 0, 0}.encode(w);
    wire::Close m;
    m.conn_id    = conn_id_;
    m.counter    = send_counter_;
    m.ciphertext = ct;
    m.encode(w);
    if (!w.ok()) return;
    buf.resize(w.size());

    // Shares the transport counter space deliberately: the peer runs every
    // packet through one replay window, so a close drawn from a separate
    // sequence would either be rejected as a replay or punch a hole in it.
    ++send_counter_;
    out_.push_back({path_, std::move(buf)});
}

void Session::close_with_notice(uint16_t reason, Instant now) {
    if (state_ == SessionState::Closed) return;
    for (int i = 0; i < kCloseCopies; ++i) queue_close(reason);
    close(now);
}

void Session::close(Instant now) { close_with_cause(now, CloseCause::Local, 0); }

void Session::close_with_cause(Instant now, CloseCause cause, uint16_t peer_reason) {
    (void)now;
    if (state_ == SessionState::Closed) return;
    state_ = SessionState::Closed;
    send_cs_.clear();
    recv_cs_.clear();
    recv_cs_prev_.clear();   // the straggler key is key material too

    SessionEvent e;
    e.kind        = SessionEvent::Kind::Closed;
    e.cause       = cause;
    e.peer_reason = peer_reason;
    events_.push_back(std::move(e));
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------
void Session::on_timeout(Instant now) {
    if (state_ == SessionState::Closed) return;

    if (now - last_recv_ >= cfg_.idle_timeout) {
        close_with_cause(now, CloseCause::TimedOut, 0);
        return;
    }
    if (now >= next_keepalive_) queue_keepalive(now);
}

std::optional<Instant> Session::next_timeout() const {
    if (state_ == SessionState::Closed) return std::nullopt;
    const Instant idle = last_recv_ + cfg_.idle_timeout;
    return next_keepalive_ < idle ? next_keepalive_ : idle;
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

}  // namespace uconnect::session
