#include "rendezvous.hpp"

#include <algorithm>

namespace uconnect::server {
namespace ctl = wire::ctl;
using namespace std::chrono_literals;

namespace {

// A control connection's unsent replies beyond this mean it is not reading;
// it is closed rather than buffered for without bound.
constexpr size_t kMaxControlBacklog = 1024 * 1024;

constexpr size_t kReadChunk = 64 * 1024;

}  // namespace

Rendezvous::Rendezvous(RendezvousConfig cfg)
    : cfg_(std::move(cfg)), registry_(cfg_.registry), service_(registry_, cfg_.control) {}

Rendezvous::~Rendezvous() = default;

bool Rendezvous::open() {
    // TCP first: with port 0 the OS picks a number, and UDP then takes the
    // same one, so a client needs only one port to reach both.
    if (!listener_.open(cfg_.port) || !listener_.listen(256)) {
        err_ = "TCP listen on port " + std::to_string(cfg_.port) + " failed: " +
               listener_.last_error();
        return false;
    }
    port_ = listener_.local_port();
    if (!udp_.open(port_, cfg_.bind_host)) {
        err_ = "UDP bind on port " + std::to_string(port_) + " failed: " + udp_.last_error();
        listener_.close();
        return false;
    }
    return true;
}

void Rendezvous::poll_once(std::chrono::milliseconds timeout) {
    std::vector<io::PollItem> items;
    std::vector<ConnKey>      keys;
    items.reserve(conns_.size() + 2);

    io::PollItem li;
    li.fd        = listener_.native();
    li.want_read = true;
    items.push_back(li);
    io::PollItem ui;
    ui.fd        = udp_.native();
    ui.want_read = true;
    items.push_back(ui);

    for (auto& [key, c] : conns_) {
        if (c.dead) continue;
        io::PollItem it;
        it.fd = c.sock.native();
        // A splice stops reading while its partner still holds a full
        // buffer: that is how a slow receiver slows the sender down.
        it.want_read = true;
        if (c.mode == Mode::Splice) {
            auto p = conns_.find(c.partner);
            if (p != conns_.end() && p->second.out.size() >= cfg_.splice_buffer) it.want_read = false;
        }
        it.want_write = !c.out.empty();
        items.push_back(it);
        keys.push_back(key);
    }

    io::poll(items, timeout);
    const Instant now = std::chrono::steady_clock::now();

    if (items[0].readable) accept_all(now);
    if (items[1].readable) read_udp(now);
    for (size_t i = 0; i < keys.size(); ++i) {
        auto it = conns_.find(keys[i]);
        if (it == conns_.end() || it->second.dead) continue;
        const auto& p = items[i + 2];
        if (p.readable || p.failed) read_from(it->second, now);
    }
    // Everything queued this round, including replies just produced.
    for (auto& [key, c] : conns_) {
        (void)key;
        if (!c.dead && !c.out.empty()) flush(c);
    }

    reap(now);
    if (last_tick_ == Instant{} || now - last_tick_ >= 5s) {
        service_.tick(now);
        last_tick_ = now;
    }
}

void Rendezvous::accept_all(Instant now) {
    for (int i = 0; i < 256; ++i) {
        auto s = listener_.accept();
        if (!s) return;
        auto peer = s->remote();
        if (!peer) continue;
        auto& n = per_ip_[peer->ip.bytes];
        if (conns_.size() >= cfg_.max_connections || n >= cfg_.max_connections_per_ip) {
            if (n == 0) per_ip_.erase(peer->ip.bytes);
            continue;  // closed as it goes out of scope
        }
        ++n;
        Conn c;
        c.key     = next_key_++;
        c.sock    = std::move(*s);
        c.peer    = *peer;
        c.opened  = now;
        c.last_rx = now;
        conns_.emplace(c.key, std::move(c));
    }
}

void Rendezvous::read_from(Conn& c, Instant now) {
    if (c.mode == Mode::Splice) {
        splice_read(c, now);
        return;
    }
    std::vector<uint8_t> buf(kReadChunk);
    for (int round = 0; round < 16 && !c.dead; ++round) {
        auto got = c.sock.recv(buf);
        if (!got) {
            kill(c);
            return;
        }
        if (*got == 0) break;
        c.last_rx = now;
        if (!c.reader.feed(std::span(buf).first(*got))) {
            kill(c);  // a frame over the limit: framing cannot be recovered
            return;
        }
        // A relay leg sends one frame and then waits; anything after that
        // frame stays in the reader for the splice to carry.
        while (!c.dead && c.mode != Mode::RelayWaiting && c.mode != Mode::Splice) {
            auto msg = c.reader.next();
            if (!msg) break;
            if (drop_filter && drop_filter(*msg)) continue;
            on_frame(c, *msg, now);
        }
        if (c.reader.broken()) kill(c);
        if (c.mode == Mode::RelayWaiting || c.mode == Mode::Splice) return;
    }
}

void Rendezvous::on_frame(Conn& c, std::span<const uint8_t> msg, Instant now) {
    if (c.mode == Mode::New) {
        if (wire::peek_type(msg) == wire::MsgType::RelayJoin) {
            on_relay_join(c, msg, now);
            return;
        }
        c.mode = Mode::Control;
        service_.on_open(c.key, c.peer, now);
    }
    if (c.mode != Mode::Control) return;

    auto res = service_.on_message(c.key, msg, now);
    for (const auto& f : res.out) deliver(f);
    if (res.close) kill(c);
}

void Rendezvous::on_relay_join(Conn& c, std::span<const uint8_t> msg, Instant now) {
    wire::Reader r{msg};
    auto         h = wire::Header::decode(r, ctl::kVersion);
    auto         j = h ? ctl::RelayJoin::decode(r) : std::nullopt;
    auto         side = j ? registry_.relay_side(j->relay_id, j->token) : std::nullopt;
    if (!side) {
        kill(c);  // wrong id or token: knowing the id alone admits nobody
        return;
    }

    c.relay_id   = j->relay_id;
    c.relay_side = *side;

    // A leg that rejoins replaces its earlier attempt.
    if (auto old = waiting_[*side].find(c.relay_id); old != waiting_[*side].end()) {
        if (auto oc = conns_.find(old->second); oc != conns_.end()) kill(oc->second);
        waiting_[*side].erase(old);
    }

    auto other = waiting_[1 - *side].find(c.relay_id);
    if (other == waiting_[1 - *side].end()) {
        c.mode = Mode::RelayWaiting;
        waiting_[*side][c.relay_id] = c.key;
        return;
    }

    auto pit = conns_.find(other->second);
    waiting_[1 - *side].erase(other);
    if (pit == conns_.end() || pit->second.dead) {
        c.mode = Mode::RelayWaiting;
        waiting_[*side][c.relay_id] = c.key;
        return;
    }
    Conn& p = pit->second;

    c.mode    = Mode::Splice;
    p.mode    = Mode::Splice;
    c.partner = p.key;
    p.partner = c.key;
    for (Conn* x : {&c, &p}) {
        auto ok = ctl::frame(ctl::empty_message(wire::MsgType::RelayJoinOk, 0));
        x->out.insert(x->out.end(), ok.begin(), ok.end());
    }
    // Anything either leg sent early belongs to the other now.
    for (auto [from, to] : {std::pair{&c, &p}, std::pair{&p, &c}}) {
        auto rest = from->reader.take_rest();
        if (rest.empty()) continue;
        if (!registry_.relay_charge(c.relay_id, rest.size(), now)) {
            kill(c);
            kill(p);
            return;
        }
        to->out.insert(to->out.end(), rest.begin(), rest.end());
    }
}

void Rendezvous::splice_read(Conn& c, Instant now) {
    auto pit = conns_.find(c.partner);
    if (pit == conns_.end() || pit->second.dead) {
        kill(c);
        return;
    }
    Conn&  p    = pit->second;
    size_t room = cfg_.splice_buffer > p.out.size() ? cfg_.splice_buffer - p.out.size() : 0;
    if (room == 0) return;

    std::vector<uint8_t> buf(std::min(room, kReadChunk));
    auto                 got = c.sock.recv(buf);
    if (!got) {
        kill(c);
        return;
    }
    if (*got == 0) return;
    c.last_rx = now;
    if (!registry_.relay_charge(c.relay_id, *got, now)) {
        // The binding's budget is spent: end both legs.
        kill(c);
        kill(p);
        return;
    }
    p.out.insert(p.out.end(), buf.begin(), buf.begin() + static_cast<ptrdiff_t>(*got));
}

void Rendezvous::flush(Conn& c) {
    while (!c.out.empty()) {
        auto n = c.sock.send(c.out);
        if (!n) {
            kill(c);
            return;
        }
        if (*n == 0) return;
        c.out.erase(c.out.begin(), c.out.begin() + static_cast<ptrdiff_t>(*n));
    }
}

void Rendezvous::deliver(const Framed& f) {
    auto it = conns_.find(f.to);
    if (it == conns_.end() || it->second.dead) return;
    auto& c = it->second;
    if (c.out.size() + f.bytes.size() > kMaxControlBacklog) {
        kill(c);
        return;
    }
    c.out.insert(c.out.end(), f.bytes.begin(), f.bytes.end());
}

void Rendezvous::kill(Conn& c) { c.dead = true; }

void Rendezvous::reap(Instant now) {
    for (auto& [key, c] : conns_) {
        (void)key;
        if (c.dead) continue;
        if ((c.mode == Mode::New && now - c.opened > cfg_.first_frame_timeout) ||
            (c.mode == Mode::Control && now - c.last_rx > cfg_.idle_timeout) ||
            (c.mode == Mode::RelayWaiting && now - c.opened > cfg_.relay_join_timeout)) {
            kill(c);
        }
    }

    // A splice ends when either leg does. The survivor gets what is already
    // buffered for it, then closes.
    for (auto& [key, c] : conns_) {
        (void)key;
        if (!c.dead || c.mode != Mode::Splice) continue;
        auto p = conns_.find(c.partner);
        if (p != conns_.end() && !p->second.dead && p->second.out.empty()) kill(p->second);
    }

    for (auto it = conns_.begin(); it != conns_.end();) {
        Conn& c = it->second;
        const bool splice_orphan =
            c.mode == Mode::Splice && !c.dead &&
            (conns_.find(c.partner) == conns_.end() || conns_.at(c.partner).dead) &&
            c.out.empty();
        if (!c.dead && !splice_orphan) {
            ++it;
            continue;
        }
        if (c.mode == Mode::Control) service_.on_close(c.key);
        if (c.mode == Mode::RelayWaiting && c.relay_side >= 0) {
            auto w = waiting_[c.relay_side].find(c.relay_id);
            if (w != waiting_[c.relay_side].end() && w->second == c.key) waiting_[c.relay_side].erase(w);
        }
        if (auto n = per_ip_.find(c.peer.ip.bytes); n != per_ip_.end()) {
            if (n->second <= 1) per_ip_.erase(n);
            else --n->second;
        }
        c.sock.close();
        it = conns_.erase(it);
    }
}

void Rendezvous::read_udp(Instant now) {
    std::vector<uint8_t> buf(2048);
    for (int i = 0; i < 256; ++i) {
        auto got = udp_.recv_from(buf);
        if (!got) return;
        auto dgram = std::span<const uint8_t>(buf).first(got->len);
        if (drop_filter && drop_filter(dgram)) continue;
        for (auto& o : service_.on_udp(got->from, dgram, now)) {
            if (!o.data.empty()) udp_.send_to(o.to, o.data);
        }
    }
}

}  // namespace uconnect::server
