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

// How long a worker waits in poll before looking for newly handed pairs.
constexpr auto kWorkerPoll = 5ms;

}  // namespace

// A worker thread and the relay pairs it carries. `conns` is the worker's
// alone; pairs arrive through `inbox`, which the loop fills.
struct Rendezvous::Worker {
    std::thread         thread;
    std::mutex          inbox_mu;
    std::vector<Conn>   inbox;
    ConnMap             conns;
    std::atomic<size_t> count{0};  // conns.size(), readable from other threads
};

Rendezvous::Rendezvous(RendezvousConfig cfg)
    : cfg_(std::move(cfg)), registry_(cfg_.registry), service_(registry_, cfg_.control) {}

Rendezvous::~Rendezvous() {
    stop_ = true;
    for (auto& w : workers_) {
        if (w->thread.joinable()) w->thread.join();
    }
}

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
    for (size_t i = 1; i < cfg_.threads; ++i) {
        auto  w    = std::make_unique<Worker>();
        auto* self = w.get();
        w->thread  = std::thread([this, self] { worker_loop(*self); });
        workers_.push_back(std::move(w));
    }
    return true;
}

RegistryStats Rendezvous::stats(Instant now) {
    std::lock_guard<std::mutex> lk(service_mu_);
    return registry_.stats(now);
}

size_t Rendezvous::control_connections() {
    std::lock_guard<std::mutex> lk(service_mu_);
    return service_.connections();
}

size_t Rendezvous::open_connections() const {
    size_t n = conns_.size();
    for (const auto& w : workers_) n += w->count.load();
    return n;
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

    hand_off();
    reap(now);
    if (last_tick_ == Instant{} || now - last_tick_ >= 5s) {
        std::lock_guard<std::mutex> lk(service_mu_);
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
        {
            std::lock_guard<std::mutex> lk(ip_mu_);
            auto& n = per_ip_[peer->ip.bytes];
            if (open_connections() >= cfg_.max_connections || n >= cfg_.max_connections_per_ip) {
                if (n == 0) per_ip_.erase(peer->ip.bytes);
                continue;  // closed as it goes out of scope
            }
            ++n;
        }
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
        splice_read(c, conns_, now);
        return;
    }
    if (c.mode == Mode::RelayWaiting) {
        // Read one byte beyond the remaining allowance to detect overflow,
        // without ever allocating or retaining an unbounded early stream.
        const size_t room = cfg_.splice_buffer - c.relay_early.size();
        std::vector<uint8_t> early(std::min(room, kReadChunk - 1) + 1);
        auto got = c.sock.recv(early);
        if (!got || *got > room) {
            kill(c);
            return;
        }
        c.relay_early.insert(c.relay_early.end(), early.begin(),
                             early.begin() + static_cast<ptrdiff_t>(*got));
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
        if (c.mode == Mode::RelayWaiting || c.mode == Mode::Splice) return;
        if (c.reader.broken()) kill(c);
    }
}

void Rendezvous::on_frame(Conn& c, std::span<const uint8_t> msg, Instant now) {
    if (c.mode == Mode::New) {
        if (wire::peek_type(msg) == wire::MsgType::RelayJoin) {
            on_relay_join(c, msg, now);
            return;
        }
        c.mode = Mode::Control;
        std::lock_guard<std::mutex> lk(service_mu_);
        service_.on_open(c.key, c.peer, now);
    }
    if (c.mode != Mode::Control) return;

    ControlService::Result res;
    {
        std::lock_guard<std::mutex> lk(service_mu_);
        res = service_.on_message(c.key, msg, now);
    }
    for (const auto& f : res.out) deliver(f);
    if (res.close) kill(c);
}

void Rendezvous::on_relay_join(Conn& c, std::span<const uint8_t> msg, Instant now) {
    wire::Reader       r{msg};
    auto               h    = wire::Header::decode(r, ctl::kVersion);
    auto               j    = h ? ctl::RelayJoin::decode(r) : std::nullopt;
    std::optional<int> side;
    if (j) {
        std::lock_guard<std::mutex> lk(service_mu_);
        side = registry_.relay_side(j->relay_id, j->token);
    }
    if (!side) {
        kill(c);  // wrong id or token: knowing the id alone admits nobody
        return;
    }

    // RelayJoin is the final framed message. Coalesced bytes are raw relay
    // input, and must obey the same cap as bytes received while waiting.
    c.relay_early = c.reader.take_rest();
    c.reader = ctl::FrameReader{};
    if (c.relay_early.size() > cfg_.splice_buffer) {
        kill(c);
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
        auto rest = std::move(from->relay_early);
        if (rest.empty()) continue;
        if (!charge(c.relay_id, rest.size(), now)) {
            kill(c);
            kill(p);
            return;
        }
        to->out.insert(to->out.end(), rest.begin(), rest.end());
    }
    // Moved at the end of this round, not now: callers up the stack still
    // hold `c`.
    if (!workers_.empty()) spliced_.emplace_back(c.key, p.key);
}

void Rendezvous::splice_read(Conn& c, ConnMap& conns, Instant now) {
    auto pit = conns.find(c.partner);
    if (pit == conns.end() || pit->second.dead) {
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
    if (!charge(c.relay_id, *got, now)) {
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

bool Rendezvous::charge(wire::RelayId id, size_t bytes, Instant now) {
    std::lock_guard<std::mutex> lk(service_mu_);
    return registry_.relay_charge(id, bytes, now);
}

void Rendezvous::release(const Conn& c) {
    std::lock_guard<std::mutex> lk(ip_mu_);
    if (auto n = per_ip_.find(c.peer.ip.bytes); n != per_ip_.end()) {
        if (n->second <= 1) per_ip_.erase(n);
        else --n->second;
    }
}

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
        if (c.mode == Mode::Control) {
            std::lock_guard<std::mutex> lk(service_mu_);
            service_.on_close(c.key);
        }
        if (c.mode == Mode::RelayWaiting && c.relay_side >= 0) {
            auto w = waiting_[c.relay_side].find(c.relay_id);
            if (w != waiting_[c.relay_side].end() && w->second == c.key) waiting_[c.relay_side].erase(w);
        }
        release(c);
        c.sock.close();
        it = conns_.erase(it);
    }
}

void Rendezvous::read_udp(Instant now) {
    std::vector<uint8_t> buf(kMaxUdpDatagram);
    for (int i = 0; i < 256; ++i) {
        auto got = udp_.recv_from(buf);
        if (!got) return;
        auto dgram = std::span<const uint8_t>(buf).first(got->len);
        if (drop_filter && drop_filter(dgram)) continue;
        std::vector<UdpOut> out;
        {
            std::lock_guard<std::mutex> lk(service_mu_);
            out = service_.on_udp(got->from, dgram, now);
        }
        for (auto& o : out) {
            if (!o.data.empty()) udp_.send_to(o.to, o.data);
        }
    }
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------
void Rendezvous::hand_off() {
    for (auto [a, b] : spliced_) {
        auto ia = conns_.find(a);
        auto ib = conns_.find(b);
        // A leg that died already is the loop's to reap, with its partner.
        if (ia == conns_.end() || ib == conns_.end() || ia->second.dead || ib->second.dead) continue;
        Worker& w = *workers_[next_worker_++ % workers_.size()];
        {
            std::lock_guard<std::mutex> lk(w.inbox_mu);
            w.inbox.push_back(std::move(ia->second));
            w.inbox.push_back(std::move(ib->second));
        }
        conns_.erase(ia);
        conns_.erase(ib);
    }
    spliced_.clear();
}

void Rendezvous::worker_loop(Worker& w) {
    std::vector<io::PollItem> items;
    std::vector<ConnKey>      keys;
    while (!stop_) {
        {
            std::lock_guard<std::mutex> lk(w.inbox_mu);
            for (auto& c : w.inbox) {
                const ConnKey k = c.key;
                w.conns.emplace(k, std::move(c));
            }
            w.inbox.clear();
        }

        items.clear();
        keys.clear();
        io::PollItem ui;
        ui.fd        = udp_.native();
        ui.want_read = true;
        items.push_back(ui);
        for (auto& [key, c] : w.conns) {
            if (c.dead) continue;
            io::PollItem it;
            it.fd        = c.sock.native();
            auto p       = w.conns.find(c.partner);
            it.want_read = !(p != w.conns.end() && p->second.out.size() >= cfg_.splice_buffer);
            it.want_write = !c.out.empty();
            items.push_back(it);
            keys.push_back(key);
        }

        io::poll(items, kWorkerPoll);
        const Instant now = std::chrono::steady_clock::now();

        if (items[0].readable) read_udp(now);
        for (size_t i = 0; i < keys.size(); ++i) {
            auto it = w.conns.find(keys[i]);
            if (it == w.conns.end() || it->second.dead) continue;
            if (items[i + 1].readable || items[i + 1].failed) splice_read(it->second, w.conns, now);
        }
        for (auto& [key, c] : w.conns) {
            (void)key;
            if (!c.dead && !c.out.empty()) flush(c);
        }

        // As reap() does for splices: a dead leg's survivor drains, then goes.
        for (auto& [key, c] : w.conns) {
            (void)key;
            if (!c.dead) continue;
            auto p = w.conns.find(c.partner);
            if (p != w.conns.end() && !p->second.dead && p->second.out.empty()) kill(p->second);
        }
        for (auto it = w.conns.begin(); it != w.conns.end();) {
            Conn&      c = it->second;
            auto       p = w.conns.find(c.partner);
            const bool orphan =
                !c.dead && (p == w.conns.end() || p->second.dead) && c.out.empty();
            if (!c.dead && !orphan) {
                ++it;
                continue;
            }
            release(c);
            c.sock.close();
            it = w.conns.erase(it);
        }
        w.count = w.conns.size();
    }
}

}  // namespace uconnect::server
