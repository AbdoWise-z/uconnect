// Targeted complexity regression for #24; run separately from ordinary CTest.
#include <chrono>
#include <cstdio>
#include "registry.hpp"
using namespace uconnect;
using namespace uconnect::server;
using namespace std::chrono_literals;

double measure(unsigned members) {
    Registry registry{{}, crypto::SymKey{}, 1};
    const auto now = Instant{} + 100s;
    wire::ctl::Register request;
    for (unsigned i = 0; i < members; ++i) {
        auto result = registry.register_entry(request,
            {IpAddr::v4(10, 1, static_cast<uint8_t>(i >> 8), static_cast<uint8_t>(i)), 4000}, i + 1, now);
        if (result.code != ErrorCode::None) return -1;
    }
    // Warm caches/expire work once; unchanged swarms must not be rescanned.
    registry.list_topics(0, 100, now);
    const auto start = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < 2000; ++i) {
        auto list = registry.list_topics(0, 100, now + 1s);
        if (list.topics.size() != 1 || list.topics[0].fresh_peers != members) return -1;
    }
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}
int main() {
    const double small = measure(100), large = measure(10000);
    std::printf("2000 listings: 100 members %.2f ms; 10000 members %.2f ms\n", small, large);
    return small >= 0 && large >= 0 && large <= small * 10 + 50 ? 0 : 1;
}
