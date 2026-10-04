// A fresh process matters: no other socket test may initialize Winsock first.
#include <atomic>
#include <barrier>
#include <cstdio>
#include <thread>
#include <vector>
#include "socket.hpp"

#if defined(_WIN32)
#include <winsock2.h>
extern "C" int (WSAAPI * __real___imp_WSAStartup)(WORD, LPWSADATA);
std::atomic<unsigned> calls{0};
extern "C" int WSAAPI startup(WORD version, LPWSADATA data) {
    ++calls;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return __real___imp_WSAStartup(version, data);
}
// MinGW --wrap replaces the DLL import pointer, not the Windows API itself.
extern "C" {
    decltype(&startup) __wrap___imp_WSAStartup = &startup;
}
#endif

int main() {
    std::barrier start{16};
    std::atomic<bool> ok{true};
    std::vector<std::thread> threads;
    for (int i = 0; i < 16; ++i) threads.emplace_back([&] {
        start.arrive_and_wait();
        if (!uconnect::io::init_networking()) ok = false;
    });
    for (auto& thread : threads) thread.join();
#if defined(_WIN32)
    if (calls != 1) {
        std::fprintf(stderr, "WSAStartup called %u times (expected 1)\n", calls.load());
        return 1;
    }
#endif
    return ok ? 0 : 1;
}
