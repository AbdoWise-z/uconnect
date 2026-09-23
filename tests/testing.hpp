#pragma once
// Minimal test harness. Deliberately dependency-free: the whole point of the
// sans-IO design is that the protocol layers can be tested with nothing but a
// compiler, and dragging in a framework would undercut that.

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace testing {

struct Case {
    const char*           name;
    std::function<void()> fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

struct Register {
    Register(const char* name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline int& failures() {
    static int n = 0;
    return n;
}

inline void fail(const char* file, int line, const std::string& msg) {
    std::printf("    FAIL %s:%d\n         %s\n", file, line, msg.c_str());
    ++failures();
}

inline int run_all() {
    int failed_cases = 0;
    for (auto& c : registry()) {
        int before = failures();
        std::printf("  %s\n", c.name);
        c.fn();
        if (failures() != before) ++failed_cases;
    }
    std::printf("\n%d case(s), %d failed, %d assertion failure(s)\n",
                static_cast<int>(registry().size()), failed_cases, failures());
    return failures() == 0 ? 0 : 1;
}

}  // namespace testing

#define TEST(name)                                                            \
    static void name();                                                       \
    static ::testing::Register reg_##name(#name, name);                       \
    static void name()

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) ::testing::fail(__FILE__, __LINE__, "CHECK(" #cond ")"); \
    } while (0)

#define CHECK_EQ(a, b)                                                        \
    do {                                                                      \
        auto _a = (a);                                                        \
        auto _b = (b);                                                        \
        if (!(_a == _b))                                                      \
            ::testing::fail(__FILE__, __LINE__,                               \
                            "CHECK_EQ(" #a ", " #b ") -> " +                  \
                                std::to_string(static_cast<long long>(_a)) +  \
                                " vs " +                                      \
                                std::to_string(static_cast<long long>(_b)));  \
    } while (0)

#define REQUIRE(cond)                                                         \
    do {                                                                      \
        if (!(cond)) {                                                        \
            ::testing::fail(__FILE__, __LINE__, "REQUIRE(" #cond ")");        \
            return;                                                           \
        }                                                                     \
    } while (0)
