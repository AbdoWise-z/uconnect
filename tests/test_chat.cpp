// The chat example's terminal sanitizer (#36). It sits between a peer and the
// user's terminal, so it must remove every control code point -- and nothing
// else, or it mangles the very text it exists to show.

#include <string>
#include <atomic>
#include <thread>
#include "../examples/chat/nickname.hpp"
#include "../tools/csv.hpp"

#include "../examples/chat/sanitize.hpp"
#include "testing.hpp"

using chat::sanitize_for_terminal;

TEST(issue76_csv_notes_preserve_field_boundaries) {
    using uconnect::tools::csv_field;
    CHECK(csv_field("plain") == "plain");
    CHECK(csv_field("error, detail") == "\"error, detail\"");
    CHECK(csv_field("say \"hello\"") == "\"say \"\"hello\"\"\"");
    CHECK(csv_field("line\r\nnext") == "\"line\r\nnext\"");
}

TEST(issue66_nickname_snapshots_are_consistent_during_changes) {
    const std::string a(32, 'a'), b(32, 'b');
    chat::Nickname nick{a};
    std::atomic<bool> start{false}, consistent{true};
    std::thread reader([&] {
        while (!start.load()) {}
        for (int i = 0; i < 100000; ++i) {
            auto snapshot = nick.get();
            if (snapshot != a && snapshot != b) consistent = false;
        }
    });
    start = true;
    for (int i = 0; i < 100000; ++i) nick.set(i % 2 ? a : b);
    reader.join();
    CHECK(consistent.load());
}

TEST(chat_sanitizer_strips_c0_controls_and_del_but_keeps_tab) {
    CHECK(sanitize_for_terminal("a\x1b[2Jb") == "a[2Jb");   // ESC dropped
    CHECK(sanitize_for_terminal("a\x7f" "b") == "ab");         // DEL dropped
    CHECK(sanitize_for_terminal("a\tb\n") == "a\tb");         // tab kept, newline not
}

TEST(chat_sanitizer_strips_c1_controls_in_utf8_and_raw) {
    // U+009B is CSI: a single-character escape introducer in C1.
    CHECK(sanitize_for_terminal("a\xc2\x9b" "2Jb") == "a2Jb");
    CHECK(sanitize_for_terminal("a\x9b" "2Jb") == "a2Jb");    // raw, not valid UTF-8
}

TEST(chat_sanitizer_keeps_ordinary_utf8_text_intact) {
    // #36: bytes 0x80-0x9F are also UTF-8 continuation bytes, so stripping
    // them outright tore apart most non-ASCII text -- every one of these.
    const std::string samples[] = {
        "caf\xc3\xa9",                   // café         (C3 A9)
        "\xc4\x80",                      // Ā  U+0100    (C4 80)
        "\xd0\x9f\xd1\x80\xd0\xb8",      // При          (D0 9F ...)
        "\xe2\x82\xac",                  // €  U+20AC    (E2 82 AC)
        "\xe4\xb8\x96\xe7\x95\x8c",      // 世界
        "\xf0\x9f\x98\x80",              // 😀 U+1F600   (F0 9F 98 80)
    };
    for (const auto& s : samples) CHECK(sanitize_for_terminal(s) == s);
}

TEST(chat_sanitizer_drops_malformed_utf8) {
    // Truncated and overlong sequences are not text; an overlong encoding in
    // particular can smuggle a control character past a byte-level filter.
    CHECK(sanitize_for_terminal("a\xe2\x82") == "a");          // truncated
    CHECK(sanitize_for_terminal("a\xc0\x9b" "b") == "ab");     // overlong ESC-ish
    CHECK(sanitize_for_terminal("a\xed\xa0\x80" "b") == "ab"); // UTF-16 surrogate
}
