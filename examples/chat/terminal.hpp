#pragma once
// A small line editor for a chat TUI.
//
// The problem it solves: messages arrive on the network thread at arbitrary
// moments while the user is mid-keystroke. With ordinary line-buffered input
// the incoming text lands in the middle of whatever is being typed and the
// terminal becomes unreadable.
//
// So input is read one key at a time and we keep the edit buffer ourselves.
// print() then erases the input line, writes the message, and redraws the
// prompt with the partially typed text intact.

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <conio.h>
#include <io.h>
#else
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace chatui {

// ANSI colours. Enabled only if the terminal supports them.
struct Palette {
    const char* reset = "\x1b[0m";
    const char* dim   = "\x1b[90m";
    const char* bold  = "\x1b[1m";
    const char* red   = "\x1b[31m";
    const char* green = "\x1b[32m";
    const char* yellow= "\x1b[33m";
    const char* blue  = "\x1b[34m";
    const char* cyan  = "\x1b[36m";
};

class Terminal {
public:
    Terminal() {
#if defined(_WIN32)
        interactive_ = _isatty(_fileno(stdin)) != 0;
        hout_ = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (GetConsoleMode(hout_, &mode)) {
            saved_out_mode_ = mode;
            // Without this, escape sequences print as literal garbage on
            // consoles that have not opted in to VT processing.
            if (SetConsoleMode(hout_, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
                ansi_ = true;
            }
        }
        // UTF-8 output so non-ASCII nicknames and messages survive.
        saved_cp_ = GetConsoleOutputCP();
        SetConsoleOutputCP(CP_UTF8);
#else
        interactive_ = isatty(STDIN_FILENO) != 0;
        ansi_        = isatty(STDOUT_FILENO) != 0;
        if (interactive_) {
            tcgetattr(STDIN_FILENO, &saved_);
            termios raw = saved_;
            raw.c_lflag &= ~(unsigned)(ICANON | ECHO);
            raw.c_cc[VMIN]  = 0;
            raw.c_cc[VTIME] = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
            raw_ = true;
        }
#endif
    }

    ~Terminal() { restore(); }

    Terminal(const Terminal&)            = delete;
    Terminal& operator=(const Terminal&) = delete;

    void restore() {
        if (restored_) return;
        restored_ = true;
#if defined(_WIN32)
        if (saved_out_mode_) SetConsoleMode(hout_, saved_out_mode_);
        if (saved_cp_) SetConsoleOutputCP(saved_cp_);
#else
        if (raw_) tcsetattr(STDIN_FILENO, TCSANOW, &saved_);
#endif
    }

    const Palette& colors() const { return ansi_ ? pal_ : plain_; }
    bool           has_ansi() const { return ansi_; }

    void set_prompt(std::string p) {
        std::lock_guard<std::mutex> lk(mu_);
        prompt_ = std::move(p);
        redraw_locked();
    }

    // Thread-safe. Erases the input line, writes `text` plus a newline, then
    // puts the prompt and any partially typed input back.
    void print(std::string_view text) {
        std::lock_guard<std::mutex> lk(mu_);
        clear_line_locked();
        std::fwrite(text.data(), 1, text.size(), stdout);
        std::fputc('\n', stdout);
        redraw_locked();
    }

    void printf(const char* fmt, ...) {
        char    buf[4096];
        va_list ap;
        va_start(ap, fmt);
        int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (n < 0) return;
        print(std::string_view(buf, static_cast<size_t>(n > (int)sizeof(buf) - 1
                                                            ? sizeof(buf) - 1
                                                            : n)));
    }

    bool interactive() const { return interactive_; }

    // Blocks until a full line is available, or returns nullopt on EOF / stop.
    //
    // When stdin is not a console -- a pipe, a file, a test harness -- the
    // key-at-a-time path cannot work (_kbhit reports nothing for a pipe), so
    // fall back to ordinary line reading. That keeps the program scriptable,
    // which is also the only way to test it automatically.
    std::optional<std::string> poll_line(const std::atomic<bool>& stop) {
        if (!interactive_) {
            std::string line;
            if (!std::getline(std::cin, line)) return std::nullopt;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return line;
        }
        while (!stop) {
            auto key = poll_key();
            if (!key) {
                std::this_thread::sleep_for(std::chrono::milliseconds(15));
                continue;
            }
            int ch = *key;

            std::lock_guard<std::mutex> lk(mu_);
            switch (ch) {
                case 3:  // Ctrl-C
                    eof_ = true;
                    return std::string("/quit");
                case 4:  // Ctrl-D
                    if (buf_.empty()) {
                        eof_ = true;
                        return std::string("/quit");
                    }
                    break;
                case '\r':
                case '\n': {
                    std::string line = buf_;
                    buf_.clear();
                    clear_line_locked();
                    redraw_locked();
                    if (!line.empty()) {
                        history_.push_front(line);
                        if (history_.size() > 100) history_.pop_back();
                    }
                    hist_pos_ = -1;
                    return line;
                }
                case 8:    // Backspace
                case 127:  // DEL
                    if (!buf_.empty()) {
                        // Trim a whole UTF-8 sequence, not one byte, or a
                        // multi-byte character leaves a broken tail behind.
                        size_t n = 1;
                        while (n < buf_.size() &&
                               (static_cast<unsigned char>(buf_[buf_.size() - n]) & 0xC0) ==
                                   0x80) {
                            ++n;
                        }
                        buf_.erase(buf_.size() - n);
                        redraw_locked();
                    }
                    break;
                case 21:  // Ctrl-U: clear the line
                    buf_.clear();
                    redraw_locked();
                    break;
                case kUp:
                    if (!history_.empty() &&
                        hist_pos_ + 1 < static_cast<int>(history_.size())) {
                        ++hist_pos_;
                        buf_ = history_[static_cast<size_t>(hist_pos_)];
                        redraw_locked();
                    }
                    break;
                case kDown:
                    if (hist_pos_ > 0) {
                        --hist_pos_;
                        buf_ = history_[static_cast<size_t>(hist_pos_)];
                    } else {
                        hist_pos_ = -1;
                        buf_.clear();
                    }
                    redraw_locked();
                    break;
                default:
                    if (ch >= 32 || static_cast<unsigned char>(ch) >= 0x80) {
                        buf_.push_back(static_cast<char>(ch));
                        redraw_locked();
                    }
                    break;
            }
        }
        return std::nullopt;
    }

    bool eof() const { return eof_; }

private:
    static constexpr int kUp   = 1000;
    static constexpr int kDown = 1001;

    std::optional<int> poll_key() {
#if defined(_WIN32)
        if (!_kbhit()) return std::nullopt;
        int ch = _getch();
        if (ch == 0 || ch == 224) {  // extended key
            int ext = _getch();
            if (ext == 72) return kUp;
            if (ext == 80) return kDown;
            return std::nullopt;
        }
        return ch;
#else
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(STDIN_FILENO, &rd);
        timeval tv{0, 0};
        if (select(STDIN_FILENO + 1, &rd, nullptr, nullptr, &tv) <= 0) return std::nullopt;
        unsigned char c;
        if (read(STDIN_FILENO, &c, 1) != 1) return std::nullopt;
        if (c == 27) {  // escape sequence
            unsigned char seq[2];
            if (read(STDIN_FILENO, &seq[0], 1) != 1) return 27;
            if (read(STDIN_FILENO, &seq[1], 1) != 1) return 27;
            if (seq[0] == '[' && seq[1] == 'A') return kUp;
            if (seq[0] == '[' && seq[1] == 'B') return kDown;
            return std::nullopt;
        }
        return static_cast<int>(c);
#endif
    }

    void clear_line_locked() {
        // Nothing to erase when output is a pipe or a file: there is no prompt
        // on screen, and emitting escape codes would corrupt the capture.
        if (!interactive_) return;
        if (ansi_) {
            std::fputs("\r\x1b[2K", stdout);
        } else {
            // No ANSI: overwrite with spaces, which is ugly but correct.
            std::fputc('\r', stdout);
            for (size_t i = 0; i < prompt_.size() + buf_.size() + 1; ++i) std::fputc(' ', stdout);
            std::fputc('\r', stdout);
        }
    }

    void redraw_locked() {
        if (!interactive_) return;
        clear_line_locked();
        if (ansi_) std::fputs(pal_.dim, stdout);
        std::fwrite(prompt_.data(), 1, prompt_.size(), stdout);
        if (ansi_) std::fputs(pal_.reset, stdout);
        std::fwrite(buf_.data(), 1, buf_.size(), stdout);
        std::fflush(stdout);
    }

    std::mutex              mu_;
    std::string             prompt_ = "> ";
    std::string             buf_;
    std::deque<std::string> history_;
    int                     hist_pos_ = -1;
    bool                    interactive_ = false;
    bool                    ansi_     = false;
    bool                    restored_ = false;
    std::atomic<bool>       eof_{false};
    Palette                 pal_;
    Palette                 plain_{"", "", "", "", "", "", "", ""};

#if defined(_WIN32)
    HANDLE hout_           = nullptr;
    DWORD  saved_out_mode_ = 0;
    UINT   saved_cp_       = 0;
#else
    termios saved_{};
    bool    raw_ = false;
#endif
};

}  // namespace chatui
