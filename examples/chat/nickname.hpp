#pragma once
#include <string>
#include <mutex>
#include <utility>

namespace chat {
class Nickname {
public:
    explicit Nickname(std::string value) : value_(std::move(value)) {}
    std::string get() const {
        std::lock_guard lock(mu_);
        return value_;
    }
    void set(std::string value) {
        std::lock_guard lock(mu_);
        value_ = std::move(value);
    }
private:
    mutable std::mutex mu_;
    std::string value_;
};
}  // namespace chat
