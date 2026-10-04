#pragma once
#include <string>
#include <string_view>

namespace uconnect::tools {
inline std::string csv_field(std::string_view value) {
    if (value.find_first_of(",\"\r\n") == std::string_view::npos) return std::string(value);
    std::string escaped = "\"";
    for (char ch : value) {
        if (ch == '"') escaped += '"';
        escaped += ch;
    }
    escaped += '"';
    return escaped;
}
}
