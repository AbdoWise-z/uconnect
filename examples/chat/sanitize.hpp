#pragma once
// Making peer-supplied text safe to print to a terminal.
//
// A peer is authenticated as a topic member, not trusted to be well-behaved,
// and a terminal will act on control characters it is sent: escape sequences
// can move the cursor, rewrite earlier lines, or change the window title.

#include <cstdint>
#include <string>
#include <string_view>

namespace chat {

// Keeps well-formed UTF-8 text and nothing else: drops C0 controls (tab
// excepted), DEL, the C1 controls U+0080-U+009F -- U+009B is a one-character
// CSI -- and any malformed sequence.
//
// It decodes rather than filtering bytes. Bytes 0x80-0x9F are also UTF-8
// continuation bytes, so stripping them outright tore apart most non-ASCII
// text (every emoji, Cyrillic, U+0100 and up); and an overlong encoding can
// spell a control character in bytes no byte filter would catch.
inline std::string sanitize_for_terminal(std::string_view in) {
    std::string out;
    out.reserve(in.size());

    size_t i = 0;
    while (i < in.size()) {
        const auto lead = static_cast<unsigned char>(in[i]);

        size_t   len = 0;
        uint32_t cp  = 0;
        uint32_t min = 0;  // smallest code point this length may encode
        if (lead < 0x80)                { len = 1; cp = lead;        min = 0; }
        else if ((lead & 0xE0) == 0xC0) { len = 2; cp = lead & 0x1F; min = 0x80; }
        else if ((lead & 0xF0) == 0xE0) { len = 3; cp = lead & 0x0F; min = 0x800; }
        else if ((lead & 0xF8) == 0xF0) { len = 4; cp = lead & 0x07; min = 0x10000; }
        else { ++i; continue; }  // a stray continuation byte, or 0xF8 and up

        if (i + len > in.size()) break;  // truncated at the end

        bool ok = true;
        for (size_t k = 1; k < len; ++k) {
            const auto c = static_cast<unsigned char>(in[i + k]);
            if ((c & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (c & 0x3F);
        }
        // Malformed: resynchronise on the next byte rather than swallow what
        // may be the start of a valid character.
        if (!ok || cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            ++i;
            continue;
        }

        const bool control = (cp < 0x20 && cp != '\t') || (cp >= 0x7F && cp <= 0x9F);
        if (!control) out.append(in.substr(i, len));
        i += len;
    }
    return out;
}

}  // namespace chat
