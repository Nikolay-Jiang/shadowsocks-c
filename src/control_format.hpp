/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CONTROL_FORMAT_HPP
#define SS_CONTROL_FORMAT_HPP

// Formatting helpers for the human-readable control-socket tables. JSON
// responses keep raw numeric values for scripts.

#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace ss::relay::format {

constexpr std::uint64_t kMinute = 60;
constexpr std::uint64_t kHour   = 60 * kMinute;
constexpr std::uint64_t kDay    = 24 * kHour;

inline void format_age(char *out, std::size_t size, std::uint64_t seconds, bool clear_after_day) noexcept
{
    if (out == nullptr || size == 0) {
        return;
    }
    if (clear_after_day && seconds >= kDay) {
        std::snprintf(out, size, "-");
    } else if (seconds >= kHour) {
        std::snprintf(out, size, "%lluh", static_cast<unsigned long long>(seconds / kHour));
    } else if (seconds >= kMinute) {
        std::snprintf(out, size, "%llum", static_cast<unsigned long long>(seconds / kMinute));
    } else {
        std::snprintf(out, size, "%llus", static_cast<unsigned long long>(seconds));
    }
}

inline void format_bytes(char *out, std::size_t size, std::uint64_t bytes) noexcept
{
    if (out == nullptr || size == 0) {
        return;
    }
    const char *const units[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    constexpr std::size_t unit_count = sizeof(units) / sizeof(units[0]);

    if (bytes < 1024) {
        std::snprintf(out, size, "%lluB", static_cast<unsigned long long>(bytes));
        return;
    }

    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    do {
        value /= 1024.0;
        ++unit;
    } while (value >= 1024.0 && unit + 1 < unit_count);

    // Avoid printing 1024.0KB when rounding would promote the value.
    if (value >= 1023.95 && unit + 1 < unit_count) {
        value /= 1024.0;
        ++unit;
    }
    std::snprintf(out, size, "%.1f%s", value, units[unit]);
}

inline std::size_t utf8_char_len(unsigned char lead) noexcept
{
    if (lead < 0x80) {
        return 1;
    }
    if ((lead & 0xE0) == 0xC0) {
        return 2;
    }
    if ((lead & 0xF0) == 0xE0) {
        return 3;
    }
    if ((lead & 0xF8) == 0xF0) {
        return 4;
    }
    return 1;
}

inline std::size_t utf8_prefix_bytes(const char *text, std::size_t max_chars) noexcept
{
    const auto *p = reinterpret_cast<const unsigned char *>(text);
    std::size_t chars = 0;
    std::size_t bytes = 0;
    while (*p != 0 && chars < max_chars) {
        std::size_t len = utf8_char_len(*p);
        for (std::size_t i = 1; i < len; ++i) {
            if (p[i] == 0 || (p[i] & 0xC0) != 0x80) {
                len = 1;
                break;
            }
        }
        p += len;
        bytes += len;
        ++chars;
    }
    return bytes;
}

inline void format_user(char *out, std::size_t size, const char *id) noexcept
{
    if (out == nullptr || size == 0) {
        return;
    }
    if (id == nullptr || *id == '\0') {
        std::snprintf(out, size, "-");
        return;
    }
    const std::size_t prefix = utf8_prefix_bytes(id, 6);
    if (id[prefix] == '\0') {
        std::snprintf(out, size, "%s", id);
    } else {
        std::snprintf(out, size, "%.*s...", static_cast<int>(prefix), id);
    }
}

} // namespace ss::relay::format

#endif // SS_CONTROL_FORMAT_HPP
