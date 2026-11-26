/* SPDX-License-Identifier: GPL-3.0-or-later */
// ssctl text formatting: compact ages, byte counters and user IDs.
#include <cstring>

#include "control_format.hpp"
#include "test_helpers.hpp"

namespace {

void expect_age(const char *expected, std::uint64_t seconds, bool clear_after_day)
{
    char out[16];
    ss::relay::format::format_age(out, sizeof(out), seconds, clear_after_day);
    SS_CHECK(std::strcmp(out, expected) == 0);
}

void test_age()
{
    expect_age("0s", 0, true);
    expect_age("59s", 59, true);
    expect_age("1m", 60, true);
    expect_age("59m", 3599, true);
    expect_age("1h", 3600, true);
    expect_age("23h", 86399, true);
    expect_age("-", 86400, true);
    expect_age("24h", 86400, false);
    expect_age("25h", 90000, false);
}

void expect_bytes(const char *expected, std::uint64_t bytes)
{
    char out[32];
    ss::relay::format::format_bytes(out, sizeof(out), bytes);
    SS_CHECK(std::strcmp(out, expected) == 0);
}

void test_bytes()
{
    expect_bytes("0B", 0);
    expect_bytes("1023B", 1023);
    expect_bytes("1.0KB", 1024);
    expect_bytes("1.5KB", 1536);
    expect_bytes("1.0MB", 1024 * 1024);
    expect_bytes("1.0MB", 1024 * 1024 - 1);
    expect_bytes("1.0GB", 1024ULL * 1024 * 1024);
    expect_bytes("1.0TB", 1024ULL * 1024 * 1024 * 1024);
}

void expect_user(const char *expected, const char *id)
{
    char out[80];
    ss::relay::format::format_user(out, sizeof(out), id);
    SS_CHECK(std::strcmp(out, expected) == 0);
}

void test_user()
{
    expect_user("alice", "alice");
    expect_user("abcdef", "abcdef");
    expect_user("abcdef...", "abcdefg");
    expect_user("anonym...", "anonymous");
    expect_user("-", nullptr);
    expect_user("-", "");

    const char *cjk7 = "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80";
    const char *cjk6 = "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80"
                       "\xE4\xB8\x80";
    const char *cjk6_dots = "\xE4\xB8\x80"
                            "\xE4\xB8\x80"
                            "\xE4\xB8\x80"
                            "\xE4\xB8\x80"
                            "\xE4\xB8\x80"
                            "\xE4\xB8\x80"
                            "...";
    expect_user(cjk6, cjk6);
    expect_user(cjk6_dots, cjk7);
}

} // namespace

int main()
{
    SS_RUN(test_age);
    SS_RUN(test_bytes);
    SS_RUN(test_user);
    return 0;
}
