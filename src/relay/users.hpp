/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_RELAY_USERS_HPP
#define SS_RELAY_USERS_HPP

// Per-user counters for SIP023 identities. The table is fixed-size and
// contains no allocation; the relay updates it from its single loop thread.

#include <array>
#include <cstdint>

namespace ss::relay {

struct UserStats {
    std::uint32_t tcp_current = 0;
    std::uint32_t udp_current = 0;
    std::uint64_t tcp_total   = 0;
    std::uint64_t udp_total   = 0;
    std::uint64_t tx          = 0;
    std::uint64_t rx          = 0;
    std::uint64_t last_seen   = 0; // loop milliseconds
};

class UserRegistry {
public:
    void set_count(std::uint32_t count) noexcept { count_ = count; }
    std::uint32_t count() const noexcept { return count_; }

    UserStats &at(std::uint8_t index) noexcept { return stats_[index]; }
    const UserStats &at(std::uint8_t index) const noexcept { return stats_[index]; }
    UserStats &anonymous() noexcept { return anonymous_; }
    const UserStats &anonymous() const noexcept { return anonymous_; }

    void open(std::uint8_t index, bool tcp, std::uint64_t now) noexcept
    {
        UserStats &s = index < count_ ? stats_[index] : anonymous_;
        if (tcp) {
            ++s.tcp_current;
            ++s.tcp_total;
        } else {
            ++s.udp_current;
            ++s.udp_total;
        }
        s.last_seen = now;
    }

    void close(std::uint8_t index, bool tcp) noexcept
    {
        UserStats &s = index < count_ ? stats_[index] : anonymous_;
        if (tcp) {
            if (s.tcp_current != 0) {
                --s.tcp_current;
            }
        } else if (s.udp_current != 0) {
            --s.udp_current;
        }
    }

    void add_tx(std::uint8_t index, std::uint64_t bytes, std::uint64_t now) noexcept
    {
        UserStats &s = index < count_ ? stats_[index] : anonymous_;
        s.tx += bytes;
        s.last_seen = now;
    }

    void add_rx(std::uint8_t index, std::uint64_t bytes, std::uint64_t now) noexcept
    {
        UserStats &s = index < count_ ? stats_[index] : anonymous_;
        s.rx += bytes;
        s.last_seen = now;
    }

private:
    static constexpr std::uint32_t kMaxUsers = 64;
    std::array<UserStats, kMaxUsers> stats_{};
    UserStats anonymous_{};
    std::uint32_t count_ = 0;
};

} // namespace ss::relay

#endif
