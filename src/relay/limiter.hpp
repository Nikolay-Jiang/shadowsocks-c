/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_RELAY_LIMITER_HPP
#define SS_RELAY_LIMITER_HPP

// Anonymous-client limits, keyed by the client IP. IPv4 uses /32 and IPv6
// uses a configurable prefix (64 by default) so rotating addresses inside a
// /64 does not bypass the limit. The table is fixed-size and preallocated;
// every counter and token bucket update happens on the relay loop thread.

#include <cstddef>
#include <cstdint>

#include "core/fixed_map.hpp"
#include "core/result.hpp"
#include "platform.h"

namespace ss::relay {

struct AnonymousLimits {
    std::uint32_t max_tcp_per_ip    = 20;
    std::uint32_t max_udp_per_ip    = 20;
    std::uint32_t preauth_per_ip    = 40;
    std::uint32_t upload_kbps       = 1024; // kilobits per second
    std::uint32_t burst_kb          = 2048;
    std::uint32_t ipv6_prefix       = 64;
    std::uint32_t max_tracked_ips   = 4096;
};

struct PeerSnapshot {
    char address[INET6_ADDRSTRLEN] = {};
    std::uint32_t tcp_connections = 0;
    std::uint32_t udp_sessions    = 0;
    std::uint32_t pending         = 0;
    std::uint64_t tx_bytes        = 0;
    std::uint64_t tokens          = 0;
    std::uint64_t last_seen       = 0;
    bool throttled                = false;
};

class PeerLimiter {
public:
    PeerLimiter() noexcept = default;
    PeerLimiter(const PeerLimiter &)            = delete;
    PeerLimiter &operator=(const PeerLimiter &) = delete;

    Status init(const AnonymousLimits &limits, std::uint64_t seed) noexcept;

    // All accepted TCP connections reserve a handshake slot.
    bool begin_handshake(const sockaddr *peer, std::uint64_t now) noexcept;
    // Release the handshake slot and admit anonymous users, subject to the
    // per-IP anonymous connection cap. Identified users are always admitted.
    bool authenticate(const sockaddr *peer, bool anonymous, std::uint64_t now) noexcept;
    void end_handshake(const sockaddr *peer) noexcept;
    void close_tcp(const sockaddr *peer, bool anonymous) noexcept;

    bool begin_udp(const sockaddr *peer, bool anonymous, std::uint64_t now) noexcept;
    void end_udp(const sockaddr *peer, bool anonymous) noexcept;

    // Refill and return how many bytes may be read now. Identified users are
    // not rate-limited.
    std::size_t budget(const sockaddr *peer, std::size_t want, bool anonymous, std::uint64_t now) noexcept;
    void consume(const sockaddr *peer, std::size_t bytes, bool anonymous, std::uint64_t now) noexcept;

    template <class F>
    void for_each(F &&f)
    {
        peers_.for_each([&](const FixedKey<17> &key, const PeerState &state) {
            PeerSnapshot snapshot;
            format_key(key, snapshot.address, sizeof(snapshot.address));
            snapshot.tcp_connections = state.tcp_connections;
            snapshot.udp_sessions    = state.udp_sessions;
            snapshot.pending         = state.pending;
            snapshot.tx_bytes        = state.tx_bytes;
            snapshot.tokens          = state.tokens;
            snapshot.last_seen       = state.last_seen;
            snapshot.throttled       = state.tcp_connections != 0 && state.tokens == 0;
            f(snapshot);
        });
    }

    std::uint32_t tracked() noexcept
    {
        std::uint32_t active = 0;
        peers_.for_each([&](const auto &, const PeerState &state) {
            if (state.tcp_connections != 0 || state.udp_sessions != 0 || state.pending != 0) {
                ++active;
            }
        });
        return active;
    }
    const AnonymousLimits &limits() const noexcept { return limits_; }

private:
    struct PeerState {
        std::uint32_t tcp_connections = 0;
        std::uint32_t udp_sessions    = 0;
        std::uint32_t pending         = 0;
        std::uint64_t tokens          = 0;
        std::uint64_t last_ms         = 0;
        std::uint64_t tx_bytes        = 0;
        std::uint64_t last_seen       = 0;
    };

    using PeerKey = FixedKey<17>;

    bool key_for(const sockaddr *peer, PeerKey &key) const noexcept;
    static void format_key(const PeerKey &key, char *out, std::size_t size) noexcept;
    PeerState *find(const PeerKey &key) noexcept;
    PeerState *find_or_create(const PeerKey &key, std::uint64_t now) noexcept;
    void refill(PeerState &state, std::uint64_t now) noexcept;
    bool evict_idle() noexcept;

    AnonymousLimits limits_{};
    FixedLru<PeerKey, PeerState> peers_;
    std::uint64_t rate_bytes_per_sec_ = 0;
    std::uint64_t burst_bytes_        = 0;
};

} // namespace ss::relay

#endif
