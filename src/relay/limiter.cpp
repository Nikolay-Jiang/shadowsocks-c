/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "relay/limiter.hpp"

#include <algorithm>
#include <cstring>

#include "core/buffer.hpp"

namespace ss::relay {

namespace {

constexpr std::uint8_t kFamilyV4 = 4;
constexpr std::uint8_t kFamilyV6 = 6;

} // namespace

Status PeerLimiter::init(const AnonymousLimits &limits, std::uint64_t seed) noexcept
{
    if (limits.max_tracked_ips == 0) {
        return fail(Errc::config);
    }
    limits_ = limits;
    if (limits_.ipv6_prefix > 128) {
        limits_.ipv6_prefix = 128;
    }
    rate_bytes_per_sec_ = static_cast<std::uint64_t>(limits_.upload_kbps) * 1000 / 8;
    burst_bytes_        = static_cast<std::uint64_t>(limits_.burst_kb) * 1024;
    if (burst_bytes_ == 0 && rate_bytes_per_sec_ != 0) {
        burst_bytes_ = rate_bytes_per_sec_;
    }
    return peers_.reserve(limits_.max_tracked_ips, seed);
}

bool PeerLimiter::key_for(const sockaddr *peer, PeerKey &key) const noexcept
{
    std::array<std::uint8_t, 17> raw{};
    if (peer->sa_family == AF_INET) {
        raw[0] = kFamilyV4;
        std::memcpy(raw.data() + 1, &reinterpret_cast<const sockaddr_in *>(peer)->sin_addr, 4);
        auto k = PeerKey::from(as_bytes(raw.data(), 5));
        if (!k) {
            return false;
        }
        key = *k;
        return true;
    }
    if (peer->sa_family == AF_INET6) {
        const auto *in6 = &reinterpret_cast<const sockaddr_in6 *>(peer)->sin6_addr;
#ifdef IN6_IS_ADDR_V4MAPPED
        if (IN6_IS_ADDR_V4MAPPED(in6)) {
            raw[0] = kFamilyV4;
            std::memcpy(raw.data() + 1, reinterpret_cast<const std::uint8_t *>(in6) + 12, 4);
            auto k = PeerKey::from(as_bytes(raw.data(), 5));
            if (!k) {
                return false;
            }
            key = *k;
            return true;
        }
#endif
        raw[0] = kFamilyV6;
        std::memcpy(raw.data() + 1, in6, 16);
        std::uint32_t prefix = limits_.ipv6_prefix;
        for (std::uint32_t bit = prefix; bit < 128; ++bit) {
            raw[1 + bit / 8] &= static_cast<std::uint8_t>(~(1U << (7 - (bit % 8))));
        }
        auto k = PeerKey::from(as_bytes(raw.data(), 17));
        if (!k) {
            return false;
        }
        key = *k;
        return true;
    }
    return false;
}

void PeerLimiter::format_key(const PeerKey &key, char *out, std::size_t size) noexcept
{
    out[0] = '\0';
    auto bytes = key.bytes();
    if (bytes.size() == 5 && static_cast<std::uint8_t>(bytes[0]) == kFamilyV4) {
        ss_inet_ntop(AF_INET, bytes.data() + 1, out, static_cast<socklen_t>(size));
    } else if (bytes.size() == 17 && static_cast<std::uint8_t>(bytes[0]) == kFamilyV6) {
        ss_inet_ntop(AF_INET6, bytes.data() + 1, out, static_cast<socklen_t>(size));
    }
}

PeerLimiter::PeerState *PeerLimiter::find(const PeerKey &key) noexcept
{
    return peers_.find(key);
}

PeerLimiter::PeerState *PeerLimiter::find_or_create(const PeerKey &key, std::uint64_t now) noexcept
{
    if (PeerState *found = peers_.find(key)) {
        return found;
    }
    if (peers_.full() && !evict_idle()) {
        return nullptr;
    }
    auto inserted = peers_.emplace(key, PeerState{});
    if (!inserted) {
        return nullptr;
    }
    PeerState &state = **inserted;
    state.tokens     = burst_bytes_;
    state.last_ms    = now;
    return &state;
}

bool PeerLimiter::evict_idle() noexcept
{
    // Only the oldest entry is considered, so an active old peer keeps the
    // table full rather than letting new addresses displace live traffic.
    const PeerKey *oldest = peers_.oldest_key();
    if (oldest == nullptr) {
        return false;
    }
    PeerState *state = peers_.peek(*oldest);
    if (state != nullptr
        && (state->tcp_connections != 0 || state->udp_sessions != 0 || state->pending != 0)) {
        return false;
    }
    return peers_.erase(*oldest);
}

void PeerLimiter::refill(PeerState &state, std::uint64_t now) noexcept
{
    if (state.last_ms == 0) {
        state.last_ms = now;
        state.tokens  = burst_bytes_;
        return;
    }
    if (now <= state.last_ms) {
        return;
    }
    if (rate_bytes_per_sec_ != 0) {
        std::uint64_t elapsed = now - state.last_ms;
        std::uint64_t add     = elapsed * rate_bytes_per_sec_ / 1000;
        if (add != 0) {
            state.tokens = std::min(burst_bytes_, state.tokens + add);
        }
    }
    state.last_ms = now;
    state.last_seen = now;
}

bool PeerLimiter::begin_handshake(const sockaddr *peer, std::uint64_t now) noexcept
{
    PeerKey key;
    if (!key_for(peer, key)) {
        return false;
    }
    PeerState *state = find_or_create(key, now);
    if (state == nullptr) {
        return false;
    }
    if (limits_.preauth_per_ip != 0 && state->pending >= limits_.preauth_per_ip) {
        return false;
    }
    ++state->pending;
    state->last_seen = now;
    return true;
}

bool PeerLimiter::authenticate(const sockaddr *peer, bool anonymous, std::uint64_t now) noexcept
{
    PeerKey key;
    if (!key_for(peer, key)) {
        return false;
    }
    PeerState *state = find(key);
    if (state == nullptr) {
        return false;
    }
    if (state->pending != 0) {
        --state->pending;
    }
    state->last_seen = now;
    if (!anonymous) {
        return true;
    }
    if (limits_.max_tcp_per_ip != 0 && state->tcp_connections >= limits_.max_tcp_per_ip) {
        return false;
    }
    ++state->tcp_connections;
    return true;
}

void PeerLimiter::end_handshake(const sockaddr *peer) noexcept
{
    PeerKey key;
    if (!key_for(peer, key)) {
        return;
    }
    if (PeerState *state = find(key)) {
        if (state->pending != 0) {
            --state->pending;
        }
    }
}

void PeerLimiter::close_tcp(const sockaddr *peer, bool anonymous) noexcept
{
    PeerKey key;
    if (!key_for(peer, key)) {
        return;
    }
    if (PeerState *state = find(key)) {
        if (anonymous && state->tcp_connections != 0) {
            --state->tcp_connections;
        }
    }
}

bool PeerLimiter::begin_udp(const sockaddr *peer, bool anonymous, std::uint64_t now) noexcept
{
    if (!anonymous) {
        return true;
    }
    PeerKey key;
    if (!key_for(peer, key)) {
        return false;
    }
    PeerState *state = find_or_create(key, now);
    if (state == nullptr) {
        return false;
    }
    state->last_seen = now;
    if (limits_.max_udp_per_ip != 0 && state->udp_sessions >= limits_.max_udp_per_ip) {
        return false;
    }
    ++state->udp_sessions;
    return true;
}

void PeerLimiter::end_udp(const sockaddr *peer, bool anonymous) noexcept
{
    if (!anonymous) {
        return;
    }
    PeerKey key;
    if (!key_for(peer, key)) {
        return;
    }
    if (PeerState *state = find(key)) {
        if (state->udp_sessions != 0) {
            --state->udp_sessions;
        }
    }
}

std::size_t PeerLimiter::budget(const sockaddr *peer, std::size_t want, bool anonymous,
                                std::uint64_t now) noexcept
{
    if (!anonymous || rate_bytes_per_sec_ == 0) {
        return want;
    }
    PeerKey key;
    if (!key_for(peer, key)) {
        return want;
    }
    PeerState *state = find(key);
    if (state == nullptr) {
        return 0;
    }
    refill(*state, now);
    return static_cast<std::size_t>(std::min<std::uint64_t>(state->tokens, want));
}

void PeerLimiter::consume(const sockaddr *peer, std::size_t bytes, bool anonymous, std::uint64_t now) noexcept
{
    if (!anonymous || rate_bytes_per_sec_ == 0 || bytes == 0) {
        return;
    }
    PeerKey key;
    if (!key_for(peer, key)) {
        return;
    }
    PeerState *state = find(key);
    if (state == nullptr) {
        return;
    }
    refill(*state, now);
    state->tokens = state->tokens > bytes ? state->tokens - bytes : 0;
    state->tx_bytes += bytes;
    state->last_seen = now;
}

} // namespace ss::relay
