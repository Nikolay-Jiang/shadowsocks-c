/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CONTROL_HPP
#define SS_CONTROL_HPP

// Read-only local control socket for ss-server: ssctl sends one datagram
// ("users", "conns", "anon", "stats", optionally followed by "json") and
// receives one text or JSON response. A Unix datagram socket keeps the
// server side stateless: no per-client allocations or connection pool.

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/result.hpp"
#include "event/loop.hpp"
#include "platform.h"
#include "relay/limiter.hpp"
#include "relay/tcp.hpp"
#include "relay/udp.hpp"
#include "relay/users.hpp"

namespace ss::relay {

struct ControlData {
    Method *method       = nullptr;
    UserRegistry *users  = nullptr;
    PeerLimiter *limiter = nullptr;
    TcpRelay *tcp        = nullptr;
    UdpRelay *udp        = nullptr;
    std::uint64_t *tx    = nullptr;
    std::uint64_t *rx    = nullptr;
};

class ControlServer {
public:
    ControlServer() noexcept = default;
    ControlServer(const ControlServer &)            = delete;
    ControlServer &operator=(const ControlServer &) = delete;
    ~ControlServer() { shutdown(); }

    Status start(event::Loop &loop, const char *path, const ControlData &data) noexcept;
    void shutdown() noexcept;
    bool closed() const noexcept { return own_closed_; }

private:
    event::Flow on_readable(int events) noexcept;
    void handle(std::span<const std::uint8_t> request, const sockaddr *from, socklen_t from_len) noexcept;
    void users_text();
    void users_json();
    void conns_text(bool udp);
    void conns_json(bool udp);
    void anon_text();
    void anon_json();
    void stats_text();
    void stats_json();
    void append(const char *text) noexcept;
    void appendf(const char *format, ...) noexcept;
    void append_json_string(const char *text) noexcept;
    void truncate_marker(bool json) noexcept;

    event::Loop *loop_ = nullptr;
    ControlData data_{};
    event::Poll<ControlServer, &ControlServer::on_readable> poll_;
    event::CloseGroup closer_;
    std::array<std::uint8_t, 4096> request_{};
    std::array<char, 60000> response_{};
    std::size_t response_len_ = 0;
    char path_[108] = {};
    bool own_closed_ = true;
};

} // namespace ss::relay

#endif
