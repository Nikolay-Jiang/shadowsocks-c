/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "control.hpp"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <sys/stat.h>
#include <sys/un.h>

#include "utils.h"

namespace ss::relay {

namespace {

void format_peer(const sockaddr_storage &addr, char *out, std::size_t size) noexcept
{
    char ip[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        const auto *in = reinterpret_cast<const sockaddr_in *>(&addr);
        ss_inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        std::snprintf(out, size, "%s:%u", ip, ntohs(in->sin_port));
    } else if (addr.ss_family == AF_INET6) {
        const auto *in = reinterpret_cast<const sockaddr_in6 *>(&addr);
        ss_inet_ntop(AF_INET6, &in->sin6_addr, ip, sizeof(ip));
        std::snprintf(out, size, "[%s]:%u", ip, ntohs(in->sin6_port));
    } else {
        std::snprintf(out, size, "-");
    }
}

void format_ip(const sockaddr_storage &addr, char *out, std::size_t size) noexcept
{
    if (addr.ss_family == AF_INET) {
        ss_inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in *>(&addr)->sin_addr, out,
                     static_cast<socklen_t>(size));
    } else if (addr.ss_family == AF_INET6) {
        ss_inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&addr)->sin6_addr, out,
                     static_cast<socklen_t>(size));
    } else {
        std::snprintf(out, size, "-");
    }
}

void format_target(const SocksTarget &target, char *out, std::size_t size) noexcept
{
    if (target.type == 4) {
        std::snprintf(out, size, "[%s]:%u", target.host, target.port);
    } else {
        std::snprintf(out, size, "%s:%u", target.host, target.port);
    }
}

std::uint64_t age_secs(std::uint64_t now, std::uint64_t then) noexcept
{
    return now > then ? (now - then) / 1000 : 0;
}

} // namespace

Status ControlServer::start(event::Loop &loop, const char *path, const ControlData &data) noexcept
{
    if (path == nullptr || *path == '\0' || std::strlen(path) >= sizeof(path_)) {
        return fail(Errc::config);
    }
    loop_ = &loop;
    data_ = data;
    std::strcpy(path_, path);
    (void)unlink(path_);
    ss_socket_t fd = ss_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        return fail(Errc::io);
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strcpy(addr.sun_path, path_);
    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        ss_socket_close(fd);
        return fail(Errc::io);
    }
    (void)chmod(path_, 0600);
    (void)set_nonblocking(fd);
    if (!poll_.open(loop, *this, fd)) {
        ss_socket_close(fd);
        (void)unlink(path_);
        return fail(Errc::io);
    }
    if (!poll_.want(event::readable)) {
        poll_.close(closer_);
        closer_.seal();
        (void)unlink(path_);
        return fail(Errc::io);
    }
    own_closed_ = false;
    LOGI("control socket listening at %s", path_);
    return {};
}

void ControlServer::shutdown() noexcept
{
    if (own_closed_) {
        return;
    }
    (void)unlink(path_);
    closer_.arm(CloseCompletion([](void *self, std::uint32_t) {
        static_cast<ControlServer *>(self)->own_closed_ = true;
    }, this, 0));
    poll_.close(closer_);
    closer_.seal();
}

event::Flow ControlServer::on_readable(int events) noexcept
{
    if ((events & event::readable) == 0) {
        return event::Flow::proceed;
    }
    for (int i = 0; i < 4; ++i) {
        sockaddr_storage from{};
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(poll_.fd(), request_.data(), request_.size(), 0, reinterpret_cast<sockaddr *>(&from),
                             &from_len);
        if (n < 0) {
            int err = ss_socket_error();
            if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR) {
                return event::Flow::proceed;
            }
            return event::Flow::proceed;
        }
        handle({ request_.data(), static_cast<std::size_t>(n) }, reinterpret_cast<const sockaddr *>(&from),
               from_len);
        if (response_len_ != 0) {
            (void)sendto(poll_.fd(), response_.data(), response_len_, 0, reinterpret_cast<const sockaddr *>(&from),
                         from_len);
        }
    }
    return event::Flow::proceed;
}

void ControlServer::handle(std::span<const std::uint8_t> request, const sockaddr *, socklen_t) noexcept
{
    response_len_ = 0;
    const char *text = reinterpret_cast<const char *>(request.data());
    std::size_t length = request.size();
    while (length != 0 && (text[length - 1] == '\n' || text[length - 1] == '\r' || text[length - 1] == '\0')) {
        --length;
    }
    std::size_t space = 0;
    while (space < length && text[space] != ' ') {
        ++space;
    }
    std::string_view command(text, space);
    std::string_view option = space < length ? std::string_view(text + space + 1, length - space - 1)
                                             : std::string_view{};
    bool json = option == "json";
    if (command == "users") {
        json ? users_json() : users_text();
    } else if (command == "conns") {
        json ? conns_json(true) : conns_text(true);
    } else if (command == "anon") {
        json ? anon_json() : anon_text();
    } else if (command == "stats") {
        json ? stats_json() : stats_text();
    } else {
        append("error\tunknown command\n");
    }
}

void ControlServer::append(const char *text) noexcept
{
    if (text == nullptr) {
        return;
    }
    std::size_t n = std::strlen(text);
    std::size_t room = response_.size() - 1 - response_len_;
    n = std::min(n, room);
    std::memcpy(response_.data() + response_len_, text, n);
    response_len_ += n;
    response_[response_len_] = '\0';
}

void ControlServer::appendf(const char *format, ...) noexcept
{
    if (response_len_ + 1 >= response_.size()) {
        return;
    }
    va_list args;
    va_start(args, format);
    int n = std::vsnprintf(response_.data() + response_len_, response_.size() - response_len_, format, args);
    va_end(args);
    if (n > 0) {
        std::size_t written = static_cast<std::size_t>(n);
        response_len_ += std::min(written, response_.size() - 1 - response_len_);
    }
}

void ControlServer::append_json_string(const char *text) noexcept
{
    append("\"");
    if (text != nullptr) {
        for (const char *p = text; *p != '\0'; ++p) {
            if (*p == '"' || *p == '\\') {
                char escaped[3] = { '\\', *p, '\0' };
                append(escaped);
            } else if (static_cast<unsigned char>(*p) < 0x20) {
                appendf("\\u%04x", static_cast<unsigned char>(*p));
            } else {
                char one[2] = { *p, '\0' };
                append(one);
            }
        }
    }
    append("\"");
}

void ControlServer::users_text()
{
    if (data_.method == nullptr || data_.users == nullptr) {
        append("error\tunavailable\n");
        return;
    }
    const std::uint64_t now = loop_->now();
    append("USER\tTCP\tUDP\tTX\tRX\tLAST\tIPS\n");
    for (std::uint32_t i = 0; i < data_.method->user_count(); ++i) {
        const auto &s = data_.users->at(static_cast<std::uint8_t>(i));
        std::uint32_t ips = 0;
        char seen[16][INET6_ADDRSTRLEN] = {};
        auto add_ip = [&](const sockaddr_storage &addr) {
            char ip[INET6_ADDRSTRLEN] = {};
            format_ip(addr, ip, sizeof(ip));
            for (std::uint32_t k = 0; k < ips; ++k) {
                if (std::strcmp(seen[k], ip) == 0) {
                    return;
                }
            }
            if (ips < 16) {
                std::strncpy(seen[ips], ip, sizeof(seen[ips]) - 1);
                ++ips;
            }
        };
        data_.tcp->for_each([&](const Connection &conn) {
            if (conn.user_index() == i) {
                add_ip(conn.peer());
            }
        });
        data_.udp->for_each([&](const UdpSession &session) {
            if (session.user_index() == i) {
                add_ip(session.client());
            }
        });
        appendf("%s\t%u\t%u\t%llu\t%llu\t%llus\t%u\n", data_.method->user_id(static_cast<std::uint8_t>(i)),
                s.tcp_current, s.udp_current, static_cast<unsigned long long>(s.tx),
                static_cast<unsigned long long>(s.rx), static_cast<unsigned long long>(s.last_seen == 0 ? 0 : age_secs(now, s.last_seen)),
                ips);
    }
    const auto &anon = data_.users->anonymous();
    appendf("anonymous\t%u\t%u\t%llu\t%llu\t%llus\t%u\n", anon.tcp_current, anon.udp_current,
            static_cast<unsigned long long>(anon.tx), static_cast<unsigned long long>(anon.rx),
            static_cast<unsigned long long>(anon.last_seen == 0 ? 0 : age_secs(now, anon.last_seen)),
            data_.limiter != nullptr ? data_.limiter->tracked() : 0);
}

void ControlServer::users_json()
{
    if (data_.method == nullptr || data_.users == nullptr) {
        append("{\"error\":\"unavailable\"}");
        return;
    }
    const std::uint64_t now = loop_->now();
    append("{\"users\":[");
    for (std::uint32_t i = 0; i < data_.method->user_count(); ++i) {
        const auto &s = data_.users->at(static_cast<std::uint8_t>(i));
        if (i != 0) {
            append(",");
        }
        append("{\"id\":");
        append_json_string(data_.method->user_id(static_cast<std::uint8_t>(i)));
        appendf(",\"tcp\":%u,\"udp\":%u,\"tx\":%llu,\"rx\":%llu,\"last_seen\":%llu}", s.tcp_current,
                s.udp_current, static_cast<unsigned long long>(s.tx), static_cast<unsigned long long>(s.rx),
                static_cast<unsigned long long>(s.last_seen == 0 ? 0 : age_secs(now, s.last_seen)));
    }
    const auto &anon = data_.users->anonymous();
    if (data_.method->user_count() != 0) {
        append(",");
    }
    appendf("{\"id\":\"anonymous\",\"tcp\":%u,\"udp\":%u,\"tx\":%llu,\"rx\":%llu,\"last_seen\":%llu,"
            "\"tracked_ips\":%u}]}",
            anon.tcp_current, anon.udp_current, static_cast<unsigned long long>(anon.tx),
            static_cast<unsigned long long>(anon.rx), static_cast<unsigned long long>(anon.last_seen == 0 ? 0 : age_secs(now, anon.last_seen)),
            data_.limiter != nullptr ? data_.limiter->tracked() : 0);
}

void ControlServer::conns_text(bool udp)
{
    const std::uint64_t now = loop_->now();
    append("USER\tPROTO\tPEER\tTARGET\tAGE\tTX\tRX\n");
    std::uint32_t count = 0;
    data_.tcp->for_each([&](const Connection &conn) {
        if (count++ >= 200) {
            return;
        }
        char peer[128] = {};
        char target[300] = {};
        format_peer(conn.peer(), peer, sizeof(peer));
        format_target(conn.target(), target, sizeof(target));
        const char *id = conn.is_anonymous() ? "anonymous" : data_.method->user_id(conn.user_index());
        appendf("%s\ttcp\t%s\t%s\t%llus\t%llu\t%llu\n", id, peer, target,
                static_cast<unsigned long long>(age_secs(now, conn.started_ms())),
                static_cast<unsigned long long>(conn.conn_tx()), static_cast<unsigned long long>(conn.conn_rx()));
    });
    if (udp) {
        data_.udp->for_each([&](const UdpSession &session) {
            if (count++ >= 200) {
                return;
            }
            char peer[128] = {};
            format_peer(session.client(), peer, sizeof(peer));
            const char *id = session.is_anonymous() ? "anonymous" : data_.method->user_id(session.user_index());
            appendf("%s\tudp\t%s\t-\t%llus\t%llu\t%llu\n", id, peer,
                    static_cast<unsigned long long>(age_secs(now, session.started_ms())),
                    static_cast<unsigned long long>(session.conn_tx()),
                    static_cast<unsigned long long>(session.conn_rx()));
        });
    }
    if (count > 200) {
        append("...\ttruncated\n");
    }
}

void ControlServer::conns_json(bool udp)
{
    const std::uint64_t now = loop_->now();
    append("{\"connections\":[");
    bool first = true;
    std::uint32_t count = 0;
    auto sep = [&]() {
        if (!first) {
            append(",");
        }
        first = false;
    };
    data_.tcp->for_each([&](const Connection &conn) {
        if (count++ >= 200) {
            return;
        }
        char peer[128] = {};
        char target[300] = {};
        format_peer(conn.peer(), peer, sizeof(peer));
        format_target(conn.target(), target, sizeof(target));
        sep();
        append("{\"user\":");
        append_json_string(conn.is_anonymous() ? "anonymous" : data_.method->user_id(conn.user_index()));
        append(",\"proto\":\"tcp\",\"peer\":");
        append_json_string(peer);
        append(",\"target\":");
        append_json_string(target);
        appendf(",\"age\":%llu,\"tx\":%llu,\"rx\":%llu}", static_cast<unsigned long long>(age_secs(now, conn.started_ms())),
                static_cast<unsigned long long>(conn.conn_tx()), static_cast<unsigned long long>(conn.conn_rx()));
    });
    if (udp) {
        data_.udp->for_each([&](const UdpSession &session) {
            if (count++ >= 200) {
                return;
            }
            char peer[128] = {};
            format_peer(session.client(), peer, sizeof(peer));
            sep();
            append("{\"user\":");
            append_json_string(session.is_anonymous() ? "anonymous" : data_.method->user_id(session.user_index()));
            append(",\"proto\":\"udp\",\"peer\":");
            append_json_string(peer);
            appendf(",\"target\":\"-\",\"age\":%llu,\"tx\":%llu,\"rx\":%llu}",
                    static_cast<unsigned long long>(age_secs(now, session.started_ms())),
                    static_cast<unsigned long long>(session.conn_tx()),
                    static_cast<unsigned long long>(session.conn_rx()));
        });
    }
    append("]}");
}

void ControlServer::anon_text()
{
    if (data_.limiter == nullptr) {
        append("error\tunavailable\n");
        return;
    }
    const std::uint64_t now = loop_->now();
    append("IP\tTCP\tUDP\tPENDING\tTX\tTOKENS\tLAST\tSTATE\n");
    std::uint32_t count = 0;
    data_.limiter->for_each([&](const PeerSnapshot &peer) {
        if (count++ >= 200) {
            return;
        }
        appendf("%s\t%u\t%u\t%u\t%llu\t%llu\t%llus\t%s\n", peer.address, peer.tcp_connections, peer.udp_sessions,
                peer.pending, static_cast<unsigned long long>(peer.tx_bytes),
                static_cast<unsigned long long>(peer.tokens),
                static_cast<unsigned long long>(age_secs(now, peer.last_seen)),
                peer.throttled ? "throttled" : "ok");
    });
    if (count > 200) {
        append("...\ttruncated\n");
    }
}

void ControlServer::anon_json()
{
    if (data_.limiter == nullptr) {
        append("{\"error\":\"unavailable\"}");
        return;
    }
    const std::uint64_t now = loop_->now();
    append("{\"anonymous\":[");
    bool first = true;
    std::uint32_t count = 0;
    data_.limiter->for_each([&](const PeerSnapshot &peer) {
        if (count++ >= 200) {
            return;
        }
        if (!first) {
            append(",");
        }
        first = false;
        append("{\"ip\":");
        append_json_string(peer.address);
        appendf(",\"tcp\":%u,\"udp\":%u,\"pending\":%u,\"tx\":%llu,\"tokens\":%llu,\"last_seen\":%llu,"
                "\"state\":\"%s\"}",
                peer.tcp_connections, peer.udp_sessions, peer.pending,
                static_cast<unsigned long long>(peer.tx_bytes), static_cast<unsigned long long>(peer.tokens),
                static_cast<unsigned long long>(age_secs(now, peer.last_seen)),
                peer.throttled ? "throttled" : "ok");
    });
    append("]}");
}

void ControlServer::stats_text()
{
    appendf("tx\t%llu\nrx\t%llu\ntcp_live\t%u\ntcp_refused\t%llu\nudp_sessions\t%u\nusers\t%u\ntracked_ips\t%u\n",
            static_cast<unsigned long long>(data_.tx != nullptr ? *data_.tx : 0),
            static_cast<unsigned long long>(data_.rx != nullptr ? *data_.rx : 0), data_.tcp->live(),
            static_cast<unsigned long long>(data_.tcp->refused()), data_.udp->sessions(),
            data_.method != nullptr ? data_.method->user_count() : 0,
            data_.limiter != nullptr ? data_.limiter->tracked() : 0);
}

void ControlServer::stats_json()
{
    appendf("{\"tx\":%llu,\"rx\":%llu,\"tcp_live\":%u,\"tcp_refused\":%llu,\"udp_sessions\":%u,\"users\":%u,"
            "\"tracked_ips\":%u}",
            static_cast<unsigned long long>(data_.tx != nullptr ? *data_.tx : 0),
            static_cast<unsigned long long>(data_.rx != nullptr ? *data_.rx : 0), data_.tcp->live(),
            static_cast<unsigned long long>(data_.tcp->refused()), data_.udp->sessions(),
            data_.method != nullptr ? data_.method->user_count() : 0,
            data_.limiter != nullptr ? data_.limiter->tracked() : 0);
}

} // namespace ss::relay
