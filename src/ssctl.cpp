/* SPDX-License-Identifier: GPL-3.0-or-later */
// ssctl - read-only query tool for ss-server's local control socket.

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <getopt.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

constexpr const char *kDefaultSocket = "/run/shadowsocks-c/control.sock";
constexpr std::size_t kResponseMax   = 65500;

void usage(const char *program)
{
    std::fprintf(stderr,
                 "Usage: %s [options] <command>\n"
                 "\n"
                 "Commands:\n"
                 "  users    configured SIP023 users and current activity\n"
                 "  conns    active TCP/UDP sessions\n"
                 "  anon     anonymous per-IP limits\n"
                 "  stats    global counters\n"
                 "\n"
                 "Options:\n"
                 "  -s, --socket <path>  control socket (default: %s)\n"
                 "      --json           request JSON output\n"
                 "  -h, --help           show this help\n",
                 program, kDefaultSocket);
}

} // namespace

int main(int argc, char **argv)
{
    const char *socket_path = kDefaultSocket;
    bool json              = false;
    static struct option options[] = {
        { "socket", required_argument, nullptr, 's' },
        { "json", no_argument, nullptr, 'j' },
        { "help", no_argument, nullptr, 'h' },
        { nullptr, 0, nullptr, 0 },
    };
    int c;
    while ((c = getopt_long(argc, argv, "s:jh", options, nullptr)) != -1) {
        switch (c) {
        case 's':
            socket_path = optarg;
            break;
        case 'j':
            json = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    if (optind + 1 != argc) {
        usage(argv[0]);
        return 2;
    }
    const char *command = argv[optind];
    if (std::strcmp(command, "users") != 0 && std::strcmp(command, "conns") != 0
        && std::strcmp(command, "anon") != 0 && std::strcmp(command, "stats") != 0) {
        std::fprintf(stderr, "ssctl: unknown command: %s\n", command);
        usage(argv[0]);
        return 2;
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::perror("ssctl: socket");
        return 1;
    }

    sockaddr_un local{};
    local.sun_family = AF_UNIX;
    std::snprintf(local.sun_path, sizeof(local.sun_path), "/tmp/ssctl.%ld.%ld", static_cast<long>(getpid()),
                  static_cast<long>(time(nullptr)));
    (void)unlink(local.sun_path);
    if (bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
        std::perror("ssctl: bind");
        close(fd);
        return 1;
    }

    sockaddr_un remote{};
    remote.sun_family = AF_UNIX;
    if (std::strlen(socket_path) >= sizeof(remote.sun_path)) {
        std::fprintf(stderr, "ssctl: socket path is too long\n");
        (void)unlink(local.sun_path);
        close(fd);
        return 2;
    }
    std::strcpy(remote.sun_path, socket_path);

    char request[64];
    std::snprintf(request, sizeof(request), "%s%s", command, json ? " json" : "");
    if (sendto(fd, request, std::strlen(request), 0, reinterpret_cast<sockaddr *>(&remote), sizeof(remote)) < 0) {
        std::perror("ssctl: sendto");
        (void)unlink(local.sun_path);
        close(fd);
        return 1;
    }

    pollfd pfd{ fd, POLLIN, 0 };
    int ready = poll(&pfd, 1, 3000);
    if (ready <= 0) {
        std::fprintf(stderr, "ssctl: no response from %s\n", socket_path);
        (void)unlink(local.sun_path);
        close(fd);
        return 1;
    }

    char response[kResponseMax];
    ssize_t n = recv(fd, response, sizeof(response) - 1, 0);
    (void)unlink(local.sun_path);
    close(fd);
    if (n < 0) {
        std::perror("ssctl: recv");
        return 1;
    }
    response[n] = '\0';
    std::fputs(response, stdout);
    if (n == 0 || response[n - 1] != '\n') {
        std::fputc('\n', stdout);
    }
    return 0;
}
