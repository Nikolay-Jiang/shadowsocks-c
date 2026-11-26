# shadowsocks-c

[![Build](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/build.yml) [![Tests](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/tests.yml) [![Portability](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/portability.yml/badge.svg?branch=master)](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/portability.yml)

## Intro

[shadowsocks-c](https://shadowsocks.org) is a lightweight secured SOCKS5
proxy for embedded devices and low-end boxes.

It is a port of [Shadowsocks](https://github.com/shadowsocks/shadowsocks)
created by [@clowwindy](https://github.com/clowwindy), and maintained by
[@madeye](https://github.com/madeye) and [@linusyang](https://github.com/linusyang).

Current version: 3.4.0 | [Changelog](debian/changelog)

[CLI reference and configuration guide](https://shadowsocks.github.io/shadowsocks-c/)
are generated from the source with Doxygen and published after updates to `master`.

An opt-in [printable TCP salt experiment](docs/printable-salt.md) is available
through `ss-local --printable-salt` or `"printable_salt": true` in the config
file. It is disabled by default.

SIP023 multi-user identities, anonymous per-IP limits, and the `ssctl` status
tool are documented in [SIP023 users and anonymous limits](docs/sip023-users.md).

Use `--help` for grouped CLI options and `--version` for version information.
See [CLI conventions](https://shadowsocks.github.io/shadowsocks-c/index.html#cli_conventions)
for the long flags, short aliases, and configuration precedence.

## Community

See the [contribution guide](CONTRIBUTION.md) for development setup, testing,
and pull request guidance.

Everyone participating in this project is expected to follow our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Project history and rename

This repository began as **shadowsocks-libev**, the lightweight C implementation
of Shadowsocks built around the libev event loop. It later entered a bug-fix-only
maintenance phase, with new development directed toward
[shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust).

In September 2026, the C implementation was modernized with a focus on
self-contained builds and portability. [The build modernization](https://github.com/shadowsocks/shadowsocks-c/pull/3050)
bundled pinned dependency sources, removed several external dependencies, and
added static-build validation across platforms.
[The subsequent migration](https://github.com/shadowsocks/shadowsocks-c/pull/3051)
replaced libev with libuv, added Windows IOCP and macOS kqueue support, expanded
asynchronous runtime DNS coverage, and strengthened CI lint checks.

The project and GitHub repository were renamed **shadowsocks-c** to reflect its
continuing identity as a pure C implementation. This repository retains the
shadowsocks-libev commit history and releases. The canonical repository is now
[shadowsocks/shadowsocks-c](https://github.com/shadowsocks/shadowsocks-c).

### Compatibility with shadowsocks-libev

- Commands such as `ss-local` and `ss-server`, the `shadowsocks.h` API, and the
  embedding library ABI remain compatible.
- New builds provide `libshadowsocks-c` and the CMake/pkg-config package
  `shadowsocks-c`. Legacy library filenames and the `shadowsocks-libev` package
  lookup name remain available as compatibility aliases.
- Existing configuration paths, distribution package names, and service names
  are retained. References to `shadowsocks-libev` in the installation examples
  below refer to those existing integrations.

See [the modernization notes](docs/modernization.md) for build options and
platform support, and [the performance measurements](docs/performance.md) for
measured tradeoffs.

## Features

shadowsocks-c is written in pure C and depends on [libuv](https://libuv.org/). It's designed
to be a lightweight implementation of shadowsocks protocol, in order to keep the resource usage as low as possible.

For a full list of feature comparison between different versions of shadowsocks,
refer to the [Wiki page](https://github.com/shadowsocks/shadowsocks/wiki/Feature-Comparison-across-Different-Versions).

## Quick Start

### Prebuilt Linux binaries

Release archives contain fully static musl binaries for Linux AMD64. Download
the `shadowsocks-c-<version>-linux-amd64.tar.gz` archive from
[Releases](https://github.com/Nikolay-Jiang/shadowsocks-c/releases), extract it,
and create `config.json` with a long random password:

```json
{
  "server": "0.0.0.0",
  "server_port": 8388,
  "password": "replace-with-a-long-random-password",
  "method": "aes-256-gcm",
  "mode": "tcp_and_udp"
}
```

```sh
tar -xzf shadowsocks-c-<version>-linux-amd64.tar.gz
cd shadowsocks-c-<version>-linux-amd64
./bin/ss-server -c /etc/shadowsocks-c/config.json
```

The archive includes `README.md` and `sip023-users.md`. Configure your
Shadowsocks client with the server address, port, password and method above.
For other platforms, build from source below.

## Installation

### Distribution-specific guide

- [Debian & Ubuntu](#debian--ubuntu)
    + [Install from repository](#install-from-repository-not-recommended)
    + [Build deb package from source](#build-deb-package-from-source)
    + [Configure and start the service](#configure-and-start-the-service)
- [Fedora & RHEL](#fedora--rhel)
    + [Build from source with centos](#build-from-source-with-centos)
- [Archlinux & Manjaro](#archlinux--manjaro)
- [NixOS](#nixos)
- [Nix](#nix)
- [Directly build and install on UNIX-like system](#linux)
- [FreeBSD](#freebsd)
    + [Install](#install)
    + [Configuration](#configuration)
    + [Run](#run)
    + [Run as client](#run-as-client)
- [OpenWRT](#openwrt)
- [macOS](#macos)
- [Windows (MinGW)](#windows-mingw)

* * *

### Build from source (CMake)

The default build uses pinned sources included in this repository. It needs a
C11 compiler, CMake 3.20+, and Make or Ninja. No Git submodules, dependency
package installations, or network access are needed for configuration/build.
Python is used by tests; optional documentation builds require Doxygen 1.9.4+.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build -L 'unit|vendor' --output-on-failure
cmake --install build --prefix /your/install/prefix
```

Programs are in `build/bin/`. Bundled binaries link to platform runtime
libraries; they do not require separately installed third-party libraries.

Doxygen renders man pages and HTML documentation from CLI source comments. See [the documentation workflow](CONTRIBUTION.md#cli-and-manual-documentation)
for validation and rendering commands.

For a smaller build, use `-DSS_MINIMAL=ON`. It excludes PCRE2 regex, plugin
subprocesses and the manager. Minimal ACLs support
IPv4/IPv6 CIDRs, `full:example.com` for exact domains, and
`suffix:example.com` for the apex and subdomains. Literal matches ignore ASCII
case and respect label boundaries. Unsupported regex rules are rejected.

Distribution packages can use `-DSS_DEPENDENCY_MODE=system -DWITH_STATIC=OFF`
with libuv, c-ares, libsodium, Mbed TLS 3.x, and PCRE2 development packages.
Use `-DCMAKE_PREFIX_PATH=/opt/homebrew/opt/mbedtls@3` when needed on macOS.

| Option | Default | Purpose |
|---|---|---|
| `SS_DEPENDENCY_MODE` | `bundled` | `bundled` sources or `system` libraries |
| `WITH_STATIC` | `ON` | Link dependency archives; system mode also supports shared dependencies |
| `SS_BUILD_EXECUTABLES` | `ON` | Command-line tools |
| `SS_BUILD_STATIC_LIBRARY` | `ON` | Static embedding library with installed dependency archives |
| `SS_BUILD_SHARED_LIBRARY` | `ON` | Shared embedding library |
| `SS_MINIMAL` | `OFF` | Disable regex, plugins and manager |
| `SS_ENABLE_REGEX` / `SS_ENABLE_PLUGINS` | `ON` | Individual compatibility features |
| `WITH_DOC_MAN` / `WITH_DOC_HTML` | `OFF` | Generate documentation (requires Doxygen 1.9.4+) |
| `SS_INSTALL_TOOLS` | `OFF` | Install platform shell helpers |
| `ENABLE_SANITIZERS` | `OFF` | AddressSanitizer and UndefinedBehaviorSanitizer |
| `ENABLE_CONNMARKTOS` / `ENABLE_NFTABLES` | `OFF` | Optional Linux firewall integrations |

CMake consumers can use `find_package(shadowsocks-c CONFIG REQUIRED)` and
link `shadowsocks::static`, `shadowsocks::shared`, or `shadowsocks::shadowsocks`
(which prefers the shared library when installed). A pkg-config file is also
installed. Dependency provenance and update instructions are in
[third_party/README.md](third_party/README.md); modernization progress and
validation limits are tracked in [docs/modernization.md](docs/modernization.md).

### Debian & Ubuntu

#### Distribution packages

Package availability and versions depend on the distribution release; packaged
versions can differ from this source branch.

```bash
sudo apt update
sudo apt install shadowsocks-libev
```

#### Build deb package from source

Install the build dependencies listed in `debian/control`, then build the
packages from this checkout:

```bash
dpkg-buildpackage -b -us -uc
```

Debian packaging explicitly uses system libraries. For a bundled build without
library development packages, use the [CMake instructions](#build-from-source-cmake).

#### Configure and start the service

```
# Edit the configuration file
sudo vim /etc/shadowsocks-libev/config.json

# Edit the default configuration for debian
sudo vim /etc/default/shadowsocks-libev

# Start the service
sudo /etc/init.d/shadowsocks-libev start    # for sysvinit, or
sudo systemctl start shadowsocks-libev      # for systemd
```

### Fedora & RHEL

Use the bundled CMake build above with a C11 compiler, CMake 3.20+ and Make
or Ninja. Older distribution toolchains may need upgrading. Autotools, gettext
and separately installed crypto/event/DNS development libraries are not required
for bundled mode.

### Archlinux & Manjaro

```bash
sudo pacman -S shadowsocks-libev
```

Please refer to downstream [PKGBUILD](https://github.com/archlinux/svntogit-community/blob/packages/shadowsocks-libev/trunk/PKGBUILD)
script for extra modifications and distribution-specific bugs.

### NixOS

```bash
nix-env -iA nixos.shadowsocks-libev
```

### Nix

```bash
nix-env -iA nixpkgs.shadowsocks-libev
```

### Linux

The default bundled build needs only a C11 compiler, CMake 3.20+ and Make
or Ninja. For example, on Debian/Ubuntu:

```bash
sudo apt-get install --no-install-recommends build-essential cmake
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build -L 'unit|vendor' --output-on-failure
sudo cmake --install build
```

Distribution packagers can install `libpcre2-dev libuv1-dev libc-ares-dev
libmbedtls-dev libsodium-dev` and select `-DSS_DEPENDENCY_MODE=system
-DWITH_STATIC=OFF`. Documentation additionally needs Doxygen 1.9.4 or newer.

### FreeBSD
#### Install
Shadowsocks-libev is available in FreeBSD Ports Collection. You can install it in either way, `pkg` or `ports`.

**pkg (recommended)**

```bash
pkg install shadowsocks-libev
```

**ports**

```bash
cd /usr/ports/net/shadowsocks-libev
make install
```

#### Configuration
Edit your `config.json` file. By default, it's located in `/usr/local/etc/shadowsocks-libev`.

To enable shadowsocks-libev, add the following rc variable to your `/etc/rc.conf` file:

```
shadowsocks_libev_enable="YES"
```

#### Run

Start the Shadowsocks server:

```bash
service shadowsocks_libev start
```

#### Run as client
By default, shadowsocks-libev is running as a server in FreeBSD. If you would like to start shadowsocks-libev in client mode, you can modify the rc script (`/usr/local/etc/rc.d/shadowsocks_libev`) manually.

```
# modify the following line from "ss-server" to "ss-local"
command="/usr/local/bin/ss-local"
```

Note that is simply a workaround, each time you upgrade the port your changes will be overwritten by the new version.

### OpenWRT

The OpenWRT project is maintained here:
[openwrt-shadowsocks](https://github.com/shadowsocks/openwrt-shadowsocks).

### macOS

Use the bundled CMake instructions above with Xcode Command Line Tools and
CMake. The bundled executables require no Homebrew runtime libraries.
For system mode, use Mbed TLS 3 and point `CMAKE_PREFIX_PATH` at its prefix.

### Windows (MinGW)

In an MSYS2 UCRT64 shell, install the toolchain and build native Windows programs:

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja
cmake -S . -B build -G Ninja
cmake --build build --parallel
ctest --test-dir build -L 'unit|vendor' --output-on-failure
```

Unix hosts with Zig installed can cross-compile without a separate MinGW SDK:

```bash
cmake -S . -B build-windows -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/zig-windows.cmake
cmake --build build-windows --parallel
```

Cross-compilation does not run Windows tests. The portability workflow runs
native UCRT64 tests and TCP/UDP relay checks on Windows. Bundled mode is required
with a bundled libuv IOCP backend. MSVC remains a
separate, unsupported milestone; configuration reports this explicitly.
The historical Autotools scripts are superseded by this build.

## Usage

Clients accept a combined remote endpoint: `--server example.com:8388` or
`--server '[2001:db8::1]:8388'`. Repeat the flag for multiple servers. Legacy
`-s HOST -p PORT` remains supported; an embedded port takes priority.

For a detailed and complete list of all supported arguments,
you may refer to the man pages of the applications, respectively.

    ss-[local|server|tunnel|manager]

       -s <server_host>           Host name or IP address of your remote server.

       -p <server_port>           Port number of your remote server.

       -l <local_port>            Port number of your local server.

       -k <password>              Password of your remote server.

       -m <encrypt_method>        Encrypt method:
                                  2022-blake3-aes-128-gcm,
                                  2022-blake3-aes-256-gcm,
                                  2022-blake3-chacha20-poly1305,
                                  aes-128-gcm, aes-192-gcm, aes-256-gcm,
                                  chacha20-ietf-poly1305 and
                                  xchacha20-ietf-poly1305.
                                  The default cipher is chacha20-ietf-poly1305.

                                  The 2022-blake3-* ciphers implement
                                  Shadowsocks 2022 (SIP022) and are the
                                  recommended choice. They take a
                                  base64-encoded pre-shared key of exactly
                                  the cipher's key size via -k, not a
                                  password: generate one with
                                  `openssl rand -base64 32` (or 16 for
                                  2022-blake3-aes-128-gcm).

       [--server-url <ss_url>]    Take the server address, port, cipher,
                                  password and SIP003 plugin from a single
                                  ss:// URL (SIP002 or the legacy form).
                                  ss-local only. Options given later on the
                                  command line override the URL's values.

       [-a <user>]                Run as another user.

       [-f <pid_file>]            The file path to store pid.

       [-t <timeout>]             Socket timeout in seconds.

       [-c <config_file>]         The path to config file.

       [-n <number>]              Max number of open files.

       [-i <interface>]           Network interface to bind.

       [-b <local_address>]       Local address to bind.
                                  For servers: Specify the local address to use 
                                  while this server is making outbound 
                                  connections to remote servers on behalf of the
                                  clients.
                                  For clients: Specify the local address to use 
                                  while this client is making outbound 
                                  connections to the server.

       [-u]                       Enable UDP relay.

       [-U]                       Enable UDP relay and disable TCP relay.
                                  (not available in local mode)

       [-L <addr>:<port>]         Destination server address and port
                                  for local port forwarding.
                                  (only available in tunnel mode)

       [-6]                       Resolve hostname to IPv6 address first.

       [-d <addr>]                Name servers for internal DNS resolver.
                                  (only available in server mode)

       [--reuse-port]             Enable port reuse.

       [--fast-open]              Enable TCP fast open.
                                  with Linux kernel > 3.7.0.
                                  (only available in local and server mode)

       [--acl <acl_file>]         Path to ACL (Access Control List).
                                  (only available in local and server mode)

       [--manager-address <addr>] UNIX domain socket address.
                                  (only available in server and manager mode)

       [--control-socket <path>] Local read-only control socket queried by
                                  ssctl. (server mode)

       [--access-log]             Log authenticated connections with the
                                  SIP023 user ID, peer address and target.

       [--mtu <MTU>]              MTU of your network interface.

       [--mptcp]                  Enable Multipath TCP on MPTCP Kernel.

       [--no-delay]               Enable TCP_NODELAY.

       [--executable <path>]      Path to the executable of ss-server.
                                  (only available in manager mode)

       [-D <path>]                Path to the working directory of ss-manager.
                                  (only available in manager mode)

       [--key <key_in_base64>]    Key of your remote server.

       [--plugin <name>]          Enable SIP003 plugin. (Experimental)

       [--plugin-opts <options>]  Set SIP003 plugin options. (Experimental)

       [-v]                       Verbose mode.

## Helper Scripts

### ss-setup

`ss-setup` is an interactive TUI (text user interface) tool for setting up shadowsocks-libev server and client configurations. It uses `whiptail` or `dialog` for the menu interface.

It is installed automatically by `make install` and can also be run directly from `scripts/ss-setup.sh`.

**Prerequisites:** `whiptail` or `dialog`, `openssl` (optional, for password generation)

#### Server setup (with systemd service)

Run as root for full functionality (config + systemd service installation):

```bash
sudo ss-setup
```

This launches an interactive menu that walks you through:
1. Choosing a config instance name
2. Setting the listen address and port (manual or random high port)
3. Selecting an AEAD cipher (chacha20-ietf-poly1305, aes-256-gcm, etc.)
4. Generating or entering a password
5. Configuring timeout, network mode (TCP/UDP), and TCP Fast Open
6. Optionally selecting a SIP003 plugin
7. Installing and starting a systemd service

The config is saved to `/etc/shadowsocks-libev/<name>.json` and a systemd template service `shadowsocks-libev-server@<name>.service` is created.

At the end, it displays a `ss://` URI you can import into clients.

#### Client config generation

Select "Generate ss-local client config" from the main menu. The wizard prompts for the remote server address, port, cipher, password, and local SOCKS5 port, then writes a JSON config:

```bash
# Run without root to generate config in the current directory
ss-setup
# Select: client -> fill in server details -> save

# Then start the client
ss-local -c ~/ss-client.json
```

#### Config-only mode (non-root)

When run without root, `ss-setup` skips service installation and plugin management, but still generates config files in the current directory:

```bash
ss-setup
# Config saved to ./config.json (in current directory)
# Start manually:
ss-server -c ./config.json
```

#### Service management

From the main menu, select "Manage running services" to start, stop, restart, enable/disable, or view logs for any configured instance:

```
sudo ss-setup
# Select: service -> pick instance -> start/stop/restart/logs
```

#### Plugin installation

Select "Install a SIP003 plugin" from the main menu (requires root). Supports automatic download of:
- simple-obfs (build from source or package manager)
- v2ray-plugin (GitHub release)
- xray-plugin (GitHub release)
- kcptun (GitHub release)
- Custom plugin binary

## Security Tips

For any public server, to avoid users accessing localhost of your server, please add `--acl acl/server_block_local.acl` to the command line.

Although shadowsocks-libev can handle thousands of concurrent connections nicely, we still recommend
setting up your server's firewall rules to limit connections from each user:

    # Up to 32 connections are enough for normal usage
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKS_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## License

```
Copyright: 2013-2015, Clow Windy <clowwindy42@gmail.com>
           2013-2018, Max Lv <max.c.lv@gmail.com>
           2014, Linus Yang <linusyang@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```
