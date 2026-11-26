# SIP023 users and anonymous limits

`ss-server` can serve several SIP023 users and an anonymous fallback on one
port, with per-user counters and per-IP limits for anonymous clients.

## Server configuration

```json
{
  "server": "0.0.0.0",
  "server_port": 8388,
  "method": "2022-blake3-aes-256-gcm",
  "password": "BASE64_SERVER_PSK",

  "users": {
    "alice": "BASE64_ALICE_PSK",
    "bob":   "BASE64_BOB_PSK"
  },

  "anonymous_limits": {
    "max_tcp_connections_per_ip": 20,
    "max_udp_sessions_per_ip": 20,
    "preauth_connections_per_ip": 40,
    "upload_kbps_per_ip": 1024,
    "burst_kb": 2048,
    "ipv6_prefix": 64,
    "max_tracked_ips": 4096
  },

  "control_socket": "/run/shadowsocks-c/control.sock",
  "access_log": true,
  "require_identity": true
}
```

`users` requires `2022-blake3-aes-128-gcm` or `2022-blake3-aes-256-gcm`.
`2022-blake3-chacha20-poly1305` and the classic AEAD methods remain usable for
single-user or anonymous operation, but do not support SIP023 identity
headers. Anonymous limits are enabled when `users` is present or when the
`anonymous_limits` object is present.

Generate keys with:

```sh
openssl rand -base64 32   # 256-bit PSK (16 for the aes-128 method)
```

## Client configuration

An identified user sends the server PSK followed by the user PSK:

```sh
ss-local -s server -p 8388 -m 2022-blake3-aes-256-gcm \
  -k 'BASE64_SERVER_PSK:BASE64_ALICE_PSK'
```

An anonymous client sends only the server PSK:

```sh
ss-local -s server -p 8388 -m 2022-blake3-aes-256-gcm \
  -k 'BASE64_SERVER_PSK'
```

The user ID is never sent in plaintext. The server maps
`BLAKE3(user PSK)[0..16]` from the SIP023 identity header to the configured
name, so a client cannot claim another user's name without that user's PSK.
Multiple terminals can use the same user PSK; their counters are aggregated
under one user.

## Rejecting anonymous clients

By default, a client that sends only the server PSK is accepted as an
anonymous user. Set `"require_identity": true` to turn `users` into an
allowlist:

```json
{
  "method": "2022-blake3-aes-256-gcm",
  "password": "BASE64_SERVER_PSK",
  "users": {
    "alice": "BASE64_ALICE_PSK"
  },
  "require_identity": true
}
```

With this option, a TCP connection or UDP datagram without a known SIP023
identity is rejected. The server PSK is still part of the client password
(`SERVER_PSK:USER_PSK`), but it cannot be used on its own.

`require_identity` requires an AES-2022 method. An empty `users` object is
allowed and rejects every client until a user is added. It is a startup
option; changing it requires restarting the server.

## Users-only reload

The local control socket accepts a `reload` request. It rereads only the
`users` object from `config.json` and applies the difference in place:

```text
reload
```

- New users are available immediately.
- Removed users lose their identity and their active TCP/UDP sessions are
  closed immediately.
- A changed user PSK is treated as remove + add; the old identity and its
  sessions are dropped, and the client must use the new password.
- Unchanged users keep their counters and sessions.
- The `users` field must be present; an absent field is rejected, while an
  explicit `"users": {}` removes everyone.
- Changes to `server`, `server_port`, `method`, the server PSK, or
  `require_identity` are rejected with `restart_required`; restart the server
  for those.

The control socket remains mode `0600`. A node agent running as the same user
as `ss-server` writes `config.json` atomically and sends `reload`. `ssctl`
still exposes only the read-only query commands.

## Limits

Only anonymous connections are limited. Identified users are counted but not
rate-limited. IPv4 is keyed by `/32`; IPv6 is keyed by `ipv6_prefix`
(`/64` by default) so rotating addresses inside a prefix does not bypass the
limit. TCP throttling pauses reading from the client and relies on kernel
backpressure; UDP datagrams over the limit are dropped.

`upload_kbps_per_ip` is kilobits per second shared by anonymous TCP and UDP
traffic from one IP. A zero value disables the corresponding limit.

## Querying with ssctl

```sh
ssctl --socket /run/shadowsocks-c/control.sock users
ssctl --socket /run/shadowsocks-c/control.sock conns
ssctl --socket /run/shadowsocks-c/control.sock anon
ssctl --socket /run/shadowsocks-c/control.sock stats
ssctl --socket /run/shadowsocks-c/control.sock users --json
```

The control socket is a local Unix datagram socket. It is created with mode
`0600`; run `ssctl` as the same user (or root). The first `ssctl` release is
read-only.

`access_log` logs one line per authenticated connection:

```text
user=alice peer=203.0.113.5:51234 proto=tcp target=example.com:443
user=anonymous peer=203.0.113.6:41000 proto=udp
```

Failed handshakes log the peer address and reason, never a claimed user ID.
