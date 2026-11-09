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
  "access_log": true
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
