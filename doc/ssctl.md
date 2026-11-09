\page ssctl ssctl

\brief query a running ss-server through its local control socket

\section ssctl_synopsis SYNOPSIS

`ssctl [--socket <path>] [--json] <command>`

\section ssctl_description DESCRIPTION

*ssctl* sends one read-only request to the Unix datagram control socket
enabled by `ss-server --control-socket`. It prints the response as a table by
default, or as JSON with `--json`.

Commands are `users`, `conns`, `anon` and `stats`. The control socket is
created with mode `0600`; run *ssctl* as the same user as *ss-server* (or as
root).

\section ssctl_options OPTIONS

`-s <path>`, `--socket <path>`
:   Control socket path. The default is `/run/shadowsocks-c/control.sock`.

`--json`
:   Print the response as JSON.

`-h`, `--help`
:   Show usage.

\section ssctl_see_also SEE ALSO

ss-server(1), shadowsocks-libev(8)
