/*
 * jconf.h - Define the config data structure
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _JCONF_H
#define _JCONF_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PORT_NUM 1024
#define MAX_REMOTE_NUM 10
#define MAX_DSCP_NUM 64
#define MAX_USER_NUM 64
#define MAX_USER_ID_LEN 64
#define MAX_CONF_SIZE (128 * 1024)
#define MAX_CONNECT_TIMEOUT 10
#define MIN_TCP_IDLE_TIMEOUT (24 * 3600)
#define MIN_UDP_TIMEOUT 10
/* Connections a TCP relay serves at once; more are refused. */
#define DEFAULT_MAX_CONNECTIONS 1024

#define DSCP_EF      0x2E
#define DSCP_MIN     0x0
#define DSCP_MAX     0x3F
#define DSCP_DEFAULT 0x0
#define DSCP_MIN_LEN 2
#define DSCP_MAX_LEN 4
#define DSCP_CS_LEN  3
#define DSCP_AF_LEN  4

#define TCP_ONLY     0
#define TCP_AND_UDP  1
#define UDP_ONLY     3

typedef struct {
    char *port;
    char *password;
} ss_port_password_t;

typedef struct {
    char *port;
    int dscp;
} ss_dscp_t;

typedef struct {
    char *id;
    char *key;
} ss_user_t;

typedef struct {
    int remote_num;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    int port_password_num;
    ss_port_password_t port_password[MAX_PORT_NUM];
    char *remote_port;
    char *local_addr;
    char *local_addr_v4;
    char *local_addr_v6;
    char *local_port;
    char *password;
    char *key;
    char *method;
    char *timeout;
    char *user;
    char *plugin;
    char *plugin_opts;
    int fast_open;
    int reuse_port;
    int tcp_incoming_sndbuf;
    int tcp_incoming_rcvbuf;
    int tcp_outgoing_sndbuf;
    int tcp_outgoing_rcvbuf;
    int nofile;
    char *nameserver;
    int dscp_num;
    ss_dscp_t dscp[MAX_DSCP_NUM];
    char *tunnel_address;
    int mode;
    int mtu;
    int mptcp;
    int ipv6_first;
    int no_delay;
    int max_connections;
    int max_udp_sessions;
    int max_dns_queries;
    int printable_salt;
    int user_num;
    ss_user_t users[MAX_USER_NUM];
    char *control_socket;
    int access_log;
    int require_identity;
    int anon_limits_set;
    int anon_max_tcp_connections;
    int anon_max_udp_sessions;
    int anon_preauth_connections;
    int anon_upload_kbps;
    int anon_burst_kb;
    int anon_ipv6_prefix;
    int anon_max_tracked_ips;
    char *workdir;
    char *acl;
    char *manager_address;
} jconf_t;

jconf_t *read_jconf(const char *file);

#define MAX_USER_PSK_LEN 256

typedef struct {
    char id[MAX_USER_ID_LEN + 1];
    char key[MAX_USER_PSK_LEN];
} ss_user_conf_t;

/* The fields a running server can compare before a users-only reload. */
typedef struct {
    int users_present;
    int user_num;
    ss_user_conf_t users[MAX_USER_NUM];
    char method[64];
    char password[MAX_USER_PSK_LEN];
    char key[MAX_USER_PSK_LEN];
    char server_port[16];
    int server_port_set;
    int require_identity;
    int require_identity_set;
} ss_users_conf_t;

/*
 * Parse the fields needed by a users-only reload without touching the static
 * arena used by read_jconf(). Returns 0 on success and -1 with a message in
 * `error`.
 */
int read_jconf_users(const char *file, ss_users_conf_t *out, char *error, size_t error_size);

void parse_addr(const char *str, ss_addr_t *addr);
void free_addr(ss_addr_t *addr);
int parse_server_endpoint(const char *str, ss_addr_t *addr);
int complete_server_ports(ss_addr_t *addr, int count, const char *fallback, int plugin);

#ifdef __cplusplus
}
#endif

#endif // _JCONF_H
