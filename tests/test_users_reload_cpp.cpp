/* SPDX-License-Identifier: GPL-3.0-or-later */
// SIP023 user slots and the users-only config parser used by reload.

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

#include <sodium.h>

#include "test_helpers.hpp"

#include "crypto/aead2022.hpp"
#include "netutils.h"
#include "jconf.h"
#include "relay/codec.hpp"
#include "relay/users.hpp"

namespace {

void
make_psk(char *out, std::size_t size)
{
    std::array<unsigned char, 32> key{};
    randombytes_buf(key.data(), key.size());
    SS_CHECK(sodium_bin2base64(out, size, key.data(), key.size(), sodium_base64_VARIANT_ORIGINAL) != nullptr);
}

std::string
make_template(const char *server_psk, const char *users, const char *extra)
{
    std::string text = "{\n";
    text += "  \"method\": \"2022-blake3-aes-256-gcm\",\n";
    text += "  \"password\": \"";
    text += server_psk;
    text += "\",\n";
    text += "  \"users\": ";
    text += users;
    text += ",\n";
    if (extra != nullptr) {
        text += extra;
        text += ",\n";
    }
    text += "  \"server\": \"127.0.0.1\",\n";
    text += "  \"server_port\": 8388\n";
    text += "}\n";
    return text;
}

void
write_file(const char *path, const std::string &text)
{
    FILE *f = fopen(path, "wb");
    SS_CHECK(f != nullptr);
    SS_CHECK(fwrite(text.data(), 1, text.size(), f) == text.size());
    fclose(f);
}

void
test_method_user_slots()
{
    char server_psk[128];
    char user1[128];
    char user2[128];
    char user3[128];
    make_psk(server_psk, sizeof(server_psk));
    make_psk(user1, sizeof(user1));
    make_psk(user2, sizeof(user2));
    make_psk(user3, sizeof(user3));

    ss::relay::Method method;
    SS_CHECK(method.init("2022-blake3-aes-256-gcm", server_psk, nullptr, ss::crypto::Role::server));
    SS_CHECK(method.user_count() == 0);
    SS_CHECK(method.user_slots() == 0);

    auto a = method.add_user("u00001", user1);
    SS_CHECK(a.has_value());
    SS_CHECK(*a == 0);
    auto b = method.add_user("u00002", user2);
    SS_CHECK(b.has_value());
    SS_CHECK(*b == 1);
    SS_CHECK(method.user_count() == 2);
    SS_CHECK(method.user_slots() == 2);
    SS_CHECK(method.user_active(0));
    SS_CHECK(method.user_active(1));

    const auto *key = method.user_key(0);
    SS_CHECK(key != nullptr);
    std::array<std::uint8_t, ss::crypto::kIdentityLen> hash{};
    ss::crypto::identity_hash_16(*key, hash);
    std::uint8_t found = 0xFF;
    SS_CHECK(method.identity_table()->find(hash, found) != nullptr);
    SS_CHECK(found == 0);

    auto removed = method.remove_user("u00001");
    SS_CHECK(removed.has_value());
    SS_CHECK(*removed == 0);
    SS_CHECK(method.user_count() == 1);
    SS_CHECK(method.user_slots() == 2);
    SS_CHECK(!method.user_active(0));
    SS_CHECK(method.user_active(1));
    found = 0xFF;
    SS_CHECK(method.identity_table()->find(hash, found) == nullptr);

    // A retired slot keeps its key until release, then it is reusable.
    SS_CHECK(method.user_key(0) != nullptr);
    SS_CHECK(method.release_user(0));
    SS_CHECK(method.user_key(0) == nullptr);
    SS_CHECK(method.user_slots() == 2);

    auto c = method.add_user("u00003", user3);
    SS_CHECK(c.has_value());
    SS_CHECK(*c == 0);
    SS_CHECK(method.user_count() == 2);
    SS_CHECK(method.user_slots() == 2);
    SS_CHECK(method.user_active(0));

    // Same id with a new PSK is remove + add; the old slot stays retired.
    auto old = method.remove_user("u00003");
    SS_CHECK(old.has_value());
    auto fresh = method.add_user("u00003", user1);
    SS_CHECK(fresh.has_value());
    SS_CHECK(*fresh == 2);
    SS_CHECK(method.user_count() == 2);
    SS_CHECK(method.user_slots() == 3);
    SS_CHECK(!method.user_active(0));
    SS_CHECK(std::strcmp(method.user_id(0), "u00003") == 0);
    SS_CHECK(std::strcmp(method.user_id(2), "u00003") == 0);
}

void
test_read_jconf_users()
{
    char server_psk[128];
    char user1[128];
    char user2[128];
    make_psk(server_psk, sizeof(server_psk));
    make_psk(user1, sizeof(user1));
    make_psk(user2, sizeof(user2));

    char path[] = "/tmp/ss-users-reload-XXXXXX";
    int fd      = mkstemp(path);
    SS_CHECK(fd >= 0);
    close(fd);

    char users[512];
    snprintf(users, sizeof(users), "{\"u00001\":\"%s\",\"u00002\":\"%s\"}", user1, user2);
    std::string text = make_template(server_psk, users, "  \"require_identity\": true");
    write_file(path, text);

    ss_users_conf_t conf{};
    char error[256] = {};
    SS_CHECK(read_jconf_users(path, &conf, error, sizeof(error)) == 0);
    SS_CHECK(conf.users_present == 1);
    SS_CHECK(conf.user_num == 2);
    SS_CHECK(conf.require_identity_set == 1);
    SS_CHECK(conf.require_identity == 1);
    SS_CHECK(conf.server_port_set == 1);
    SS_CHECK(std::strcmp(conf.server_port, "8388") == 0);
    SS_CHECK(std::strcmp(conf.method, "2022-blake3-aes-256-gcm") == 0);
    SS_CHECK(std::strcmp(conf.password, server_psk) == 0);
    SS_CHECK(std::strcmp(conf.users[0].id, "u00001") == 0);
    SS_CHECK(std::strcmp(conf.users[1].id, "u00002") == 0);
    SS_CHECK(std::strcmp(conf.users[0].key, user1) == 0);

    // An absent users field must not silently wipe the table.
    write_file(path, make_template(server_psk, "null", nullptr));
    error[0] = '\0';
    SS_CHECK(read_jconf_users(path, &conf, error, sizeof(error)) != 0);
    SS_CHECK(std::strstr(error, "users") != nullptr);

    // An explicit empty object is a valid "remove all" request.
    write_file(path, make_template(server_psk, "{}", nullptr));
    SS_CHECK(read_jconf_users(path, &conf, error, sizeof(error)) == 0);
    SS_CHECK(conf.users_present == 1);
    SS_CHECK(conf.user_num == 0);

    // More than MAX_USER_NUM entries are rejected instead of truncated.
    std::string too_many = "{";
    for (int i = 0; i < MAX_USER_NUM + 1; ++i) {
        char entry[192];
        snprintf(entry, sizeof(entry), "%s\"u%05d\":\"%s\"", i == 0 ? "" : ",", i, user1);
        too_many += entry;
    }
    too_many += "}";
    write_file(path, make_template(server_psk, too_many.c_str(), nullptr));
    error[0] = '\0';
    SS_CHECK(read_jconf_users(path, &conf, error, sizeof(error)) != 0);
    SS_CHECK(std::strstr(error, "too many") != nullptr);

    unlink(path);
}

} // namespace

int
main()
{
    SS_CHECK(sodium_init() >= 0);
    SS_RUN(test_method_user_slots);
    SS_RUN(test_read_jconf_users);
    return 0;
}
