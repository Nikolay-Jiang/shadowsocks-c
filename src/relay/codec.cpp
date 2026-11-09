/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "relay/codec.hpp"

#include <algorithm>
#include <cstring>

#include <sodium.h>

#include "crypto/keys.hpp"
#include "ppbloom.h"
#include "utils.h"

namespace ss::relay {

namespace {

// Ping-pong bloom filter sizing, as in the C implementation.
constexpr int kBloomEntriesServer   = 1000000;
constexpr double kBloomErrorServer  = 1e-10;
constexpr int kBloomEntriesClient   = 10000;
constexpr double kBloomErrorClient  = 1e-15;

} // namespace

Status Method::init(const char *method, const char *password, const char *key, Role role) noexcept
{
    if (method == nullptr) {
        return fail(Errc::config);
    }
    if (sodium_init() == -1) {
        return fail(Errc::crypto);
    }
    role_ = role;
    // The salt/IV replay filter shared by every connection and datagram.
    if (!bloom_ready_) {
        int err = role == Role::server ? ppbloom_init(kBloomEntriesServer, kBloomErrorServer)
                                       : ppbloom_init(kBloomEntriesClient, kBloomErrorClient);
        if (err != 0) {
            LOGE("failed to set up the replay filter");
            return fail(Errc::exhausted);
        }
        bloom_ready_ = true;
    }
    if (auto spec = crypto::find_aead2022(method)) {
        const char *secret = key != nullptr ? key : password;
        if (secret == nullptr) {
            return fail(Errc::config);
        }
        // A SIP023 client password is "base PSK:user PSK". The base PSK is
        // the identity key; the user PSK is the traffic key. A server takes
        // the base PSK here and gets user keys from add_user().
        const char *colon = role == Role::client ? std::strchr(secret, ':') : nullptr;
        if (colon != nullptr) {
            constexpr std::size_t kMaxPskText = 128;
            char base[kMaxPskText];
            char user[kMaxPskText];
            std::size_t base_len = static_cast<std::size_t>(colon - secret);
            std::size_t user_len = std::strlen(colon + 1);
            if (base_len == 0 || base_len >= kMaxPskText || user_len == 0 || user_len >= kMaxPskText) {
                return fail(Errc::config);
            }
            std::memcpy(base, secret, base_len);
            base[base_len] = '\0';
            std::memcpy(user, colon + 1, user_len + 1);
            auto base_psk = crypto::Psk::from_base64(*spec, base);
            auto user_psk = crypto::Psk::from_base64(*spec, user);
            if (!base_psk || !user_psk) {
                crypto::report_bad_key("pre-shared key", spec->aead.key_len);
                return fail(Errc::config);
            }
            key_         = *user_psk;
            identity_psk_ = *base_psk;
            return {};
        }
        // The password field may carry the base64 PSK too.
        auto psk = crypto::Psk::from_base64(*spec, secret);
        if (!psk) {
            crypto::report_bad_key("pre-shared key", spec->aead.key_len);
            return fail(psk.error());
        }
        if (role == Role::server && !psk->chacha()) {
            SS_TRY(identities_.reserve(crypto::kMaxIdentityUsers, randombytes_random()));
        }
        key_ = *psk;
        return {};
    }
    if (auto spec = crypto::find_aead(method)) {
        if (key != nullptr) {
            auto master = crypto::MasterKey::from_base64(*spec, key);
            if (!master) {
                crypto::report_bad_key("key", spec->key_len);
                return fail(master.error());
            }
            key_ = *master;
        } else {
            SS_TRY_ASSIGN(master, crypto::MasterKey::from_password(*spec, password));
            key_ = master;
        }
        return {};
    }
    // The unauthenticated stream ciphers (and RC4/table before them) were
    // removed; say so instead of calling the name unknown.
    static constexpr const char *kRemoved[] = {
        "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
        "aes-256-ctr", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb",
        "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "salsa20", "chacha20", "chacha20-ietf",
    };
    for (const char *name : kRemoved) {
        if (std::strcmp(name, method) == 0) {
            LOGE("stream cipher %s is no longer supported; use an AEAD method such as chacha20-ietf-poly1305 "
                 "or 2022-blake3-aes-256-gcm",
                 method);
            return fail(Errc::config);
        }
    }
    LOGE("unsupported method: %s", method);
    return fail(Errc::config);
}

Method::~Method()
{
    if (bloom_ready_) {
        ppbloom_free();
    }
}

Status Method::add_user(const char *id, const char *key) noexcept
{
    if (role_ != Role::server || id == nullptr || key == nullptr || !is_2022_aes()
        || user_count_ >= crypto::kMaxIdentityUsers) {
        return fail(Errc::config);
    }
    std::size_t id_len = std::strlen(id);
    if (id_len == 0 || id_len >= sizeof(users_[0].id)) {
        return fail(Errc::config);
    }
    const crypto::Psk *base = psk();
    if (base == nullptr) {
        return fail(Errc::config);
    }
    auto user = crypto::Psk::from_base64(base->spec, key);
    if (!user) {
        crypto::report_bad_key("user pre-shared key", base->spec.aead.key_len);
        return fail(Errc::config);
    }
    std::array<std::uint8_t, crypto::kIdentityLen> hash{};
    crypto::identity_hash_16(*user, hash);
    auto index = static_cast<std::uint8_t>(user_count_);
    SS_TRY(identities_.add(hash, *user, index));
    std::memcpy(users_[index].id, id, id_len + 1);
    users_[index].used = true;
    ++user_count_;
    return {};
}

const char *Method::user_id(std::uint8_t index) const noexcept
{
    return index < user_count_ && users_[index].used ? users_[index].id : "";
}

Status Encoder::init(Method &method, bool plain, const Decoder *peer, bool printable_salt) noexcept
{
    if (plain) {
        impl_.emplace<Plain>();
        return {};
    }
    const crypto::ReplayFilter filter = crypto::ReplayFilter::ppbloom();
    if (auto *master = std::get_if<crypto::MasterKey>(&method.key_)) {
        return impl_.emplace<crypto::AeadTcpEncryptor>().init(*master, filter, printable_salt);
    }
    if (auto *psk = std::get_if<crypto::Psk>(&method.key_)) {
        const crypto::Aead2022TcpDecryptor *request = peer != nullptr ? peer->as_2022() : nullptr;
        if (method.role_ == Role::server) {
            if (request == nullptr || !request->identity_resolved()) {
                return fail(Errc::invalid);
            }
            return impl_.emplace<crypto::Aead2022TcpEncryptor>().init(request->selected_key(), Role::server, request,
                                                                      nullptr);
        }
        return impl_.emplace<crypto::Aead2022TcpEncryptor>().init(*psk, Role::client, request,
                                                                  method.identity_psk());
    }
    return fail(Errc::config);
}

// Explicit dispatch: std::visit can report bad_variant_access through the
// C++ runtime, which the programs do not link.
std::size_t Encoder::sealed_size(std::size_t plaintext_len) const noexcept
{
    if (auto *e = std::get_if<crypto::AeadTcpEncryptor>(&impl_)) {
        return e->sealed_size(plaintext_len);
    }
    if (auto *e = std::get_if<crypto::Aead2022TcpEncryptor>(&impl_)) {
        return e->sealed_size(plaintext_len);
    }
    return plaintext_len;
}

Result<std::size_t> Encoder::seal(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out) noexcept
{
    if (auto *e = std::get_if<crypto::AeadTcpEncryptor>(&impl_)) {
        return e->seal(plaintext, out);
    }
    if (auto *e = std::get_if<crypto::Aead2022TcpEncryptor>(&impl_)) {
        return e->seal(plaintext, out);
    }
    if (out.size() < plaintext.size()) {
        return fail(Errc::invalid);
    }
    if (!plaintext.empty()) {
        std::memcpy(out.data(), plaintext.data(), plaintext.size());
    }
    return plaintext.size();
}

std::span<const std::uint8_t> Encoder::salt_2022() const noexcept
{
    if (auto *e = std::get_if<crypto::Aead2022TcpEncryptor>(&impl_)) {
        return e->salt();
    }
    return {};
}

Status Decoder::init(Method &method, bool plain, const Encoder *peer) noexcept
{
    if (plain) {
        impl_.emplace<Plain>();
        return {};
    }
    const crypto::ReplayFilter filter = crypto::ReplayFilter::ppbloom();
    if (auto *master = std::get_if<crypto::MasterKey>(&method.key_)) {
        return impl_.emplace<crypto::AeadTcpDecryptor>().init(*master, filter);
    }
    if (auto *psk = std::get_if<crypto::Psk>(&method.key_)) {
        if (method.role_ == Role::client) {
            if (peer == nullptr) {
                return fail(Errc::invalid);
            }
            return impl_.emplace<crypto::Aead2022TcpDecryptor>().init(*psk, Role::client, peer->salt_2022());
        }
        return impl_.emplace<crypto::Aead2022TcpDecryptor>().init(*psk, Role::server, {}, &method.salt_pool_,
                                                                   method.identity_table());
    }
    return fail(Errc::config);
}

std::uint8_t Decoder::selected_user() const noexcept
{
    if (auto *d = std::get_if<crypto::Aead2022TcpDecryptor>(&impl_)) {
        return d->selected_user();
    }
    return crypto::kAnonymousIdentity;
}

const crypto::Psk *Decoder::selected_key() const noexcept
{
    if (auto *d = std::get_if<crypto::Aead2022TcpDecryptor>(&impl_)) {
        return &d->selected_key();
    }
    return nullptr;
}

bool Decoder::header_received() const noexcept
{
    if (auto *d = std::get_if<crypto::Aead2022TcpDecryptor>(&impl_)) {
        return d->header_received();
    }
    return true;
}

std::size_t Decoder::accept_limit() const noexcept
{
    if (auto *d = std::get_if<crypto::AeadTcpDecryptor>(&impl_)) {
        return d->accept_limit();
    }
    if (auto *d = std::get_if<crypto::Aead2022TcpDecryptor>(&impl_)) {
        return d->accept_limit();
    }
    return SIZE_MAX; // plain decodes as much as there is room for
}

Result<Decoder::Step> Decoder::decrypt(std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept
{
    auto convert = [](auto step) -> Result<Step> {
        if (!step) {
            return fail(step.error());
        }
        return Step{ step->consumed, step->produced };
    };
    if (auto *d = std::get_if<crypto::AeadTcpDecryptor>(&impl_)) {
        return convert(d->decrypt(in, out));
    }
    if (auto *d = std::get_if<crypto::Aead2022TcpDecryptor>(&impl_)) {
        return convert(d->decrypt(in, out));
    }
    std::size_t n = std::min(in.size(), out.size());
    if (n != 0) {
        std::memcpy(out.data(), in.data(), n);
    }
    return Step{ n, n };
}


} // namespace ss::relay
