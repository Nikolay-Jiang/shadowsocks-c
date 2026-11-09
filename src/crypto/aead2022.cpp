/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "crypto/aead2022.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>

#include <mbedtls/aes.h>
#include <sodium.h>

#include "blake3/blake3.h"
#include "crypto/keys.hpp"

namespace ss::crypto {

namespace {

constexpr Aead2022Spec kSpecs[] = {
    { "2022-blake3-aes-128-gcm", { "2022-blake3-aes-128-gcm", AeadKind::aes_128_gcm, 16, 12, 16 } },
    { "2022-blake3-aes-256-gcm", { "2022-blake3-aes-256-gcm", AeadKind::aes_256_gcm, 32, 12, 16 } },
    { "2022-blake3-chacha20-poly1305",
      { "2022-blake3-chacha20-poly1305", AeadKind::chacha20_poly1305, 32, 12, 16 } },
};

constexpr char kSubkeyContext[]     = "shadowsocks 2022 session subkey";
constexpr char kIdentityContext[]   = "shadowsocks 2022 identity subkey";

constexpr std::uint8_t kTypeClient = 0;
constexpr std::uint8_t kTypeServer = 1;
constexpr std::size_t kLenSize     = 2;
constexpr std::size_t kReqFixed    = 1 + 8 + 2;             // type, timestamp, length
constexpr std::size_t kUdpMinHdr   = 1 + 8 + 2;             // type, timestamp, padding length
constexpr std::size_t kMaxFixed    = kReqFixed + kMaxKey;   // response: + request salt

std::size_t resp_fixed(std::size_t salt_len) noexcept
{
    return kReqFixed + salt_len;
}

void store16_be(std::uint8_t *p, std::uint16_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}

std::uint16_t load16_be(const std::uint8_t *p) noexcept
{
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

void store64_be(std::uint8_t *p, std::uint64_t v) noexcept
{
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<std::uint8_t>(v & 0xff);
        v >>= 8;
    }
}

std::uint64_t load64_be(const std::uint8_t *p) noexcept
{
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

std::uint64_t unix_now() noexcept
{
    return static_cast<std::uint64_t>(std::time(nullptr));
}

bool timestamp_ok(std::uint64_t ts, std::uint64_t now) noexcept
{
    std::uint64_t diff = now > ts ? now - ts : ts - now;
    return diff <= k2022TimeSkew;
}

// Length of the SOCKS address (type, address, port) at the head of `buf`, or
// 0 if it is malformed or truncated.
std::size_t socks_addr_len(std::span<const std::uint8_t> buf) noexcept
{
    if (buf.empty()) {
        return 0;
    }
    std::size_t len = 0;
    switch (buf[0]) { // exactly 1, 3 or 4, as the SOCKS parser reads it
    case 1:
        len = 1 + 4;
        break;
    case 4:
        len = 1 + 16;
        break;
    case 3:
        if (buf.size() < 2) {
            return 0;
        }
        len = 2 + buf[1];
        break;
    default:
        return 0;
    }
    return buf.size() >= len + 2 ? len + 2 : 0;
}

std::size_t chunks_cost(std::size_t n) noexcept
{
    std::size_t chunks = (n + k2022MaxChunk - 1) / k2022MaxChunk;
    return n + chunks * (kLenSize + 2 * kTag);
}

// AES-ECB over the 16-byte separate header, keyed with the PSK.
Status sep_header(const Psk &psk, std::uint8_t *dst, const std::uint8_t *src, bool encrypt) noexcept
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    unsigned bits = static_cast<unsigned>(psk.size() * 8);
    int rc        = encrypt ? mbedtls_aes_setkey_enc(&aes, psk.bytes.data(), bits)
                            : mbedtls_aes_setkey_dec(&aes, psk.bytes.data(), bits);
    if (rc == 0) {
        rc = mbedtls_aes_crypt_ecb(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, src, dst);
    }
    mbedtls_aes_free(&aes);
    if (rc != 0) {
        return fail(Errc::crypto);
    }
    return {};
}

// AES-ECB over one 16-byte block with an arbitrary AES key (the identity
// subkey for TCP, or the identity PSK itself for UDP).
Status aes_ecb_block(std::span<const std::uint8_t> key, std::uint8_t *dst, const std::uint8_t *src,
                     bool encrypt) noexcept
{
    if (key.size() != 16 && key.size() != 32) {
        return fail(Errc::crypto);
    }
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    unsigned bits = static_cast<unsigned>(key.size() * 8);
    int rc        = encrypt ? mbedtls_aes_setkey_enc(&aes, key.data(), bits)
                            : mbedtls_aes_setkey_dec(&aes, key.data(), bits);
    if (rc == 0) {
        rc = mbedtls_aes_crypt_ecb(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, src, dst);
    }
    mbedtls_aes_free(&aes);
    if (rc != 0) {
        return fail(Errc::crypto);
    }
    return {};
}

// TCP SIP023 identity header: AES-ECB(identity_subkey, hash(user PSK)), where
// identity_subkey is BLAKE3-derived from the identity PSK and the request salt.
Status identity_tcp_block(const Psk &identity, const Psk &user, std::span<const std::uint8_t> salt,
                          std::uint8_t block[kIdentityLen], bool encrypt) noexcept
{
    if (identity.chacha() || identity.size() != salt.size()) {
        return fail(Errc::protocol);
    }
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, kIdentityContext);
    blake3_hasher_update(&hasher, identity.key().data(), identity.size());
    blake3_hasher_update(&hasher, salt.data(), salt.size());
    std::array<std::uint8_t, kMaxKey> subkey{};
    blake3_hasher_finalize(&hasher, subkey.data(), subkey.size());
    sodium_memzero(&hasher, sizeof(hasher));

    std::array<std::uint8_t, kIdentityLen> hash{};
    std::array<std::uint8_t, kIdentityLen> result{};
    if (encrypt) {
        identity_hash_16(user, hash);
    }
    Status st = aes_ecb_block({ subkey.data(), identity.size() }, result.data(),
                              encrypt ? hash.data() : block, encrypt);
    if (st) {
        std::memcpy(block, result.data(), result.size());
    }
    sodium_memzero(subkey.data(), subkey.size());
    sodium_memzero(hash.data(), hash.size());
    sodium_memzero(result.data(), result.size());
    return st;
}

// UDP SIP023 identity header: AES-ECB(identity PSK, hash(user PSK) XOR
// session_id || packet_id).
void identity_udp_mask(std::span<const std::uint8_t> separate,
                       std::array<std::uint8_t, kIdentityLen> &block) noexcept
{
    for (std::size_t i = 0; i < kIdentityLen && i < separate.size(); ++i) {
        block[i] ^= separate[i];
    }
}

void window_reset(UdpSession2022 &s, const std::array<std::uint8_t, kSessionIdLen> &id, std::uint64_t packet) noexcept
{
    s.rx_id = id;
    s.rx_window.fill(0);
    // Packet 0 is legitimate for a fresh session.
    s.rx_highest = packet > 0 ? packet - 1 : 0;
    s.rx_ready   = true;
}

bool window_check(const UdpSession2022 &s, std::uint64_t id) noexcept
{
    if (id > s.rx_highest) {
        return true;
    }
    if (s.rx_highest - id >= kUdpWindowBits) {
        return false;
    }
    std::uint64_t bit = id % kUdpWindowBits;
    return (s.rx_window[bit / 8] & (1U << (bit % 8))) == 0;
}

void window_update(UdpSession2022 &s, std::uint64_t id) noexcept
{
    if (id > s.rx_highest) {
        std::uint64_t shift = id - s.rx_highest;
        if (shift >= kUdpWindowBits) {
            s.rx_window.fill(0);
        } else {
            for (std::uint64_t i = s.rx_highest + 1; i <= id; ++i) {
                std::uint64_t b = i % kUdpWindowBits;
                s.rx_window[b / 8] &= static_cast<std::uint8_t>(~(1U << (b % 8)));
            }
        }
        s.rx_highest = id;
    }
    std::uint64_t bit = id % kUdpWindowBits;
    s.rx_window[bit / 8] |= static_cast<std::uint8_t>(1U << (bit % 8));
}

std::size_t udp_header_len(Role sender) noexcept
{
    return kUdpMinHdr + (sender == Role::server ? kSessionIdLen : 0);
}

} // namespace

std::optional<Aead2022Spec> find_aead2022(std::string_view name) noexcept
{
    for (const Aead2022Spec &spec : kSpecs) {
        if (spec.name == name) {
            return spec;
        }
    }
    return std::nullopt;
}

Result<Psk> Psk::from_base64(const Aead2022Spec &spec, const char *key) noexcept
{
    if (key == nullptr) {
        return fail(Errc::config);
    }
    Psk psk{ spec, {} };
    if (!parse_key(key, { psk.bytes.data(), spec.aead.key_len }, true)) {
        return fail(Errc::config);
    }
    return psk;
}

void derive_subkey_2022(std::span<const std::uint8_t> psk, std::span<const std::uint8_t> salt,
                        std::span<std::uint8_t> subkey) noexcept
{
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, kSubkeyContext);
    blake3_hasher_update(&hasher, psk.data(), psk.size());
    blake3_hasher_update(&hasher, salt.data(), salt.size());
    blake3_hasher_finalize(&hasher, subkey.data(), subkey.size());
    sodium_memzero(&hasher, sizeof(hasher));
}

void identity_hash_16(const Psk &psk, std::array<std::uint8_t, kIdentityLen> &out) noexcept
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, psk.key().data(), psk.size());
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    sodium_memzero(&hasher, sizeof(hasher));
}

Status IdentityTable::reserve(std::uint32_t capacity, std::uint64_t seed) noexcept
{
    if (capacity == 0 || capacity > kMaxIdentityUsers) {
        return fail(Errc::invalid);
    }
    return index_.reserve(capacity, seed);
}

Status IdentityTable::add(std::span<const std::uint8_t> hash, const Psk &key, std::uint8_t index) noexcept
{
    if (hash.size() != kIdentityLen || index >= kMaxIdentityUsers || used_[index]) {
        return fail(Errc::invalid);
    }
    auto fixed = FixedKey<kIdentityLen>::from(as_bytes(hash.data(), hash.size()));
    if (!fixed) {
        return fail(Errc::invalid);
    }
    auto inserted = index_.emplace(*fixed, index);
    if (!inserted) {
        return fail(inserted.error());
    }
    keys_[index] = key;
    used_[index] = true;
    return {};
}

const Psk *IdentityTable::find(std::span<const std::uint8_t> hash, std::uint8_t &index) const noexcept
{
    if (hash.size() != kIdentityLen) {
        return nullptr;
    }
    auto fixed = FixedKey<kIdentityLen>::from(as_bytes(hash.data(), hash.size()));
    if (!fixed) {
        return nullptr;
    }
    const std::uint8_t *found = index_.find(*fixed);
    if (found == nullptr || *found >= kMaxIdentityUsers || !used_[*found]) {
        return nullptr;
    }
    index = *found;
    return &keys_[*found];
}

const Psk *IdentityTable::key(std::uint8_t index) const noexcept
{
    return index < kMaxIdentityUsers && used_[index] ? &keys_[index] : nullptr;
}

bool SaltPool::check_and_add(std::span<const std::uint8_t> salt, std::uint64_t now) noexcept
{
    auto key = FixedKey<kMaxKey>::from(std::as_bytes(salt));
    if (!key) {
        return false;
    }
    // Forget salts older than the retention period; they are oldest first.
    while (const std::uint64_t *first = seen_.oldest()) {
        if (*first + k2022SaltTtl > now) {
            break;
        }
        (void)seen_.pop_oldest();
    }
    if (seen_.peek(*key) != nullptr) {
        return false;
    }
    if (seen_.full()) {
        // Every remembered salt is still inside the replay window: forgetting
        // one would let its request be replayed, so refuse the new one.
        return false;
    }
    return seen_.emplace(*key, now).has_value();
}

Status Aead2022TcpEncryptor::init(const Psk &psk, Role role, const Aead2022TcpDecryptor *request,
                                  const Psk *identity) noexcept
{
    if (role == Role::server && request == nullptr) {
        return fail(Errc::invalid);
    }
    if (identity != nullptr && (psk.chacha() || identity->chacha() || psk.spec.aead.key_len != identity->size())) {
        return fail(Errc::config);
    }
    psk_         = psk;
    role_        = role;
    peer_        = request;
    identity_    = identity;
    header_sent_ = false;
    nonce_.fill(0);
    randombytes_buf(salt_.data(), psk.size());
    std::array<std::uint8_t, kMaxKey> subkey{};
    derive_subkey_2022(psk.key(), salt(), { subkey.data(), psk.size() });
    Status st = engine_.init(psk.spec.aead, { subkey.data(), psk.size() });
    sodium_memzero(subkey.data(), subkey.size());
    return st;
}

std::size_t Aead2022TcpEncryptor::sealed_size(std::size_t plaintext_len) const noexcept
{
    if (header_sent_) {
        return chunks_cost(plaintext_len);
    }
    // salt, optional identity header, fixed header and its tag, the
    // header/first chunk tag, padding.
    std::size_t identity = role_ == Role::client && identity_ != nullptr ? kIdentityLen : 0;
    return psk_.size() + identity + kMaxFixed + kTag + kLenSize + k2022MaxPad + kTag + chunks_cost(plaintext_len);
}

Result<std::size_t> Aead2022TcpEncryptor::seal_one(std::span<const std::uint8_t> plaintext, std::uint8_t *out) noexcept
{
    SS_TRY(engine_.seal(out, plaintext, nonce_.data()));
    sodium_increment(nonce_.data(), psk_.spec.aead.nonce_len);
    return plaintext.size() + kTag;
}

Result<std::size_t> Aead2022TcpEncryptor::seal_chunks(std::span<const std::uint8_t> plaintext, std::uint8_t *out) noexcept
{
    std::size_t at = 0;
    while (!plaintext.empty()) {
        std::size_t n = std::min(plaintext.size(), k2022MaxChunk);
        std::uint8_t len[kLenSize];
        store16_be(len, static_cast<std::uint16_t>(n));
        SS_TRY_ASSIGN(w, seal_one(len, out + at));
        at += w;
        SS_TRY_ASSIGN(p, seal_one(plaintext.first(n), out + at));
        at += p;
        plaintext = plaintext.subspan(n);
    }
    return at;
}

Result<std::size_t> Aead2022TcpEncryptor::seal(std::span<const std::uint8_t> plaintext,
                                               std::span<std::uint8_t> out) noexcept
{
    if (plaintext.empty()) {
        return std::size_t{ 0 };
    }
    if (out.size() < sealed_size(plaintext.size())) {
        return fail(Errc::invalid);
    }
    if (header_sent_) {
        return seal_chunks(plaintext, out.data());
    }

    const std::size_t salt_len = psk_.size();
    std::uint8_t fixed[kMaxFixed];
    std::size_t fixed_len = 0;
    std::size_t at        = salt_len;
    std::memcpy(out.data(), salt_.data(), salt_len);
    std::span<const std::uint8_t> rest;

    if (role_ == Role::client) {
        if (identity_ != nullptr) {
            Status st = identity_tcp_block(*identity_, psk_, salt(), out.data() + at, true);
            if (!st) {
                return fail(st.error().code);
            }
            at += kIdentityLen;
        }
        std::size_t addr_len = socks_addr_len(plaintext);
        if (addr_len == 0) {
            return fail(Errc::protocol);
        }
        auto payload    = plaintext.subspan(addr_len);
        std::size_t now = std::min(payload.size(), k2022MaxChunk - addr_len - kLenSize);
        std::uint16_t pad = 0;
        if (payload.empty()) {
            // SIP022 requires padding when no payload follows the address.
            pad = static_cast<std::uint16_t>(randombytes_uniform(k2022MaxPad) + 1);
        }
        std::size_t body_len = addr_len + kLenSize + pad + now;
        fixed[0]             = kTypeClient;
        store64_be(fixed + 1, unix_now());
        store16_be(fixed + 9, static_cast<std::uint16_t>(body_len));
        fixed_len = kReqFixed;
        SS_TRY_ASSIGN(f, seal_one({ fixed, fixed_len }, out.data() + at));
        at += f;
        // Assemble the header body in place and encrypt it there.
        std::uint8_t *body = out.data() + at;
        std::memcpy(body, plaintext.data(), addr_len);
        store16_be(body + addr_len, pad);
        if (pad != 0) {
            randombytes_buf(body + addr_len + kLenSize, pad);
        }
        if (now != 0) {
            std::memcpy(body + addr_len + kLenSize + pad, payload.data(), now);
        }
        SS_TRY_ASSIGN(b, seal_one({ body, body_len }, body));
        at += b;
        rest = payload.subspan(now);
    } else {
        if (peer_ == nullptr || !peer_->header_received()) {
            return fail(Errc::protocol); // nothing to answer yet
        }
        std::size_t now = std::min(plaintext.size(), k2022MaxChunk);
        fixed[0]        = kTypeServer;
        store64_be(fixed + 1, unix_now());
        std::memcpy(fixed + 9, peer_->salt().data(), salt_len);
        store16_be(fixed + 9 + salt_len, static_cast<std::uint16_t>(now));
        fixed_len = resp_fixed(salt_len);
        SS_TRY_ASSIGN(f, seal_one({ fixed, fixed_len }, out.data() + at));
        at += f;
        SS_TRY_ASSIGN(b, seal_one(plaintext.first(now), out.data() + at));
        at += b;
        rest = plaintext.subspan(now);
    }
    header_sent_ = true;
    SS_TRY_ASSIGN(tail, seal_chunks(rest, out.data() + at));
    return at + tail;
}

Status Aead2022TcpDecryptor::init(const Psk &psk, Role role, std::span<const std::uint8_t> request_salt,
                                  SaltPool *pool, const IdentityTable *identities) noexcept
{
    if (role == Role::client && request_salt.size() != psk.size()) {
        return fail(Errc::invalid);
    }
    psk_       = psk;
    base_psk_  = psk;
    role_      = role;
    pool_      = pool;
    identities_ = identities;
    stage_     = role == Role::server && !psk.chacha() && identities != nullptr ? Stage::identity : Stage::fixed;
    failed_    = false;
    want_      = 0;
    plain_     = 0;
    skip_      = 0;
    user_index_       = kAnonymousIdentity;
    identity_resolved_ = stage_ == Stage::fixed;
    header_received_   = false;
    nonce_.fill(0);
    request_salt_.fill(0);
    if (!request_salt.empty()) {
        std::memcpy(request_salt_.data(), request_salt.data(), request_salt.size());
    }
    buffer_.clear();
    engine_.reset();
    return {};
}

Result<Aead2022TcpDecryptor::Step> Aead2022TcpDecryptor::decrypt(std::span<const std::uint8_t> in,
                                                                  std::span<std::uint8_t> out) noexcept
{
    if (failed_) {
        return fail(Errc::closed);
    }
    Step step{ 0, 0 };
    if (buffer_.writable().size() < in.size()) {
        buffer_.compact();
    }
    std::size_t take = std::min(in.size(), buffer_.writable().size());
    if (take != 0) {
        std::memcpy(buffer_.writable().data(), in.data(), take);
        (void)buffer_.commit(take);
        step.consumed = take;
    }
    auto bytes = [this]() {
        auto r = buffer_.readable();
        return std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(r.data()), r.size());
    };
    auto broken = [this](Errc code) {
        failed_ = true;
        return fail(code);
    };
    // Chunks are opened in place: the plaintext ends up at the front of the
    // buffer, followed by the tag (and for a request header the padding),
    // which is skipped once the plaintext has been handed out.
    auto open = [this](std::span<std::uint8_t> chunk) {
        bool ok = static_cast<bool>(engine_.open(chunk.data(), chunk, nonce_.data()));
        if (ok) {
            sodium_increment(nonce_.data(), psk_.spec.aead.nonce_len);
        }
        return ok;
    };
    const std::size_t salt_len = psk_.size();

    for (;;) {
        if (plain_ != 0) {
            std::size_t n = std::min(plain_, out.size() - step.produced);
            if (n == 0) {
                return step;
            }
            std::memcpy(out.data() + step.produced, bytes().data(), n);
            (void)buffer_.consume(n);
            plain_ -= n;
            step.produced += n;
            if (plain_ != 0) {
                return step;
            }
        }
        if (skip_ != 0) {
            (void)buffer_.consume(skip_);
            skip_ = 0;
        }
        auto data = bytes();
        switch (stage_) {
        case Stage::identity: {
            // A server may read an optional SIP023 identity header between
            // the salt and the first AEAD chunk. Try the one known identity
            // layer; a miss means this is an anonymous request and those
            // bytes are part of the chunk.
            if (data.size() < salt_len + kIdentityLen) {
                return step;
            }
            std::array<std::uint8_t, kMaxKey> salt_buf{};
            std::memcpy(salt_buf.data(), data.data(), salt_len);
            std::array<std::uint8_t, kIdentityLen> block{};
            std::memcpy(block.data(), data.data() + salt_len, block.size());
            Status st = identity_tcp_block(base_psk_, base_psk_, { salt_buf.data(), salt_len }, block.data(), false);
            if (!st) {
                return broken(st.error().code);
            }
            std::uint8_t index = kAnonymousIdentity;
            const Psk *user    = identities_->find(block, index);
            if (user != nullptr) {
                psk_        = *user;
                user_index_ = index;
                // Drop salt + identity header, then put the salt back for
                // the fixed-header stage, which still expects it in front.
                (void)buffer_.consume(salt_len + kIdentityLen);
                if (!buffer_.prepend(as_bytes(salt_buf.data(), salt_len))) {
                    return broken(Errc::crypto);
                }
            } else {
                psk_        = base_psk_;
                user_index_ = kAnonymousIdentity;
            }
            identity_resolved_ = true;
            stage_             = Stage::fixed;
            break;
        }
        case Stage::fixed: {
            // A server reads requests; a client reads responses.
            std::size_t fixed_len = role_ == Role::server ? kReqFixed : resp_fixed(salt_len);
            if (data.size() < salt_len + fixed_len + kTag) {
                return step;
            }
            std::memcpy(salt_.data(), data.data(), salt_len);
            std::array<std::uint8_t, kMaxKey> subkey{};
            derive_subkey_2022(psk_.key(), salt(), { subkey.data(), salt_len });
            Status st = engine_.init(psk_.spec.aead, { subkey.data(), salt_len });
            sodium_memzero(subkey.data(), subkey.size());
            if (!st) {
                return broken(st.error().code);
            }
            std::uint8_t *fixed = data.data() + salt_len;
            if (!open(data.subspan(salt_len, fixed_len + kTag))) {
                return broken(Errc::crypto);
            }
            std::uint64_t now = unix_now();
            if (fixed[0] != (role_ == Role::server ? kTypeClient : kTypeServer)
                || !timestamp_ok(load64_be(fixed + 1), now)) {
                return broken(Errc::protocol);
            }
            if (role_ == Role::client) {
                if (sodium_memcmp(fixed + 9, request_salt_.data(), salt_len) != 0) {
                    return broken(Errc::crypto);
                }
                want_ = load16_be(fixed + 9 + salt_len);
            } else {
                // Only authentic salts enter the pool.
                if (pool_ != nullptr && !pool_->check_and_add(salt(), now)) {
                    return broken(Errc::crypto);
                }
                want_ = load16_be(fixed + 9);
            }
            if (want_ == 0) {
                return broken(Errc::protocol);
            }
            (void)buffer_.consume(salt_len + fixed_len + kTag);
            header_received_ = true;
            stage_           = Stage::variable;
            break;
        }
        case Stage::variable: {
            if (data.size() < want_ + kTag) {
                return step;
            }
            if (!open(data.first(want_ + kTag))) {
                return broken(Errc::crypto);
            }
            stage_ = Stage::length;
            if (role_ == Role::client) {
                plain_ = want_; // the first response payload
                skip_  = kTag;
                break;
            }
            std::uint8_t *hdr    = data.data();
            std::size_t addr_len = socks_addr_len(data.first(want_));
            if (addr_len == 0 || want_ < addr_len + kLenSize) {
                return broken(Errc::protocol);
            }
            std::size_t pad = load16_be(hdr + addr_len);
            std::size_t off = addr_len + kLenSize + pad;
            if (pad > k2022MaxPad || off > want_) {
                return broken(Errc::protocol);
            }
            std::size_t payload = want_ - off;
            if (payload == 0 && pad == 0) {
                return broken(Errc::protocol); // SIP022: neither payload nor padding
            }
            std::memmove(hdr + addr_len, hdr + off, payload);
            plain_ = addr_len + payload;
            skip_  = want_ - plain_ + kTag;
            break;
        }
        case Stage::length: {
            if (data.size() < kLenSize + kTag) {
                return step;
            }
            if (!open(data.first(kLenSize + kTag))) {
                return broken(Errc::crypto);
            }
            want_ = load16_be(data.data());
            if (want_ == 0) {
                return broken(Errc::protocol);
            }
            (void)buffer_.consume(kLenSize + kTag);
            stage_ = Stage::payload;
            break;
        }
        case Stage::payload: {
            if (data.size() < want_ + kTag) {
                return step;
            }
            if (!open(data.first(want_ + kTag))) {
                return broken(Errc::crypto);
            }
            plain_ = want_;
            skip_  = kTag;
            stage_ = Stage::length;
            break;
        }
        }
    }
}

UdpSession2022::~UdpSession2022()
{
    sodium_memzero(tx_subkey.data(), tx_subkey.size());
}

std::size_t udp2022_overhead(const Psk &psk, Role role, bool with_identity) noexcept
{
    std::size_t prefix = psk.chacha() ? kUdpXNonce + kUdpSepHeader : kUdpSepHeader;
    if (with_identity && !psk.chacha()) {
        prefix += kIdentityLen;
    }
    return prefix + udp_header_len(role) + kTag;
}

Result<std::size_t> udp2022_seal(const Psk &psk, Role role, UdpSession2022 &session,
                                 std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out,
                                 const Psk *identity) noexcept
{
    if (identity != nullptr && (psk.chacha() || identity->chacha() || identity->size() != psk.size())) {
        return fail(Errc::config);
    }
    const std::size_t total = udp2022_overhead(psk, role, identity != nullptr) + plaintext.size();
    if (out.size() < total) {
        return fail(Errc::invalid);
    }
    if (role == Role::server && !session.peer_known) {
        return fail(Errc::protocol); // no client session to reply to
    }
    if (!session.tx_ready) {
        randombytes_buf(session.tx_id.data(), kSessionIdLen);
        session.tx_packet = 0;
        if (!psk.chacha()) {
            derive_subkey_2022(psk.key(), session.tx_id, { session.tx_subkey.data(), psk.size() });
        }
        session.tx_ready = true;
    }

    std::uint8_t sep[kUdpSepHeader];
    std::memcpy(sep, session.tx_id.data(), kSessionIdLen);
    store64_be(sep + kSessionIdLen, session.tx_packet);

    // The body (main header + payload) is assembled where its ciphertext
    // goes and encrypted in place; for ChaCha the separate header is part
    // of the encrypted body.
    std::size_t prefix = psk.chacha() ? kUdpXNonce + kUdpSepHeader : kUdpSepHeader;
    if (identity != nullptr) {
        prefix += kIdentityLen;
    }
    std::uint8_t *body = out.data() + prefix;
    std::size_t o      = 0;
    body[o++]          = role == Role::server ? kTypeServer : kTypeClient;
    store64_be(body + o, unix_now());
    o += 8;
    if (role == Role::server) {
        std::memcpy(body + o, session.peer_id.data(), kSessionIdLen);
        o += kSessionIdLen;
    }
    store16_be(body + o, 0); // no padding
    o += kLenSize;
    std::memmove(body + o, plaintext.data(), plaintext.size());
    std::size_t body_len = o + plaintext.size();

    if (psk.chacha()) {
        std::uint8_t *nonce = out.data();
        randombytes_buf(nonce, kUdpXNonce);
        std::uint8_t *merged = nonce + kUdpXNonce;
        std::memcpy(merged, sep, kUdpSepHeader);
        unsigned long long clen = 0;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(merged, &clen, merged, kUdpSepHeader + body_len, nullptr, 0,
                                                       nullptr, nonce, psk.bytes.data())
            != 0) {
            return fail(Errc::crypto);
        }
    } else {
        const Psk &sep_key = identity != nullptr ? *identity : psk;
        SS_TRY(sep_header(sep_key, out.data(), sep, true));
        if (identity != nullptr) {
            std::array<std::uint8_t, kIdentityLen> block{};
            identity_hash_16(psk, block);
            identity_udp_mask({ sep, kUdpSepHeader }, block);
            SS_TRY(aes_ecb_block(identity->key(), out.data() + kUdpSepHeader, block.data(), true));
            sodium_memzero(block.data(), block.size());
        }
        AeadEngine engine;
        SS_TRY(engine.init(psk.spec.aead, { session.tx_subkey.data(), psk.size() }));
        SS_TRY(engine.seal(body, { body, body_len }, sep + 4));
    }
    ++session.tx_packet;
    return total;
}

Result<Udp2022Packet> udp2022_decrypt(const Psk &psk, std::span<const std::uint8_t> packet,
                                      std::span<std::uint8_t> out, const IdentityTable *identities) noexcept
{
    if (out.size() < packet.size()) {
        return fail(Errc::invalid);
    }
    Udp2022Packet result{};
    if (psk.chacha()) {
        if (packet.size() <= kUdpXNonce + kUdpSepHeader + kTag) {
            return fail(Errc::protocol);
        }
        unsigned long long plen = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &plen, nullptr, packet.data() + kUdpXNonce,
                                                       packet.size() - kUdpXNonce, nullptr, 0, packet.data(),
                                                       psk.bytes.data())
            != 0) {
            return fail(Errc::crypto);
        }
        std::memcpy(result.session_id.data(), out.data(), kSessionIdLen);
        result.packet_id = load64_be(out.data() + kSessionIdLen);
        result.body_len  = static_cast<std::size_t>(plen) - kUdpSepHeader;
        std::memmove(out.data(), out.data() + kUdpSepHeader, result.body_len);
        return result;
    }
    if (packet.size() <= kUdpSepHeader + kTag) {
        return fail(Errc::protocol);
    }
    std::uint8_t sep[kUdpSepHeader];
    SS_TRY(sep_header(psk, sep, packet.data(), false));
    std::memcpy(result.session_id.data(), sep, kSessionIdLen);
    result.packet_id = load64_be(sep + kSessionIdLen);

    std::size_t identity_len = 0;
    const Psk *traffic      = &psk;
    if (identities != nullptr && packet.size() >= kUdpSepHeader + kIdentityLen + kTag) {
        std::array<std::uint8_t, kIdentityLen> block{};
        SS_TRY(aes_ecb_block(psk.key(), block.data(), packet.data() + kUdpSepHeader, false));
        identity_udp_mask({ sep, kUdpSepHeader }, block);
        std::uint8_t index     = kAnonymousIdentity;
        const Psk *user        = identities->find(block, index);
        sodium_memzero(block.data(), block.size());
        if (user != nullptr) {
            traffic              = user;
            result.user_index    = index;
            identity_len         = kIdentityLen;
        }
    }

    std::array<std::uint8_t, kMaxKey> subkey{};
    derive_subkey_2022(traffic->key(), result.session_id, { subkey.data(), psk.size() });
    AeadEngine engine;
    Status st = engine.init(psk.spec.aead, { subkey.data(), psk.size() });
    sodium_memzero(subkey.data(), subkey.size());
    SS_TRY(st);
    SS_TRY(engine.open(out.data(), packet.subspan(kUdpSepHeader + identity_len), sep + 4));
    result.body_len = packet.size() - kUdpSepHeader - identity_len - kTag;
    return result;
}

Result<std::size_t> udp2022_accept(Role role, UdpSession2022 &session, const Udp2022Packet &packet,
                                   std::span<std::uint8_t> out, std::uint64_t now) noexcept
{
    // We receive what the other role sent.
    const Role sender  = role == Role::server ? Role::client : Role::server;
    const std::size_t n = packet.body_len;
    if (n < udp_header_len(sender) || out.size() < n) {
        return fail(Errc::protocol);
    }
    const std::uint8_t *body = out.data();
    if (body[0] != (sender == Role::server ? kTypeServer : kTypeClient) || !timestamp_ok(load64_be(body + 1), now)) {
        return fail(Errc::protocol);
    }
    std::size_t o = 9;
    if (role == Role::client) {
        // The server echoes our session ID.
        if (!session.tx_ready || std::memcmp(body + o, session.tx_id.data(), kSessionIdLen) != 0) {
            return fail(Errc::protocol);
        }
        o += kSessionIdLen;
    }
    std::size_t pad = load16_be(body + o);
    o += kLenSize;
    if (pad > k2022MaxPad || o + pad > n) {
        return fail(Errc::protocol);
    }
    o += pad;

    if (session.rx_ready && session.rx_id != packet.session_id) {
        // Keep the current window as the previous one, or bring the previous
        // one back for a late packet of that session.
        bool back = session.prev_ready && session.prev_id == packet.session_id;
        std::swap(session.rx_id, session.prev_id);
        std::swap(session.rx_highest, session.prev_highest);
        std::swap(session.rx_window, session.prev_window);
        std::swap(session.rx_ready, session.prev_ready);
        if (!back) {
            session.rx_ready = false;
        }
    }
    if (!session.rx_ready) {
        window_reset(session, packet.session_id, packet.packet_id);
    } else if (!window_check(session, packet.packet_id)) {
        return fail(Errc::crypto); // replayed
    }
    window_update(session, packet.packet_id);
    if (role == Role::server) {
        session.peer_id    = packet.session_id;
        session.peer_known = true;
    }
    std::memmove(out.data(), out.data() + o, n - o);
    return n - o;
}

} // namespace ss::crypto
