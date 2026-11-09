/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CRYPTO_AEAD2022_HPP
#define SS_CRYPTO_AEAD2022_HPP

// Shadowsocks 2022 (SIP022) as value types.
//
// Replaces aead2022.cpp / aead2022_udp.cpp, which allocate a temporary
// header body per stream, a chunk buffer per connection, an Mbed TLS cipher
// context per UDP packet and a session object per UDP conversation. Here
// the stream codecs hold one fixed reassembly buffer, a UDP packet is
// sealed or opened entirely on the stack, and UDP sessions are plain values
// whose storage the caller provides (a pool slot in the relay).
//
// SIP022 is asymmetric: a client encrypts requests and decrypts responses,
// a server does the opposite, and the response header echoes the request
// salt. The two directions of one connection are therefore linked: the
// server's encryptor reads the salt its decryptor received, and the client's
// decryptor checks the echo against the salt its encryptor sent.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "core/buffer.hpp"
#include "core/fixed_map.hpp"
#include "core/result.hpp"
#include "crypto/aead.hpp"

namespace ss::crypto {

enum class Role : std::uint8_t { client, server };

inline constexpr std::size_t k2022MaxChunk  = 0xFFFF; // payload bytes per TCP chunk
inline constexpr std::size_t k2022MaxPad    = 900;
inline constexpr std::size_t k2022TimeSkew  = 30;  // seconds either way
inline constexpr std::size_t k2022SaltTtl   = 60;  // seconds a TCP salt is remembered
inline constexpr std::size_t kSessionIdLen  = 8;
inline constexpr std::size_t kUdpSepHeader  = 16; // session ID + packet ID
inline constexpr std::size_t kUdpXNonce     = 24;
inline constexpr std::size_t kUdpWindowBits = 256;
inline constexpr std::size_t kIdentityLen   = 16; // SIP023 identity hash
inline constexpr std::size_t kMaxIdentityUsers = 64;
inline constexpr std::uint8_t kAnonymousIdentity = 0xFF;

struct Aead2022Spec {
    std::string_view name;
    AeadSpec aead; // the TCP / AES-UDP body cipher
};

std::optional<Aead2022Spec> find_aead2022(std::string_view name) noexcept;

// The pre-shared key. SIP022 forbids password derivation.
struct Psk {
    Aead2022Spec spec;
    std::array<std::uint8_t, kMaxKey> bytes{};

    Psk() noexcept = default;
    Psk(const Aead2022Spec &s, const std::array<std::uint8_t, kMaxKey> &b) noexcept : spec(s), bytes(b) {}
    Psk(const Psk &) noexcept            = default;
    Psk &operator=(const Psk &) noexcept = default;
    ~Psk() { sodium_memzero(bytes.data(), bytes.size()); }

    std::size_t size() const noexcept { return spec.aead.key_len; }
    std::span<const std::uint8_t> key() const noexcept { return { bytes.data(), size() }; }
    bool chacha() const noexcept { return spec.aead.kind == AeadKind::chacha20_poly1305; }

    static Result<Psk> from_base64(const Aead2022Spec &spec, const char *key) noexcept;
};

// blake3::derive_key("shadowsocks 2022 session subkey", psk || salt).
void derive_subkey_2022(std::span<const std::uint8_t> psk, std::span<const std::uint8_t> salt,
                        std::span<std::uint8_t> subkey) noexcept;

// SIP023: blake3(psk)[0..16], the identity a server can map to a user.
void identity_hash_16(const Psk &psk, std::array<std::uint8_t, kIdentityLen> &out) noexcept;

// SIP023 identity table: hash(user PSK) -> user index. The keys stay here so
// the relay only needs to keep the index it hands to its statistics table.
class IdentityTable {
public:
    IdentityTable() noexcept = default;
    IdentityTable(const IdentityTable &)            = delete;
    IdentityTable &operator=(const IdentityTable &) = delete;

    Status reserve(std::uint32_t capacity, std::uint64_t seed) noexcept;
    Status add(std::span<const std::uint8_t> hash, const Psk &key, std::uint8_t index) noexcept;
    const Psk *find(std::span<const std::uint8_t> hash, std::uint8_t &index) const noexcept;
    const Psk *key(std::uint8_t index) const noexcept;
    std::uint32_t size() const noexcept { return index_.size(); }

private:
    FixedHashMap<FixedKey<kIdentityLen>, std::uint8_t> index_;
    std::array<Psk, kMaxIdentityUsers> keys_{};
    std::array<bool, kMaxIdentityUsers> used_{};
};

// Exact-match TCP salt replay protection for servers (SIP022 forbids bloom
// filters): every salt seen in the last k2022SaltTtl seconds.
class SaltPool {
public:
    Status reserve(std::uint32_t capacity, std::uint64_t seed) noexcept { return seen_.reserve(capacity, seed); }
    // False if the salt was seen within the retention period; otherwise
    // remembers it.
    bool check_and_add(std::span<const std::uint8_t> salt, std::uint64_t now) noexcept;
    std::uint32_t size() const noexcept { return seen_.size(); }

private:
    FixedLru<FixedKey<kMaxKey>, std::uint64_t> seen_; // salt -> time first seen
};

class Aead2022TcpDecryptor;

class Aead2022TcpEncryptor {
public:
    // A server encryptor answers the request its `request` decryptor read.
    // A client with `identity` set writes an SIP023 identity header using
    // that base PSK before the request body.
    Status init(const Psk &psk, Role role, const Aead2022TcpDecryptor *request = nullptr,
                const Psk *identity = nullptr) noexcept;

    // Upper bound of the bytes seal() writes for `plaintext_len` input.
    std::size_t sealed_size(std::size_t plaintext_len) const noexcept;

    // Encrypt into `out` (at least sealed_size() bytes). A client's first
    // plaintext must start with the SOCKS target address; it becomes the
    // request header, padded when no payload follows. A server's first call
    // writes the response header. Returns the bytes written.
    Result<std::size_t> seal(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out) noexcept;

    std::span<const std::uint8_t> salt() const noexcept { return { salt_.data(), psk_.size() }; }

private:
    Result<std::size_t> seal_chunks(std::span<const std::uint8_t> plaintext, std::uint8_t *out) noexcept;
    Result<std::size_t> seal_one(std::span<const std::uint8_t> plaintext, std::uint8_t *out) noexcept;

    Psk psk_{};
    Role role_                         = Role::client;
    const Aead2022TcpDecryptor *peer_  = nullptr;
    const Psk *identity_               = nullptr;
    AeadEngine engine_;
    std::array<std::uint8_t, kMaxKey> salt_{};
    std::array<std::uint8_t, kMaxNonce> nonce_{};
    bool header_sent_ = false;
};

class Aead2022TcpDecryptor {
public:
    Aead2022TcpDecryptor() noexcept = default;
    Aead2022TcpDecryptor(const Aead2022TcpDecryptor &) = delete;
    Aead2022TcpDecryptor &operator=(const Aead2022TcpDecryptor &) = delete;
    // Chunks are decrypted in place: the buffer held plaintext.
    ~Aead2022TcpDecryptor() { sodium_memzero(buffer_.storage().data(), buffer_.storage().size()); }

    // A client decryptor checks the response echoes `request_salt`; a server
    // decryptor rejects salts already in `pool` (which may be null in tests).
    // `identities` enables SIP023 identity headers on an AES server.
    Status init(const Psk &psk, Role role, std::span<const std::uint8_t> request_salt = {},
                SaltPool *pool = nullptr, const IdentityTable *identities = nullptr) noexcept;

    struct Step {
        std::size_t consumed;
        std::size_t produced;
    };

    // Take up to accept_limit() bytes of `in`, decrypt complete chunks in
    // place and copy as much plaintext as fits into `out` (any size). Call
    // again with an empty input to collect the rest. A server's first
    // output is the SOCKS target address followed by the initial payload,
    // with the padding removed.
    Result<Step> decrypt(std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept;

    std::size_t accept_limit() const noexcept { return buffer_.capacity() - buffer_.size(); }
    bool header_received() const noexcept { return header_received_; }
    bool identity_resolved() const noexcept { return identity_resolved_; }
    // The traffic key selected by the identity header (the base key for an
    // anonymous client).
    const Psk &selected_key() const noexcept { return psk_; }
    std::uint8_t selected_user() const noexcept { return user_index_; }
    std::span<const std::uint8_t> salt() const noexcept { return { salt_.data(), psk_.size() }; }
    std::size_t pending() const noexcept { return buffer_.size(); }

private:
    enum class Stage : std::uint8_t { identity, fixed, variable, length, payload };

    Psk psk_{};
    Psk base_psk_{};
    Role role_      = Role::server;
    SaltPool *pool_ = nullptr;
    const IdentityTable *identities_ = nullptr;
    AeadEngine engine_;
    std::array<std::uint8_t, kMaxKey> salt_{};
    std::array<std::uint8_t, kMaxKey> request_salt_{};
    std::array<std::uint8_t, kMaxNonce> nonce_{};
    // The largest unit is a full 64 KiB chunk plus its tag.
    FixedBuffer<k2022MaxChunk + kTag + 64> buffer_;
    std::size_t want_  = 0; // plaintext length of the next variable/payload chunk
    std::size_t plain_ = 0; // decrypted bytes at the front of buffer_ not yet handed out
    std::size_t skip_  = 0; // bytes after them to drop (tag, padding) once they are
    Stage stage_       = Stage::fixed;
    std::uint8_t user_index_ = kAnonymousIdentity;
    bool identity_resolved_  = false;
    bool header_received_    = false;
    bool failed_             = false;
};

// One end of a UDP conversation: our outgoing session and the replay window
// of the peer session we hear from. Callers own the storage.
struct UdpSession2022 {
    std::array<std::uint8_t, kSessionIdLen> tx_id{};
    std::uint64_t tx_packet = 0;
    std::array<std::uint8_t, kMaxKey> tx_subkey{};
    bool tx_ready = false;

    std::array<std::uint8_t, kSessionIdLen> rx_id{};
    std::uint64_t rx_highest = 0;
    std::array<std::uint8_t, kUdpWindowBits / 8> rx_window{};
    bool rx_ready = false;

    // The peer session heard from before rx_id, so a peer that starts a new
    // session cannot have its old packets replayed into a fresh window.
    std::array<std::uint8_t, kSessionIdLen> prev_id{};
    std::uint64_t prev_highest = 0;
    std::array<std::uint8_t, kUdpWindowBits / 8> prev_window{};
    bool prev_ready = false;

    // Server side: the client session ID replies are addressed to.
    std::array<std::uint8_t, kSessionIdLen> peer_id{};
    bool peer_known = false;

    ~UdpSession2022();
};

// Encrypt [SOCKS address][payload] into one packet; returns its length.
// `out` must hold udp2022_overhead() more bytes than the plaintext. A client
// that passes `identity` writes an SIP023 identity header.
Result<std::size_t> udp2022_seal(const Psk &psk, Role role, UdpSession2022 &session,
                                 std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out,
                                 const Psk *identity = nullptr) noexcept;

// Receiving is two steps, because a server finds the session by the ID
// inside the packet: decrypt authenticates the packet into `out` (at least
// as large as the packet) and names its session, then accept checks the
// header and replay window against that session and leaves
// [SOCKS address][payload] at the start of `out`, returning its length.
struct Udp2022Packet {
    std::array<std::uint8_t, kSessionIdLen> session_id;
    std::uint64_t packet_id;
    std::size_t body_len;
    std::uint8_t user_index = kAnonymousIdentity;
};
// `identities` enables SIP023 identity headers on an AES server. The returned
// packet names the selected user (kAnonymousIdentity when no identity header
// matched, or on a client decrypting a response).
Result<Udp2022Packet> udp2022_decrypt(const Psk &psk, std::span<const std::uint8_t> packet,
                                      std::span<std::uint8_t> out,
                                      const IdentityTable *identities = nullptr) noexcept;
Result<std::size_t> udp2022_accept(Role role, UdpSession2022 &session, const Udp2022Packet &packet,
                                   std::span<std::uint8_t> out, std::uint64_t now) noexcept;
std::size_t udp2022_overhead(const Psk &psk, Role role, bool with_identity = false) noexcept;

} // namespace ss::crypto

#endif
