#include "Client.hpp"
#include "Math/Setup.h"
#include "Math/Z2k.h"
#include "Math/Z2k.hpp"
#include "Math/gfp.h"
#include "Math/gfp.hpp"
#include "Math/bigint.h"
#include "Tools/int.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using std::cerr;
using std::cout;
using std::runtime_error;
using std::string;
using std::vector;

namespace {

constexpr uint8_t RECORD_TYPE_CHANGE_CIPHER_SPEC = 20;
constexpr uint8_t RECORD_TYPE_HANDSHAKE = 22;
constexpr uint8_t RECORD_TYPE_APPLICATION_DATA = 23;

constexpr int MAX_REC_WORDS = 320;
constexpr int MAX_APP_WORDS = 128;
constexpr int RESP_CT_BYTES = MAX_APP_WORDS * 8 - 21;
constexpr int MAX_HS_RECORDS = 5;
constexpr int MAX_RESP_RECORDS = 2;

constexpr uint16_t TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;
constexpr uint16_t TLS_AES_128_GCM_SHA256 = 0x1301;
constexpr uint16_t X25519 = 0x001D;

constexpr uint16_t EXT_SERVER_NAME = 0x0000;
constexpr uint16_t EXT_SUPPORTED_GROUPS = 0x000A;
constexpr uint16_t EXT_SIGNATURE_ALGORITHMS = 0x000D;
constexpr uint16_t EXT_ALPN = 0x0010;
constexpr uint16_t EXT_SUPPORTED_VERSIONS = 0x002B;
constexpr uint16_t EXT_KEY_SHARE = 0x0033;

void log(const string& s)
{
    cerr << "[otls-external-io] " << s << "\n";
}

template<class T>
void append_u16_be(T& out, uint16_t v)
{
    out.push_back((v >> 8) & 0xff);
    out.push_back(v & 0xff);
}

template<class T>
void append_u24_be(T& out, uint32_t v)
{
    out.push_back((v >> 16) & 0xff);
    out.push_back((v >> 8) & 0xff);
    out.push_back(v & 0xff);
}

int connect_tcp(const string& host, int port)
{
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0)
        throw runtime_error("getaddrinfo failed: " + string(gai_strerror(rc)));

    int fd = -1;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next)
    {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        throw runtime_error("unable to connect to " + host + ":" + std::to_string(port));
    return fd;
}

bool wait_readable(int fd, double timeout_sec)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    timeval tv {};
    tv.tv_sec = (int) timeout_sec;
    tv.tv_usec = (int) ((timeout_sec - tv.tv_sec) * 1e6);
    int rc = select(fd + 1, &rfds, nullptr, nullptr, &tv);
    return rc > 0 && FD_ISSET(fd, &rfds);
}

void send_all(int fd, const uint8_t* data, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t rc = send(fd, data + sent, len - sent, 0);
        if (rc <= 0)
            throw runtime_error("send failed");
        sent += rc;
    }
}

void recv_exact(int fd, uint8_t* data, size_t len)
{
    size_t got = 0;
    while (got < len)
    {
        ssize_t rc = recv(fd, data + got, len - got, 0);
        if (rc <= 0)
            throw runtime_error("connection closed while receiving");
        got += rc;
    }
}

struct TLSRecord
{
    uint8_t type;
    vector<uint8_t> header;  // 5 bytes
    vector<uint8_t> payload;
};

TLSRecord read_tls_record(int sock)
{
    TLSRecord rec;
    rec.header.resize(5);
    recv_exact(sock, rec.header.data(), rec.header.size());
    rec.type = rec.header[0];
    uint16_t len = ((uint16_t) rec.header[3] << 8) | rec.header[4];
    rec.payload.resize(len);
    if (len > 0)
        recv_exact(sock, rec.payload.data(), len);
    return rec;
}

vector<uint8_t> sha256_bytes(const vector<uint8_t>& data)
{
    vector<uint8_t> out(32);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

vector<uint8_t> concat(const vector<uint8_t>& a, const vector<uint8_t>& b)
{
    vector<uint8_t> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

string hex_prefix(const vector<uint8_t>& data, size_t bytes = 8)
{
    std::ostringstream oss;
    for (size_t i = 0; i < std::min(bytes, data.size()); ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int) data[i];
    return oss.str();
}

void write_client_hello_record(int sock, const vector<uint8_t>& ch_msg)
{
    vector<uint8_t> rec;
    rec.reserve(5 + ch_msg.size());
    rec.push_back(RECORD_TYPE_HANDSHAKE);
    append_u16_be(rec, 0x0301);  // TLS 1.0 legacy record version for compatibility
    append_u16_be(rec, ch_msg.size());
    rec.insert(rec.end(), ch_msg.begin(), ch_msg.end());
    send_all(sock, rec.data(), rec.size());
}

vector<uint8_t> encode_client_hello(const std::array<uint8_t, 32>& random,
        const std::array<uint8_t, 32>& pub_key, const string& alpn, const string& server_name)
{
    vector<uint8_t> exts;

    if (!server_name.empty())
    {
        vector<uint8_t> sn;
        sn.push_back(0);  // host_name
        append_u16_be(sn, server_name.size());
        sn.insert(sn.end(), server_name.begin(), server_name.end());

        vector<uint8_t> body;
        append_u16_be(body, sn.size());
        body.insert(body.end(), sn.begin(), sn.end());

        append_u16_be(exts, EXT_SERVER_NAME);
        append_u16_be(exts, body.size());
        exts.insert(exts.end(), body.begin(), body.end());
    }

    {
        vector<uint8_t> body;
        append_u16_be(body, 2);
        append_u16_be(body, X25519);
        append_u16_be(exts, EXT_SUPPORTED_GROUPS);
        append_u16_be(exts, body.size());
        exts.insert(exts.end(), body.begin(), body.end());
    }

    {
        vector<uint8_t> kshare;
        append_u16_be(kshare, X25519);
        append_u16_be(kshare, pub_key.size());
        kshare.insert(kshare.end(), pub_key.begin(), pub_key.end());

        vector<uint8_t> body;
        append_u16_be(body, kshare.size());
        body.insert(body.end(), kshare.begin(), kshare.end());

        append_u16_be(exts, EXT_KEY_SHARE);
        append_u16_be(exts, body.size());
        exts.insert(exts.end(), body.begin(), body.end());
    }

    {
        vector<uint16_t> sig_algos = {0x0401, 0x0403, 0x0804};
        vector<uint8_t> body;
        append_u16_be(body, sig_algos.size() * 2);
        for (auto a : sig_algos)
            append_u16_be(body, a);
        append_u16_be(exts, EXT_SIGNATURE_ALGORITHMS);
        append_u16_be(exts, body.size());
        exts.insert(exts.end(), body.begin(), body.end());
    }

    {
        vector<uint8_t> body;
        append_u16_be(body, alpn.size() + 1);
        body.push_back(alpn.size());
        body.insert(body.end(), alpn.begin(), alpn.end());
        append_u16_be(exts, EXT_ALPN);
        append_u16_be(exts, body.size());
        exts.insert(exts.end(), body.begin(), body.end());
    }

    {
        vector<uint8_t> body;
        body.push_back(2);
        append_u16_be(body, 0x0304);  // TLS 1.3
        append_u16_be(exts, EXT_SUPPORTED_VERSIONS);
        append_u16_be(exts, body.size());
        exts.insert(exts.end(), body.begin(), body.end());
    }

    vector<uint8_t> payload;
    append_u16_be(payload, 0x0303);  // legacy_version
    payload.insert(payload.end(), random.begin(), random.end());
    payload.push_back(0);  // session id len

    vector<uint8_t> ciphers;
    append_u16_be(ciphers, TLS_AES_128_GCM_SHA256);
    append_u16_be(ciphers, TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    append_u16_be(payload, ciphers.size());
    payload.insert(payload.end(), ciphers.begin(), ciphers.end());

    payload.push_back(1);  // compression methods len
    payload.push_back(0);  // null compression

    append_u16_be(payload, exts.size());
    payload.insert(payload.end(), exts.begin(), exts.end());

    vector<uint8_t> hs;
    hs.push_back(1);  // ClientHello
    append_u24_be(hs, payload.size());
    hs.insert(hs.end(), payload.begin(), payload.end());
    return hs;
}

std::pair<vector<uint8_t>, uint16_t> decode_server_hello(const vector<uint8_t>& sh_payload)
{
    // input is ServerHello body (without handshake header)
    size_t off = 0;
    if (sh_payload.size() < 2 + 32 + 1)
        throw runtime_error("ServerHello too short");
    off += 2;  // legacy_version
    off += 32; // random

    uint8_t sid_len = sh_payload[off++];
    off += sid_len;
    if (off + 3 > sh_payload.size())
        throw runtime_error("ServerHello truncated");

    uint16_t cipher = ((uint16_t) sh_payload[off] << 8) | sh_payload[off + 1];
    off += 2;
    uint8_t comp_len = sh_payload[off++];
    off += comp_len;

    if (off + 2 > sh_payload.size())
        throw runtime_error("ServerHello no extensions");
    uint16_t ext_len = ((uint16_t) sh_payload[off] << 8) | sh_payload[off + 1];
    off += 2;
    size_t ext_end = off + ext_len;
    if (ext_end > sh_payload.size())
        throw runtime_error("ServerHello ext overflow");

    vector<uint8_t> server_pub;
    while (off + 4 <= ext_end)
    {
        uint16_t etype = ((uint16_t) sh_payload[off] << 8) | sh_payload[off + 1];
        uint16_t elen = ((uint16_t) sh_payload[off + 2] << 8) | sh_payload[off + 3];
        off += 4;
        if (off + elen > ext_end)
            break;
        if (etype == EXT_KEY_SHARE && elen >= 4)
        {
            uint16_t key_len = ((uint16_t) sh_payload[off + 2] << 8) | sh_payload[off + 3];
            if (elen >= 4 + key_len)
                server_pub.assign(sh_payload.begin() + off + 4, sh_payload.begin() + off + 4 + key_len);
            break;
        }
        off += elen;
    }

    if (server_pub.empty())
        throw runtime_error("ServerHello missing key_share");
    return {server_pub, cipher};
}

struct X25519Keypair
{
    std::array<uint8_t, 32> priv {};
    std::array<uint8_t, 32> pub {};
};

X25519Keypair x25519_generate()
{
    X25519Keypair kp;
    if (RAND_bytes(kp.priv.data(), kp.priv.size()) != 1)
        throw runtime_error("RAND_bytes failed");

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, kp.priv.data(), kp.priv.size());
    if (!pkey)
        throw runtime_error("EVP_PKEY_new_raw_private_key failed");

    size_t out_len = kp.pub.size();
    if (EVP_PKEY_get_raw_public_key(pkey, kp.pub.data(), &out_len) != 1 || out_len != kp.pub.size())
    {
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    EVP_PKEY_free(pkey);
    return kp;
}

vector<uint8_t> x25519_derive(const std::array<uint8_t, 32>& priv, const vector<uint8_t>& peer_pub)
{
    EVP_PKEY* my = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size());
    if (!my || !peer)
    {
        if (my) EVP_PKEY_free(my);
        if (peer) EVP_PKEY_free(peer);
        throw runtime_error("EVP_PKEY_new_raw_* failed");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my, nullptr);
    if (!ctx)
        throw runtime_error("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_derive_init(ctx) != 1 || EVP_PKEY_derive_set_peer(ctx, peer) != 1)
        throw runtime_error("EVP_PKEY_derive init/peer failed");

    size_t out_len = 32;
    vector<uint8_t> out(out_len);
    if (EVP_PKEY_derive(ctx, out.data(), &out_len) != 1)
        throw runtime_error("EVP_PKEY_derive failed");
    out.resize(out_len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(my);
    EVP_PKEY_free(peer);
    return out;
}

vector<long> pack_bytes(const vector<uint8_t>& data, int max_words)
{
    vector<long> words;
    for (size_t i = 0; i < data.size(); i += 8)
    {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j)
        {
            w <<= 8;
            size_t idx = i + j;
            if (idx < data.size())
                w |= data[idx];
        }
        words.push_back((long) w);
    }
    while ((int) words.size() < max_words)
        words.push_back(0);
    if ((int) words.size() > max_words)
        words.resize(max_words);
    return words;
}

vector<uint8_t> unpack_words(const vector<Z2<64>>& vals, size_t length)
{
    vector<uint8_t> out;
    out.reserve(vals.size() * 8);
    for (auto& v : vals)
    {
        uint64_t w = (uint64_t) v.get_limb(0);
        for (int i = 7; i >= 0; --i)
            out.push_back((w >> (i * 8)) & 0xff);
    }
    if (out.size() > length)
        out.resize(length);
    return out;
}

vector<Z2<64>> to_z2(const vector<long>& in)
{
    vector<Z2<64>> out;
    out.reserve(in.size());
    for (auto x : in)
        out.emplace_back(x);
    return out;
}

void send_public_inputs(Client& client, const vector<long>& values)
{
    octetStream os;
    for (auto v : values)
    {
        Z2<64> x(v);
        x.pack(os);
    }
    for (auto* socket : client.sockets)
        os.Send(socket);
}

/** Raw 64-bit little-endian words (matches Python Client.send_public_inputs_raw64 + regint.read_from_socket). */
void send_public_inputs_raw64(Client& client, const vector<long>& values)
{
    octetStream os;
    for (auto v : values)
    {
        uint64_t u = (uint64_t) (long long) v;
        octet le[8];
        for (int i = 0; i < 8; i++)
            le[i] = (u >> (8 * i)) & 0xff;
        os.append(le, 8);
    }
    for (auto* socket : client.sockets)
        os.Send(socket);
}

void add_mod256(const uint8_t* a, const uint8_t* b, uint8_t* out)
{
    uint16_t c = 0;
    for (int i = 0; i < 32; i++)
    {
        c = (uint16_t) c + a[i] + b[i];
        out[i] = (uint8_t) (c & 0xff);
        c >>= 8;
    }
}

void sub_mod256(const uint8_t* k, const uint8_t* s, uint8_t* out)
{
    int borrow = 0;
    for (int i = 0; i < 32; i++)
    {
        int v = (int) k[i] - (int) s[i] - borrow;
        if (v < 0)
        {
            v += 256;
            borrow = 1;
        }
        else
            borrow = 0;
        out[i] = (uint8_t) v;
    }
}

/** 256-bit integer (LE) -> 4 x 64-bit BE words (matches Python scalar_int_to_be_words). */
vector<uint64_t> scalar_le_to_be_words(const uint8_t* le32)
{
    vector<uint64_t> w(4);
    for (int i = 0; i < 4; i++)
    {
        uint64_t x = 0;
        for (int j = 0; j < 8; j++)
            x = (x << 8) | le32[i * 8 + j];
        w[i] = x;
    }
    return w;
}

/** Three additive shares mod 2^256 -> 12 BE words for otls_demo_field private inputs. */
vector<uint64_t> split_scalar_three_shares(const uint8_t* priv_le32)
{
    uint8_t r0[32], r1[32], r2[32], sum01[32];
    if (RAND_bytes(r0, 32) != 1 || RAND_bytes(r1, 32) != 1)
        throw runtime_error("RAND_bytes failed");
    add_mod256(r0, r1, sum01);
    sub_mod256(priv_le32, sum01, r2);

    vector<uint64_t> out;
    auto w0 = scalar_le_to_be_words(r0);
    auto w1 = scalar_le_to_be_words(r1);
    auto w2 = scalar_le_to_be_words(r2);
    out.insert(out.end(), w0.begin(), w0.end());
    out.insert(out.end(), w1.begin(), w1.end());
    out.insert(out.end(), w2.begin(), w2.end());
    return out;
}

vector<long> digest_to_words32(const vector<uint8_t>& d)
{
    auto u = scalar_le_to_be_words(d.data());
    vector<long> w;
    for (uint64_t x : u)
        w.push_back((long) (int64_t) x);
    return w;
}

vector<uint8_t> unpack_words_fp(const vector<gfp0>& vals, size_t length)
{
    vector<uint8_t> out;
    out.reserve(vals.size() * 8);
    for (auto& v : vals)
    {
        bigint b = v;
        uint64_t w = b.get_ui();
        for (int i = 7; i >= 0; --i)
            out.push_back((w >> (i * 8)) & 0xff);
    }
    if (out.size() > length)
        out.resize(length);
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    try
    {
        string host = argc > 1 ? argv[1] : "restcountries.com";
        int port = argc > 2 ? atoi(argv[2]) : 443;
        string path = argc > 3 ? argv[3] : "/v3.1/name/deutschland";
        int mpc_port = argc > 4 ? atoi(argv[4]) : 18000;

        log("Connecting to " + host + ":" + std::to_string(port));
        int sock = connect_tcp(host, port);

        auto kp = x25519_generate();
        std::array<uint8_t, 32> client_random {};
        RAND_bytes(client_random.data(), client_random.size());
        auto ch = encode_client_hello(client_random, kp.pub, "http/1.1", host);
        write_client_hello_record(sock, ch);
        log("ClientHello sent");

        auto sh_rec = read_tls_record(sock);
        if (sh_rec.type != RECORD_TYPE_HANDSHAKE)
            throw runtime_error("Expected ServerHello, got type " + std::to_string(sh_rec.type));
        vector<uint8_t> sh_msg = sh_rec.payload;
        if (sh_msg.size() < 4)
            throw runtime_error("ServerHello message too short");
        auto [server_pub, cipher_suite] = decode_server_hello(vector<uint8_t>(sh_msg.begin() + 4, sh_msg.end()));
        log("ServerHello received, cipher_suite=0x" + hex_prefix({(uint8_t)(cipher_suite >> 8), (uint8_t)(cipher_suite & 0xff)}, 2));
        if (cipher_suite != TLS_AES_128_GCM_SHA256)
            throw runtime_error("Server selected unsupported cipher");

        vector<vector<uint8_t>> enc_records;
        while ((int) enc_records.size() < MAX_HS_RECORDS)
        {
            auto rec = read_tls_record(sock);
            if (rec.type == RECORD_TYPE_CHANGE_CIPHER_SPEC)
                continue;
            if (rec.type == RECORD_TYPE_APPLICATION_DATA)
            {
                vector<uint8_t> whole = rec.header;
                whole.insert(whole.end(), rec.payload.begin(), rec.payload.end());
                enc_records.push_back(whole);
                log("  HS-phase record " + std::to_string(enc_records.size()) + ": "
                        + std::to_string(whole.size()) + " bytes");
                if (!wait_readable(sock, 0.5))
                    break;
            }
            else
                break;
        }
        log("Read " + std::to_string(enc_records.size()) + " encrypted server HS-phase records");

        auto th_ch_sh = sha256_bytes(concat(ch, sh_msg));
        log("th(CH||SH) = " + hex_prefix(th_ch_sh) + "...");

        vector<string> hosts(3, "localhost");
        Client client(hosts, mpc_port, 0);

        int domain_kind = client.specification.get<int>();
        bool use_field_mpc = (domain_kind == 'p');

        auto thw = digest_to_words32(th_ch_sh);
        send_public_inputs_raw64(client, thw);

        if (use_field_mpc)
        {
            gfp0::init_field(client.specification.get<bigint>());
            log("MPC domain: prime field (otls_demo_field); X25519 computed in MPC");
            vector<gfp0> priv12;
            auto sh = split_scalar_three_shares(kp.priv.data());
            for (uint64_t x : sh)
                priv12.emplace_back((word) x);
            client.send_private_inputs<gfp0>(priv12);
            vector<uint8_t> sp32 = server_pub;
            if (sp32.size() < 32)
                sp32.resize(32, 0);
            else if (sp32.size() > 32)
                sp32.resize(32);
            send_public_inputs_raw64(client, digest_to_words32(sp32));
        }
        else if (domain_kind == 'R')
        {
            int ring_bits = client.specification.get<int>();
            int clear_bits = client.specification.get<int>();
            if (ring_bits != 64 || clear_bits != 64)
                throw runtime_error("Expected ring64 domain for otls_demo");
            auto shared_secret = x25519_derive(kp.priv, server_pub);
            log("MPC domain: ring; X25519 shared secret computed in ExternalIO client");
            auto ss_words = pack_bytes(shared_secret, 4);
            client.send_private_inputs<Z2<64>>(to_z2(ss_words));
        }
        else
            throw runtime_error("Unsupported MPC domain (expected 'p' field or 'R' ring)");

        send_public_inputs_raw64(client, {(long) enc_records.size()});
        for (auto& rec : enc_records)
        {
            auto words = pack_bytes(rec, MAX_REC_WORDS);
            vector<long> payload;
            payload.reserve(1 + words.size());
            payload.push_back(rec.size());
            payload.insert(payload.end(), words.begin(), words.end());
            send_public_inputs_raw64(client, payload);
        }
        for (size_t i = enc_records.size(); i < (size_t) MAX_HS_RECORDS; ++i)
        {
            vector<long> payload(1 + MAX_REC_WORDS, 0);
            send_public_inputs_raw64(client, payload);
        }

        log("Waiting for MPC to decrypt server handshake records...");
        vector<uint8_t> server_hs_messages;
        int n_nst_phase0 = 0;
        for (int ri = 0; ri < MAX_HS_RECORDS; ++ri)
        {
            if (use_field_mpc)
            {
                auto hs_out = client.receive_outputs<gfp0, gfp0>(1 + MAX_REC_WORDS);
                if (ri >= (int) enc_records.size())
                {
                    log("  HS record " + std::to_string(ri) + ": padding");
                    continue;
                }
                int actual_rec_len = enc_records[ri].size();
                int actual_ct = std::max(0, actual_rec_len - 21);
                vector<gfp0> packed(hs_out.begin() + 1, hs_out.end());
                auto pt = unpack_words_fp(packed, actual_ct);
                while (!pt.empty() && pt.back() == 0)
                    pt.pop_back();
                if (pt.empty())
                    continue;
                uint8_t inner_ct = pt.back();
                pt.pop_back();
                std::ostringstream oss;
                oss << "  HS record " << ri << ": " << pt.size() << " bytes, inner_ct=0x"
                        << std::hex << std::setw(2) << std::setfill('0') << (int) inner_ct;
                log(oss.str());
                if (inner_ct == 0x16)
                    server_hs_messages.insert(server_hs_messages.end(), pt.begin(), pt.end());
                else
                    n_nst_phase0++;
            }
            else
            {
                auto hs_out = client.receive_outputs<Z2<64>, Z2<64>>(1 + MAX_REC_WORDS);
                if (ri >= (int) enc_records.size())
                {
                    log("  HS record " + std::to_string(ri) + ": padding");
                    continue;
                }
                int actual_rec_len = enc_records[ri].size();
                int actual_ct = std::max(0, actual_rec_len - 21);
                vector<Z2<64>> packed(hs_out.begin() + 1, hs_out.end());
                auto pt = unpack_words(packed, actual_ct);
                while (!pt.empty() && pt.back() == 0)
                    pt.pop_back();
                if (pt.empty())
                    continue;
                uint8_t inner_ct = pt.back();
                pt.pop_back();
                std::ostringstream oss;
                oss << "  HS record " << ri << ": " << pt.size() << " bytes, inner_ct=0x"
                        << std::hex << std::setw(2) << std::setfill('0') << (int) inner_ct;
                log(oss.str());
                if (inner_ct == 0x16)
                    server_hs_messages.insert(server_hs_messages.end(), pt.begin(), pt.end());
                else
                    n_nst_phase0++;
            }
        }

        auto transcript = concat(concat(ch, sh_msg), server_hs_messages);
        auto th_sf = sha256_bytes(transcript);
        log("th(through server Finished) = " + hex_prefix(th_sf) + "...");

        std::ostringstream req_stream;
        req_stream << "GET " << path << " HTTP/1.1\r\nHost: " << host << "\r\nConnection: close\r\n\r\n";
        string req_s = req_stream.str();
        vector<uint8_t> req(req_s.begin(), req_s.end());
        log("HTTP request: " + std::to_string(req.size()) + " bytes");

        send_public_inputs_raw64(client, digest_to_words32(th_sf));
        {
            auto req_words = pack_bytes(req, MAX_APP_WORDS);
            vector<long> payload;
            payload.reserve(1 + req_words.size());
            payload.push_back(req.size());
            payload.insert(payload.end(), req_words.begin(), req_words.end());
            send_public_inputs_raw64(client, payload);
        }

        log("Waiting for MPC to encrypt Client Finished + HTTP GET...");
        vector<uint8_t> fin_rec, app_rec;
        if (use_field_mpc)
        {
            auto fin_out = client.receive_outputs<gfp0, gfp0>(1 + MAX_APP_WORDS);
            auto app_out = client.receive_outputs<gfp0, gfp0>(1 + MAX_APP_WORDS);
            bigint b0 = fin_out[0], b1 = app_out[0];
            size_t fin_len = b0.get_ui();
            size_t app_len = b1.get_ui();
            vector<gfp0> fin_packed(fin_out.begin() + 1, fin_out.end());
            vector<gfp0> app_packed(app_out.begin() + 1, app_out.end());
            fin_rec = unpack_words_fp(fin_packed, fin_len);
            app_rec = unpack_words_fp(app_packed, app_len);
        }
        else
        {
            auto fin_out = client.receive_outputs<Z2<64>, Z2<64>>(1 + MAX_APP_WORDS);
            auto app_out = client.receive_outputs<Z2<64>, Z2<64>>(1 + MAX_APP_WORDS);
            size_t fin_len = (uint64_t) fin_out[0].get_limb(0);
            size_t app_len = (uint64_t) app_out[0].get_limb(0);
            vector<Z2<64>> fin_packed(fin_out.begin() + 1, fin_out.end());
            vector<Z2<64>> app_packed(app_out.begin() + 1, app_out.end());
            fin_rec = unpack_words(fin_packed, fin_len);
            app_rec = unpack_words(app_packed, app_len);
        }
        send_all(sock, fin_rec.data(), fin_rec.size());
        send_all(sock, app_rec.data(), app_rec.size());

        vector<vector<uint8_t>> all_resp;
        for (int i = 0; i < MAX_RESP_RECORDS + 4; ++i)
        {
            if (!wait_readable(sock, 2.0))
                break;
            try
            {
                auto rec = read_tls_record(sock);
                vector<uint8_t> whole = rec.header;
                whole.insert(whole.end(), rec.payload.begin(), rec.payload.end());
                log("  post-HS record ct=" + std::to_string(rec.type) + " len=" + std::to_string(whole.size()));
                if (rec.type == RECORD_TYPE_APPLICATION_DATA)
                    all_resp.push_back(whole);
            }
            catch (std::exception& e)
            {
                log(string("  read error: ") + e.what());
                break;
            }
        }

        int nst_in_resp = 0;
        vector<vector<uint8_t>> resp_records;
        for (auto& rec : all_resp)
        {
            if (rec.size() < 300 && resp_records.empty())
                nst_in_resp++;
            else
                resp_records.push_back(rec);
        }
        int srv_app_seq = n_nst_phase0 + nst_in_resp;
        send_public_inputs_raw64(client, {(long) srv_app_seq});
        send_public_inputs_raw64(client, {(long) resp_records.size()});
        for (int i = 0; i < MAX_RESP_RECORDS; ++i)
        {
            vector<long> payload;
            payload.reserve(1 + MAX_APP_WORDS);
            if (i < (int) resp_records.size())
            {
                auto w = pack_bytes(resp_records[i], MAX_APP_WORDS);
                payload.push_back(resp_records[i].size());
                payload.insert(payload.end(), w.begin(), w.end());
            }
            else
                payload.assign(1 + MAX_APP_WORDS, 0);
            send_public_inputs_raw64(client, payload);
        }

        vector<uint8_t> resp_body;
        if (use_field_mpc)
        {
            auto resp_out = client.receive_outputs<gfp0, gfp0>(1 + MAX_APP_WORDS);
            size_t actual_ct;
            if (resp_records.empty())
            {
                bigint br = resp_out[0];
                actual_ct = br.get_ui();
            }
            else
                actual_ct = (size_t) std::max(0, (int) resp_records[0].size() - 21);
            vector<gfp0> resp_packed(resp_out.begin() + 1, resp_out.end());
            resp_body = unpack_words_fp(resp_packed, std::min((size_t) RESP_CT_BYTES, actual_ct));
        }
        else
        {
            auto resp_out = client.receive_outputs<Z2<64>, Z2<64>>(1 + MAX_APP_WORDS);
            size_t actual_ct = resp_records.empty() ? (uint64_t) resp_out[0].get_limb(0)
                                                   : (size_t) std::max(0, (int) resp_records[0].size() - 21);
            vector<Z2<64>> resp_packed(resp_out.begin() + 1, resp_out.end());
            resp_body = unpack_words(resp_packed, std::min((size_t) RESP_CT_BYTES, actual_ct));
        }
        while (!resp_body.empty() && resp_body.back() == 0)
            resp_body.pop_back();
        if (!resp_body.empty())
            resp_body.pop_back(); // inner content type

        close(sock);
        std::cout << string(resp_body.begin(), resp_body.end()) << std::endl;
        return 0;
    }
    catch (std::exception& e)
    {
        cerr << "[otls-external-io] ERROR: " << e.what() << std::endl;
        return 1;
    }
}
