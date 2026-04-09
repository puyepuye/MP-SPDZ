#include "Processor/OtlsTlsClientHelloPoc.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace
{
constexpr uint8_t RECORD_TYPE_HANDSHAKE = 22;
constexpr uint16_t TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;
constexpr uint16_t TLS_AES_128_GCM_SHA256 = 0x1301;
constexpr uint16_t X25519 = 0x001D;
constexpr uint16_t EXT_SERVER_NAME = 0x0000;
constexpr uint16_t EXT_SUPPORTED_GROUPS = 0x000A;
constexpr uint16_t EXT_SIGNATURE_ALGORITHMS = 0x000D;
constexpr uint16_t EXT_ALPN = 0x0010;
constexpr uint16_t EXT_SUPPORTED_VERSIONS = 0x002B;
constexpr uint16_t EXT_KEY_SHARE = 0x0033;

void append_u16_be(std::vector<uint8_t>& out, uint16_t v)
{
  out.push_back((v >> 8) & 0xff);
  out.push_back(v & 0xff);
}

void append_u24_be(std::vector<uint8_t>& out, uint32_t v)
{
  out.push_back((v >> 16) & 0xff);
  out.push_back((v >> 8) & 0xff);
  out.push_back(v & 0xff);
}

void send_all(int fd, const uint8_t* data, size_t len)
{
  size_t sent = 0;
  while (sent < len)
    {
      ssize_t rc = send(fd, data + sent, len - sent, 0);
      if (rc <= 0)
        throw std::runtime_error("OTLS TLS poc: send failed");
      sent += (size_t) rc;
    }
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
    throw std::runtime_error("OTLS TLS poc: RAND_bytes failed");
  EVP_PKEY* pkey =
      EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, kp.priv.data(), kp.priv.size());
  if (!pkey)
    throw std::runtime_error("OTLS TLS poc: EVP_PKEY_new_raw_private_key failed");
  size_t out_len = kp.pub.size();
  if (EVP_PKEY_get_raw_public_key(pkey, kp.pub.data(), &out_len) != 1
      || out_len != kp.pub.size())
    {
      EVP_PKEY_free(pkey);
      throw std::runtime_error("OTLS TLS poc: EVP_PKEY_get_raw_public_key failed");
    }
  EVP_PKEY_free(pkey);
  return kp;
}

std::vector<uint8_t> encode_client_hello(const std::array<uint8_t, 32>& random,
        const std::array<uint8_t, 32>& pub_key, const std::string& alpn,
        const std::string& server_name)
{
  std::vector<uint8_t> exts;
  if (!server_name.empty())
    {
      std::vector<uint8_t> sn;
      sn.push_back(0);
      append_u16_be(sn, server_name.size());
      sn.insert(sn.end(), server_name.begin(), server_name.end());
      std::vector<uint8_t> body;
      append_u16_be(body, sn.size());
      body.insert(body.end(), sn.begin(), sn.end());
      append_u16_be(exts, EXT_SERVER_NAME);
      append_u16_be(exts, body.size());
      exts.insert(exts.end(), body.begin(), body.end());
    }
  {
    std::vector<uint8_t> body;
    append_u16_be(body, 2);
    append_u16_be(body, X25519);
    append_u16_be(exts, EXT_SUPPORTED_GROUPS);
    append_u16_be(exts, body.size());
    exts.insert(exts.end(), body.begin(), body.end());
  }
  {
    std::vector<uint8_t> kshare;
    append_u16_be(kshare, X25519);
    append_u16_be(kshare, pub_key.size());
    kshare.insert(kshare.end(), pub_key.begin(), pub_key.end());
    std::vector<uint8_t> body;
    append_u16_be(body, kshare.size());
    body.insert(body.end(), kshare.begin(), kshare.end());
    append_u16_be(exts, EXT_KEY_SHARE);
    append_u16_be(exts, body.size());
    exts.insert(exts.end(), body.begin(), body.end());
  }
  {
    std::vector<uint16_t> sig_algos = {0x0401, 0x0403, 0x0804};
    std::vector<uint8_t> body;
    append_u16_be(body, sig_algos.size() * 2);
    for (auto a : sig_algos)
      append_u16_be(body, a);
    append_u16_be(exts, EXT_SIGNATURE_ALGORITHMS);
    append_u16_be(exts, body.size());
    exts.insert(exts.end(), body.begin(), body.end());
  }
  {
    std::vector<uint8_t> body;
    append_u16_be(body, alpn.size() + 1);
    body.push_back(alpn.size());
    body.insert(body.end(), alpn.begin(), alpn.end());
    append_u16_be(exts, EXT_ALPN);
    append_u16_be(exts, body.size());
    exts.insert(exts.end(), body.begin(), body.end());
  }
  {
    std::vector<uint8_t> body;
    body.push_back(2);
    append_u16_be(body, 0x0304);
    append_u16_be(exts, EXT_SUPPORTED_VERSIONS);
    append_u16_be(exts, body.size());
    exts.insert(exts.end(), body.begin(), body.end());
  }
  std::vector<uint8_t> payload;
  append_u16_be(payload, 0x0303);
  payload.insert(payload.end(), random.begin(), random.end());
  payload.push_back(0);
  std::vector<uint8_t> ciphers;
  append_u16_be(ciphers, TLS_AES_128_GCM_SHA256);
  append_u16_be(ciphers, TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
  append_u16_be(payload, ciphers.size());
  payload.insert(payload.end(), ciphers.begin(), ciphers.end());
  payload.push_back(1);
  payload.push_back(0);
  append_u16_be(payload, exts.size());
  payload.insert(payload.end(), exts.begin(), exts.end());
  std::vector<uint8_t> hs;
  hs.push_back(1);
  append_u24_be(hs, payload.size());
  hs.insert(hs.end(), payload.begin(), payload.end());
  return hs;
}

void write_client_hello_record(int fd, const std::vector<uint8_t>& ch_msg)
{
  std::vector<uint8_t> rec;
  rec.reserve(5 + ch_msg.size());
  rec.push_back(RECORD_TYPE_HANDSHAKE);
  append_u16_be(rec, 0x0301);
  append_u16_be(rec, ch_msg.size());
  rec.insert(rec.end(), ch_msg.begin(), ch_msg.end());
  send_all(fd, rec.data(), rec.size());
}
} // namespace

void otls_tls_send_client_hello_poc(int tcp_fd, const char* server_name)
{
  if (tcp_fd < 0)
    throw std::runtime_error("OTLS TLS poc: invalid tcp fd");
  std::string sn = (server_name && server_name[0]) ? server_name : "restcountries.com";
  std::array<uint8_t, 32> random {};
  if (RAND_bytes(random.data(), random.size()) != 1)
    throw std::runtime_error("OTLS TLS poc: RAND_bytes(random) failed");
  auto kp = x25519_generate();
  auto ch = encode_client_hello(random, kp.pub, "http/1.1", sn);
  write_client_hello_record(tcp_fd, ch);
}
