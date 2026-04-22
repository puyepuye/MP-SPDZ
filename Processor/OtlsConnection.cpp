#include "Processor/OtlsConnection.h"
#include "Processor/OtlsTlsClientHelloPoc.h"

#include "Networking/Player.h"
#include "Processor/Processor.h"
#include "Tools/octetStream.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace OtlsConnection
{
namespace
{
int tcp_fd = -1;
std::vector<uint8_t> last_ch_msg;
std::vector<uint8_t> last_sh_msg;
std::array<uint8_t, 32> last_priv {};
std::deque<std::vector<uint8_t>> pending_tls_records;
bool has_last_ch = false;
bool has_last_sh = false;
bool has_last_priv = false;

SHA256_CTX transcript_ctx;
bool transcript_ctx_initialized = false;
int nst_phase0_count = 0;

int connect_tcp(const std::string& host, int port)
{
  addrinfo hints {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo* res = nullptr;
  std::string port_str = std::to_string(port);
  int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
  if (rc != 0)
    throw std::runtime_error("OTLS TCP: getaddrinfo failed: "
        + std::string(gai_strerror(rc)));

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
    throw std::runtime_error("OTLS TCP: unable to connect to " + host + ":"
        + std::to_string(port));
  return fd;
}

void send_all(int fd, const uint8_t* data, size_t len)
{
  size_t sent = 0;
  while (sent < len)
    {
      ssize_t rc = send(fd, data + sent, len - sent, 0);
      if (rc <= 0)
        throw std::runtime_error("OTLS TCP: send failed");
      sent += (size_t) rc;
    }
}

void recv_exact(int fd, uint8_t* data, size_t len)
{
  size_t got = 0;
  while (got < len)
    {
      ssize_t rc = recv(fd, data + got, len - got, 0);
      if (rc == 0)
        throw std::runtime_error("OTLS TCP: peer closed TCP during recv_exact");
      if (rc < 0)
        throw std::runtime_error(std::string("OTLS TCP: recv: ") + strerror(errno));
      got += (size_t) rc;
    }
}

bool recv_exact_or_eof(int fd, uint8_t* data, size_t len)
{
  size_t got = 0;
  while (got < len)
    {
      ssize_t rc = recv(fd, data + got, len - got, 0);
      if (rc == 0)
        return false;
      if (rc < 0)
        throw std::runtime_error(std::string("OTLS TCP: recv: ") + strerror(errno));
      got += (size_t) rc;
    }
  return true;
}

std::vector<uint8_t> recv_tls_record(int fd)
{
  std::vector<uint8_t> header(5);
  recv_exact(fd, header.data(), header.size());
  uint16_t payload_len = ((uint16_t) header[3] << 8) | header[4];
  std::vector<uint8_t> rec = header;
  if (payload_len > 0)
    {
      size_t old = rec.size();
      rec.resize(old + payload_len);
      recv_exact(fd, rec.data() + old, payload_len);
    }
  return rec;
}

std::vector<uint8_t> recv_tls_record_or_empty(int fd)
{
  std::vector<uint8_t> header(5);
  if (!recv_exact_or_eof(fd, header.data(), header.size()))
    return {};
  uint16_t payload_len = ((uint16_t) header[3] << 8) | header[4];
  std::vector<uint8_t> rec = header;
  if (payload_len > 0)
    {
      size_t old = rec.size();
      rec.resize(old + payload_len);
      recv_exact(fd, rec.data() + old, payload_len);
    }
  return rec;
}

std::vector<uint8_t> next_tls_record(int fd)
{
  if (!pending_tls_records.empty())
    {
      auto rec = pending_tls_records.front();
      pending_tls_records.pop_front();
      return rec;
    }
  return recv_tls_record(fd);
}

std::pair<std::vector<uint8_t>, uint16_t> decode_server_hello(const std::vector<uint8_t>& sh_payload)
{
  size_t off = 0;
  if (sh_payload.size() < 2 + 32 + 1)
    throw std::runtime_error("ServerHello too short");
  off += 2;
  off += 32;
  uint8_t sid_len = sh_payload[off++];
  off += sid_len;
  if (off + 3 > sh_payload.size())
    throw std::runtime_error("ServerHello truncated");

  uint16_t cipher = ((uint16_t) sh_payload[off] << 8) | sh_payload[off + 1];
  off += 2;
  uint8_t comp_len = sh_payload[off++];
  off += comp_len;
  if (off + 2 > sh_payload.size())
    throw std::runtime_error("ServerHello no extensions");
  uint16_t ext_len = ((uint16_t) sh_payload[off] << 8) | sh_payload[off + 1];
  off += 2;
  size_t ext_end = off + ext_len;
  if (ext_end > sh_payload.size())
    throw std::runtime_error("ServerHello ext overflow");

  std::vector<uint8_t> server_pub;
  while (off + 4 <= ext_end)
    {
      uint16_t etype = ((uint16_t) sh_payload[off] << 8) | sh_payload[off + 1];
      uint16_t elen = ((uint16_t) sh_payload[off + 2] << 8) | sh_payload[off + 3];
      off += 4;
      if (off + elen > ext_end)
        break;
      if (etype == 0x0033 && elen >= 4)
        {
          uint16_t key_len = ((uint16_t) sh_payload[off + 2] << 8) | sh_payload[off + 3];
          if (elen >= 4 + key_len)
            server_pub.assign(sh_payload.begin() + off + 4, sh_payload.begin() + off + 4 + key_len);
          break;
        }
      off += elen;
    }
  if (server_pub.empty())
    throw std::runtime_error("ServerHello missing key_share");
  return {server_pub, cipher};
}

std::vector<long> bytes32_to_words_be(const std::vector<uint8_t>& b32)
{
  if (b32.size() < 32)
    throw std::runtime_error("bytes32_to_words_be: need 32 bytes");
  std::vector<long> out(4);
  for (int i = 0; i < 4; i++)
    {
      uint64_t x = 0;
      for (int j = 0; j < 8; j++)
        x = (x << 8) | b32[i * 8 + j];
      out[i] = (long) (long long) x;
    }
  return out;
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

std::vector<uint64_t> scalar_le_to_be_words(const uint8_t* le32)
{
  std::vector<uint64_t> w(4);
  for (int i = 0; i < 4; i++)
    {
      uint64_t x = 0;
      for (int j = 0; j < 8; j++)
        x = (x << 8) | le32[i * 8 + j];
      w[i] = x;
    }
  return w;
}

std::vector<uint64_t> split_scalar_three_shares(const uint8_t* priv_le32)
{
  uint8_t r0[32], r1[32], r2[32], sum01[32];
  if (RAND_bytes(r0, 32) != 1 || RAND_bytes(r1, 32) != 1)
    throw std::runtime_error("OTLS scalar split: RAND_bytes failed");
  add_mod256(r0, r1, sum01);
  sub_mod256(priv_le32, sum01, r2);

  std::vector<uint64_t> out;
  auto w0 = scalar_le_to_be_words(r0);
  auto w1 = scalar_le_to_be_words(r1);
  auto w2 = scalar_le_to_be_words(r2);
  out.insert(out.end(), w0.begin(), w0.end());
  out.insert(out.end(), w1.begin(), w1.end());
  out.insert(out.end(), w2.begin(), w2.end());
  return out;
}

std::string default_host()
{
  const char* h = getenv("OTLS_HOST");
  if (h && h[0])
    return h;
  return "restcountries.com";
}
} // namespace

void log_role(int my_party, int64_t role)
{
  std::cerr << "[otls] OtlsConnection::log_role party=" << my_party << " role=" << role
            << std::endl;
}

void tcp_connect(int my_party, int port)
{
  if (my_party != 1)
    return;
  if (tcp_fd >= 0)
    {
      close(tcp_fd);
      tcp_fd = -1;
    }
  std::string host = default_host();
  tcp_fd = connect_tcp(host, port);
  pending_tls_records.clear();
  has_last_ch = false;
  has_last_sh = false;
  has_last_priv = false;
  transcript_ctx_initialized = false;
  nst_phase0_count = 0;
  std::cerr << "[otls] party 1: TCP connected to " << host << ":" << port << " (fd="
            << tcp_fd << ")" << std::endl;
}

void tcp_close(int my_party)
{
  if (my_party != 1)
    return;
  if (tcp_fd >= 0)
    {
      close(tcp_fd);
      std::cerr << "[otls] party 1: TCP closed" << std::endl;
    }
  tcp_fd = -1;
  pending_tls_records.clear();
  has_last_ch = false;
  has_last_sh = false;
  has_last_priv = false;
  transcript_ctx_initialized = false;
  nst_phase0_count = 0;
}

void send_tls_client_hello_poc(int my_party)
{
  if (my_party != 1)
    return;
  if (tcp_fd < 0)
    throw std::runtime_error("OTLS TLS poc: tcp_connect first");
  const char* h = getenv("OTLS_HOST");
  otls_tls_send_client_hello_poc(tcp_fd, h && h[0] ? h : "restcountries.com", &last_ch_msg, &last_priv);
  has_last_ch = true;
  has_last_priv = true;
  std::cerr << "[otls] party 1: TLS ClientHello sent (poc)" << std::endl;
}

void tcp_bcast_send(ArithmeticProcessor& Proc, int my_party, int nbytes, int r_base,
        int n_words)
{
  if (n_words != (nbytes + 7) / 8)
    throw std::runtime_error("OTLS TCP: send n_words mismatch");
  if (my_party != 1)
    return;
  if (tcp_fd < 0)
    throw std::runtime_error("OTLS TCP: send before connect");
  std::vector<uint8_t> buf(nbytes);
  for (int wi = 0; wi < n_words; wi++)
    {
      long w = Proc.read_Ci(r_base + wi);
      uint64_t u = (uint64_t) (long long) w;
      for (int b = 0; b < 8; b++)
        {
          size_t idx = (size_t) wi * 8 + (size_t) b;
          if (idx < buf.size())
            buf[idx] = (uint8_t) ((u >> (8 * b)) & 0xff);
        }
    }
  send_all(tcp_fd, buf.data(), nbytes);
}

void tcp_bcast_recv(ArithmeticProcessor& Proc, Player& P, int my_party, int nbytes,
        int r_base, int n_words)
{
  if (n_words != (nbytes + 7) / 8)
    throw std::runtime_error("OTLS TCP: recv n_words mismatch");
  octetStream os;
  if (my_party == 1)
    {
      if (tcp_fd < 0)
        throw std::runtime_error("OTLS TCP: recv before connect");
      std::vector<uint8_t> buf(nbytes);
      recv_exact(tcp_fd, buf.data(), nbytes);
      os.append(buf.data(), nbytes);
      P.send_all(os);
    }
  else
    P.receive_player(1, os);

  const uint8_t* data = os.get_data();
  size_t len = os.get_length();
  if (len < (size_t) nbytes)
    throw std::runtime_error("OTLS TCP: short broadcast");
  for (int wi = 0; wi < n_words; wi++)
    {
      uint64_t w = 0;
      for (int b = 0; b < 8; b++)
        {
          size_t idx = (size_t) wi * 8 + (size_t) b;
          if (idx < (size_t) nbytes)
            w |= (uint64_t) data[idx] << (8 * b);
        }
      Proc.write_Ci(r_base + wi, (long) w);
    }
}

void tcp_bcast_recv_tls_record(ArithmeticProcessor& Proc, Player& P, int my_party,
        int max_record_bytes, int r_base, int n_words)
{
  int packed_words = (max_record_bytes + 7) / 8;
  if (n_words != 1 + packed_words)
    throw std::runtime_error("OTLS TCP: recv_tls_record n_words mismatch");

  octetStream os;
  if (my_party == 1)
    {
      if (tcp_fd < 0)
        throw std::runtime_error("OTLS TCP: recv_tls_record before connect");
      std::vector<uint8_t> rec;
      if (!pending_tls_records.empty())
        {
          rec = pending_tls_records.front();
          pending_tls_records.pop_front();
        }
      else
        rec = recv_tls_record_or_empty(tcp_fd);
      while (!rec.empty() && rec[0] == 0x14)
        rec = recv_tls_record_or_empty(tcp_fd);
      if ((int) rec.size() > max_record_bytes)
        throw std::runtime_error("OTLS TCP: recv_tls_record exceeds max_record_bytes");
      os.store((int) rec.size());
      if (!rec.empty())
        os.append(rec.data(), rec.size());
      P.send_all(os);
    }
  else
    P.receive_player(1, os);

  int actual_len = os.get<int>();
  if (actual_len < 0 || actual_len > max_record_bytes)
    throw std::runtime_error("OTLS TCP: recv_tls_record invalid length");

  std::vector<uint8_t> rec(actual_len);
  if (actual_len > 0)
    os.consume(rec.data(), rec.size());

  Proc.write_Ci(r_base, actual_len);
  for (int wi = 0; wi < packed_words; wi++)
    {
      uint64_t w = 0;
      for (int bi = 0; bi < 8; bi++)
        {
          size_t idx = (size_t) wi * 8 + (size_t) bi;
          w <<= 8;
          if (idx < rec.size())
            w |= rec[idx];
        }
      Proc.write_Ci(r_base + 1 + wi, (long) w);
    }
}

void tls_export_meta_words_poc(ArithmeticProcessor& Proc, Player& P, int my_party, int r_base,
        int n_words)
{
  if (n_words != 8)
    throw std::runtime_error("OTLS TLS poc meta: need exactly 8 words");
  if (my_party != 1)
    {
      // non-owner parties wait for broadcast payload below
    }

  octetStream os;
  if (my_party == 1)
    {
      if (tcp_fd < 0 || !has_last_ch)
        throw std::runtime_error("OTLS TLS poc meta: call connect + clienthello first");
      auto rec = recv_tls_record(tcp_fd);
      if (rec.size() < 9 || rec[0] != 22)
        throw std::runtime_error("OTLS TLS poc meta: expected handshake record");
      std::vector<uint8_t> sh_msg(rec.begin() + 5, rec.end());
      if (sh_msg.size() < 4)
        throw std::runtime_error("OTLS TLS poc meta: short ServerHello msg");
      last_sh_msg = sh_msg;
      has_last_sh = true;
      auto parsed = decode_server_hello(std::vector<uint8_t>(sh_msg.begin() + 4, sh_msg.end()));
      auto server_pub = parsed.first;
      std::vector<uint8_t> th_input = last_ch_msg;
      th_input.insert(th_input.end(), sh_msg.begin(), sh_msg.end());
      std::vector<uint8_t> th(32);
      SHA256(th_input.data(), th_input.size(), th.data());
      if (server_pub.size() < 32)
        server_pub.resize(32, 0);
      else if (server_pub.size() > 32)
        server_pub.resize(32);

      auto thw = bytes32_to_words_be(th);
      auto spw = bytes32_to_words_be(server_pub);
      for (int i = 0; i < 4; i++)
        {
          uint64_t u = (uint64_t) (long long) thw[i];
          os.append((octet*) &u, sizeof(u));
        }
      for (int i = 0; i < 4; i++)
        {
          uint64_t u = (uint64_t) (long long) spw[i];
          os.append((octet*) &u, sizeof(u));
        }
      std::cerr << "[otls] party 1: exported th(CH||SH)+server_pub (poc)" << std::endl;

      std::cerr << "[otls] party 1: th words:";
      for (int i = 0; i < 4; i++)
        std::cerr << " " << (uint64_t) (unsigned long long) thw[i];
      std::cerr << std::endl;
      std::cerr << "[otls] party 1: spub words:";
      for (int i = 0; i < 4; i++)
        std::cerr << " " << (uint64_t) (unsigned long long) spw[i];
      std::cerr << std::endl;

      {
        EVP_PKEY* our_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
            last_priv.data(), 32);
        EVP_PKEY* their_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
            server_pub.data(), server_pub.size());
        if (our_key && their_key)
          {
            EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(our_key, nullptr);
            EVP_PKEY_derive_init(dctx);
            EVP_PKEY_derive_set_peer(dctx, their_key);
            size_t ss_len = 32;
            uint8_t ss[32];
            EVP_PKEY_derive(dctx, ss, &ss_len);
            EVP_PKEY_CTX_free(dctx);
            std::cerr << "[otls] party 1: expected shared secret (hex): ";
            for (size_t d = 0; d < ss_len; d++)
              std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int) ss[d];
            std::cerr << std::dec << std::endl;
            auto ssw = bytes32_to_words_be(std::vector<uint8_t>(ss, ss + 32));
            std::cerr << "[otls] party 1: expected ss words:";
            for (int i = 0; i < 4; i++)
              std::cerr << " " << (uint64_t) (unsigned long long) ssw[i];
            std::cerr << std::endl;
          }
        if (our_key)
          EVP_PKEY_free(our_key);
        if (their_key)
          EVP_PKEY_free(their_key);
      }
    }

  // use party channels (same pattern as other OTLS ops)
  if (my_party == 1)
    P.send_all(os);
  else
    P.receive_player(1, os);

  for (int i = 0; i < 8; i++)
    {
      uint64_t u = 0;
      os.consume((octet*) &u, sizeof(u));
      Proc.write_Ci(r_base + i, (long) (long long) u);
    }
}

void tls_write_scalar_input_poc(ArithmeticProcessor& Proc, int my_party)
{
  if (my_party != 1)
    return;
  if (!has_last_priv)
    throw std::runtime_error("OTLS scalar handoff: call tls_clienthello first");

  auto shares = split_scalar_three_shares(last_priv.data());

  std::string prefix = OnlineOptions::singleton.cmd_private_input_file;
  if (prefix.empty())
    prefix = "Player-Data/Input";
  std::string filename = prefix + "-P" + std::to_string(my_party) + "-"
      + std::to_string(Proc.get_thread_num());

  std::ofstream out(filename, std::ios::out | std::ios::trunc);
  if (!out.is_open())
    throw std::runtime_error("OTLS scalar handoff: failed to open " + filename);
  for (auto w : shares)
    out << w << "\n";
  out.flush();
  out.close();

  std::cerr << "[otls] party 1: wrote scalar shares to " << filename << std::endl;
  std::cerr << "[otls] party 1: share words:";
  for (size_t i = 0; i < shares.size(); i++)
    std::cerr << " " << shares[i];
  std::cerr << std::endl;
}
void tls_feed_hs_plain_poc(ArithmeticProcessor& Proc, Player& P, int my_party,
        int max_bytes, int r_base, int n_words)
{
  int packed_words = (max_bytes + 7) / 8;
  if (n_words != 1 + packed_words)
    throw std::runtime_error("OTLS TLS feed_hs_plain: n_words mismatch");

  int actual_len = (int) Proc.read_Ci(r_base);

  octetStream os;
  if (my_party == 1)
    {
      if (!has_last_ch || !has_last_sh)
        throw std::runtime_error("OTLS TLS feed_hs_plain: missing ch/sh (call export_meta first)");

      if (!transcript_ctx_initialized)
        {
          SHA256_Init(&transcript_ctx);
          SHA256_Update(&transcript_ctx, last_ch_msg.data(), last_ch_msg.size());
          SHA256_Update(&transcript_ctx, last_sh_msg.data(), last_sh_msg.size());
          transcript_ctx_initialized = true;
          nst_phase0_count = 0;
          std::cerr << "[otls] party 1: transcript ctx init (ch="
                    << last_ch_msg.size() << " sh=" << last_sh_msg.size() << ")" << std::endl;
        }

      int inner_ct = 0;
      if (actual_len > 0)
        {
          std::vector<uint8_t> buf(actual_len);
          for (int wi = 0; wi < packed_words; wi++)
            {
              long w = Proc.read_Ci(r_base + 1 + wi);
              uint64_t u = (uint64_t) (long long) w;
              for (int bi = 0; bi < 8; bi++)
                {
                  size_t idx = (size_t) wi * 8 + (size_t) bi;
                  if (idx < (size_t) actual_len)
                    buf[idx] = (uint8_t) ((u >> (8 * (7 - bi))) & 0xff);
                }
            }
          inner_ct = buf[actual_len - 1];
          int msg_len = actual_len - 1;
          {
            std::cerr << "[otls] party 1: feed buf actual_len=" << actual_len
                      << " first8=[";
            for (int d = 0; d < std::min(8, actual_len); d++)
              std::cerr << std::hex << std::setw(2) << std::setfill('0')
                        << (int) buf[d];
            std::cerr << "] last4=[";
            for (int d = std::max(0, actual_len - 4); d < actual_len; d++)
              std::cerr << std::hex << std::setw(2) << std::setfill('0')
                        << (int) buf[d];
            std::cerr << "]" << std::dec << std::endl;
          }
          if (inner_ct == 0x16)
            {
              SHA256_Update(&transcript_ctx, buf.data(), msg_len);
              std::cerr << "[otls] party 1: transcript feed " << msg_len
                        << " B (inner_ct=0x16)" << std::endl;
            }
          else
            {
              nst_phase0_count++;
              std::cerr << "[otls] party 1: transcript skip inner_ct=0x"
                        << std::hex << inner_ct << std::dec << " (nst#"
                        << nst_phase0_count << ")" << std::endl;
            }
        }
      os.store(inner_ct);
      P.send_all(os);
    }
  else
    P.receive_player(1, os);
}

void tls_finalize_th_sf_poc(ArithmeticProcessor& Proc, Player& P, int my_party,
        int r_base, int n_words)
{
  if (n_words != 5)
    throw std::runtime_error("OTLS TLS finalize_th_sf: need exactly 5 output words");

  octetStream os;
  if (my_party == 1)
    {
      if (!transcript_ctx_initialized)
        throw std::runtime_error("OTLS TLS finalize_th_sf: no transcript ctx (call feed first)");

      std::vector<uint8_t> th_sf(32);
      SHA256_CTX ctx_copy = transcript_ctx;
      SHA256_Final(th_sf.data(), &ctx_copy);

      auto thw = bytes32_to_words_be(th_sf);
      for (int i = 0; i < 4; i++)
        {
          uint64_t u = (uint64_t) (long long) thw[i];
          os.append((octet*) &u, sizeof(u));
        }
      os.store(nst_phase0_count);

      transcript_ctx_initialized = false;
      std::cerr << "[otls] party 1: th_sf finalized, n_nst_phase0=" << nst_phase0_count
                << std::endl;
    }

  if (my_party == 1)
    P.send_all(os);
  else
    P.receive_player(1, os);

  for (int i = 0; i < 4; i++)
    {
      uint64_t u = 0;
      os.consume((octet*) &u, sizeof(u));
      Proc.write_Ci(r_base + i, (long) (long long) u);
    }
  Proc.write_Ci(r_base + 4, (long) os.get<int>());
}

void tcp_send_record_be(ArithmeticProcessor& Proc, int my_party, int max_bytes,
        int r_base, int n_words)
{
  int packed_words = (max_bytes + 7) / 8;
  if (n_words != 1 + packed_words)
    throw std::runtime_error("OTLS TCP: send_record_be n_words mismatch (need 1+"
        + std::to_string(packed_words) + ", got " + std::to_string(n_words) + ")");

  int actual_len = (int) Proc.read_Ci(r_base);
  if (actual_len < 0 || actual_len > max_bytes)
    throw std::runtime_error("OTLS TCP: send_record_be actual_len out of range ("
        + std::to_string(actual_len) + " vs max " + std::to_string(max_bytes) + ")");

  if (my_party != 1)
    return;
  if (tcp_fd < 0)
    throw std::runtime_error("OTLS TCP: send_record_be before connect");

  std::vector<uint8_t> buf(actual_len);
  for (int wi = 0; wi < packed_words; wi++)
    {
      long w = Proc.read_Ci(r_base + 1 + wi);
      uint64_t u = (uint64_t) (long long) w;
      for (int bi = 0; bi < 8; bi++)
        {
          size_t idx = (size_t) wi * 8 + (size_t) bi;
          if (idx < (size_t) actual_len)
            buf[idx] = (uint8_t) ((u >> (8 * (7 - bi))) & 0xff);
        }
    }
  send_all(tcp_fd, buf.data(), actual_len);
  std::cerr << "[otls] party 1: sent " << actual_len << " bytes (send_record_be)" << std::endl;
}

void tcp_bcast_wait_readable(ArithmeticProcessor& Proc, Player& P, int my_party,
        int timeout_ms, int r_base)
{
  octetStream os;
  if (my_party == 1)
    {
      int ready = 0;
      if (tcp_fd >= 0)
        {
          fd_set rfds;
          FD_ZERO(&rfds);
          FD_SET(tcp_fd, &rfds);
          timeval tv {};
          tv.tv_sec = timeout_ms / 1000;
          tv.tv_usec = (timeout_ms % 1000) * 1000;
          int rc = select(tcp_fd + 1, &rfds, nullptr, nullptr, &tv);
          ready = (rc > 0 && FD_ISSET(tcp_fd, &rfds)) ? 1 : 0;
        }
      os.store(ready);
      P.send_all(os);
    }
  else
    P.receive_player(1, os);

  int ready = os.get<int>();
  Proc.write_Ci(r_base, ready);
}
} // namespace OtlsConnection
