#include "Processor/OtlsConnection.h"
#include "Processor/OtlsTlsClientHelloPoc.h"

#include "Networking/Player.h"
#include "Processor/Processor.h"
#include "Tools/octetStream.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
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
}

void send_tls_client_hello_poc(int my_party)
{
  if (my_party != 1)
    return;
  if (tcp_fd < 0)
    throw std::runtime_error("OTLS TLS poc: tcp_connect first");
  const char* h = getenv("OTLS_HOST");
  otls_tls_send_client_hello_poc(tcp_fd, h && h[0] ? h : "restcountries.com");
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
      auto rec = recv_tls_record(tcp_fd);
      if ((int) rec.size() > max_record_bytes)
        throw std::runtime_error("OTLS TCP: recv_tls_record exceeds max_record_bytes");
      os.store((int) rec.size());
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
} // namespace OtlsConnection
