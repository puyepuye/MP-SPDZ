#ifndef PROCESSOR_OTLSCONNECTION_H_
#define PROCESSOR_OTLSCONNECTION_H_

#include <cstdint>

class Player;
class ArithmeticProcessor;

namespace OtlsConnection
{
/** Hook for in-process OTLS work: C++ sees party index and an immediate role tag.
 *  Convention (pf-notes): 0 = hello/sender emphasis, 1 = TCP/socket owner, etc. */
void log_role(int my_party, int64_t role);

/** TLS/HTTPS bridge TCP fd is owned only by party 1 (see pf-notes). Other parties
 *  skip fd ops but stay synchronized on broadcast instructions. */
void tcp_connect(int my_party, int port);
void tcp_close(int my_party);

/** Pack clear registers [r_base, +n_words) as little-endian bytes (nbytes total)
 *  and send on party 1 only. */
void tcp_bcast_send(ArithmeticProcessor& Proc, int my_party, int nbytes, int r_base,
        int n_words);

/** Party 1 recv() exactly nbytes from TCP; broadcast blob; all parties unpack LE
 *  words into Ci[r_base + i]. */
void tcp_bcast_recv(ArithmeticProcessor& Proc, Player& P, int my_party, int nbytes,
        int r_base, int n_words);

/** Party 1: send TLS 1.3 ClientHello on existing TCP (uses ``OTLS_HOST`` for SNI). */
void send_tls_client_hello_poc(int my_party);

/** Party 1 receives one TLS record (header+payload), broadcasts raw bytes, and writes
 *  ``Ci[r_base] = actual_len`` plus BE-packed 64-bit words at ``Ci[r_base+1..]``. */
void tcp_bcast_recv_tls_record(ArithmeticProcessor& Proc, Player& P, int my_party,
        int max_record_bytes, int r_base, int n_words);
} // namespace OtlsConnection

#endif
