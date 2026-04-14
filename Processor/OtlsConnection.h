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

/** Party 1 reads ServerHello, computes th(CH||SH), extracts server X25519 pubkey, and
 *  writes 8 words: th words (4) + server_pub words (4). */
void tls_export_meta_words_poc(ArithmeticProcessor& Proc, Player& P, int my_party, int r_base,
        int n_words);

/** Party 1 writes 12 scalar-share words into Input-P1-<thread> for secure
 *  ``sint.Array(...).input_from(1)`` in VM-only mode. */
void tls_write_scalar_input_poc(ArithmeticProcessor& Proc, int my_party);

/** Party 1 unpacks BE-packed clear words from ``Ci[r_base+1..]`` to ``Ci[r_base]``
 *  bytes and sends them on the TCP socket. Other parties no-op but must execute. */
void tcp_send_record_be(ArithmeticProcessor& Proc, int my_party, int max_bytes,
        int r_base, int n_words);

/** Party 1 polls ``select()`` on the TCP fd with ``timeout_ms`` and broadcasts the
 *  result (1=readable, 0=timeout) to all parties via ``Ci[r_base]``. */
void tcp_bcast_wait_readable(ArithmeticProcessor& Proc, Player& P, int my_party,
        int timeout_ms, int r_base);

/** Feed one decrypted HS plaintext record into the running SHA-256 transcript.
 *  On first call, seeds with stored CH + SH messages. Records with inner_ct == 0x16
 *  contribute to the hash; others increment the NST counter. ``src`` is ``[actual_len,
 *  BE_words...]``. All parties must call; party 1 drives, broadcasts inner_ct. */
void tls_feed_hs_plain_poc(ArithmeticProcessor& Proc, Player& P, int my_party,
        int max_bytes, int r_base, int n_words);

/** Finalize th_sf = SHA-256(CH || SH || HS messages) and output 5 words:
 *  ``dest[0:4]`` = th_sf (BE 64-bit words), ``dest[4]`` = n_nst_phase0. */
void tls_finalize_th_sf_poc(ArithmeticProcessor& Proc, Player& P, int my_party,
        int r_base, int n_words);
} // namespace OtlsConnection

#endif
