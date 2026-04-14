#ifndef PROCESSOR_OTLSTLSCLIENTHELLOPOC_H_
#define PROCESSOR_OTLSTLSCLIENTHELLOPOC_H_

#include <array>
#include <vector>

/** Send a TLS 1.3 ClientHello (X25519) as raw bytes on an existing TCP fd (party 1).
 *  SNI uses ``server_name`` (e.g. restcountries.com). For in-VM POC only.
 *  Optionally exports raw ClientHello handshake bytes and X25519 private scalar. */
void otls_tls_send_client_hello_poc(int tcp_fd, const char* server_name,
        std::vector<uint8_t>* out_ch_msg = nullptr,
        std::array<uint8_t, 32>* out_priv = nullptr);

#endif
