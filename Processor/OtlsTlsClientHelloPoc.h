#ifndef PROCESSOR_OTLSTLSCLIENTHELLOPOC_H_
#define PROCESSOR_OTLSTLSCLIENTHELLOPOC_H_

/** Send a TLS 1.3 ClientHello (X25519) as raw bytes on an existing TCP fd (party 1).
 *  SNI uses ``server_name`` (e.g. restcountries.com). For in-VM POC only. */
void otls_tls_send_client_hello_poc(int tcp_fd, const char* server_name);

#endif
