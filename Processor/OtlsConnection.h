#ifndef PROCESSOR_OTLSCONNECTION_H_
#define PROCESSOR_OTLSCONNECTION_H_

#include <cstdint>

namespace OtlsConnection
{
/** Hook for in-process OTLS work: C++ sees party index and an immediate role tag.
 *  Convention (pf-notes): 0 = hello/sender emphasis (party 0), 1 = TCP/socket owner (party 1), etc. */
void log_role(int my_party, int64_t role);
}

#endif
