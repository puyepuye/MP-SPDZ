#include "Processor/OtlsConnection.h"

#include <iostream>

namespace OtlsConnection
{
void log_role(int my_party, int64_t role)
{
  std::cerr << "[otls] OtlsConnection::log_role party=" << my_party
            << " role=" << role << std::endl;
}
}
