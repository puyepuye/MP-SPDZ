#!/usr/bin/env bash
# In-VM OTLS TCP POC (party 1 holds fd; broadcast send/recv). No otls-external-io-client.x.
# Usage:
#   OTLS_HOST=restcountries.com ./Scripts/otls-run-tcp-poc.sh
#
set -e
HERE=$(cd "$(dirname "$0")"; pwd)
SPDZROOT="$HERE/.."
cd "$SPDZROOT"

export OTLS_HOST="${OTLS_HOST:-restcountries.com}"

echo "=== Compiling otls_tcp_poc (OTLS_HOST=$OTLS_HOST) ==="
./compile.py otls_tcp_poc >/dev/null

echo "=== Building replicated-field-party (touch to pick up Instruction.hpp opcode changes) ==="
touch "$SPDZROOT/Machines/replicated-field-party.cpp"
make -j4 replicated-field-party.x >/dev/null

echo "=== 3 parties (party 1: TCP $OTLS_HOST:443 + TLS ClientHello poc) ==="
export PLAYERS=3
PORT=14000 ./Scripts/rep-field.sh otls_tcp_poc
