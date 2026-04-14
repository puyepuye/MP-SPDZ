#!/usr/bin/env bash
# Run OTLS field VM: full TLS 1.3 handshake + HTTP fetch, no ExternalIO client.
# Usage:
#   OTLS_HOST=restcountries.com ./Scripts/otls-run-field-vm.sh

set -e
HERE=$(cd "$(dirname "$0")"; pwd)
SPDZROOT="$HERE/.."
cd "$SPDZROOT"

export OTLS_HOST="${OTLS_HOST:-restcountries.com}"
PRIME=57896044618658097711785492504343953926634992332820282019728792003956564819949
PROGRAM="otls_demo_field_vm"

echo "=== Compile $PROGRAM (field 253-bit) ==="
./compile.py -F 253 -P "$PRIME" "$PROGRAM"

echo "=== Build replicated-field-party (touch to catch opcode edits) ==="
touch "$SPDZROOT/Machines/replicated-field-party.cpp"
make -j4 replicated-field-party.x

echo "=== Run 3 parties (party 1 connects to $OTLS_HOST:443) ==="
export PLAYERS=3
PORT=14000 ./Scripts/rep-field.sh "$PROGRAM" -P "$PRIME"
