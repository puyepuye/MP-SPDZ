#!/usr/bin/env bash
# Run OTLS field VM: full TLS 1.3 handshake + HTTP fetch.
#
# Usage:
#   ./Scripts/otls-run-field-vm.sh
#   OTLS_HOST=example.com OTLS_PATH=/api ./Scripts/otls-run-field-vm.sh
#
# Environment variables (override defaults):
#   OTLS_HOST           target HTTPS host   (default: restcountries.com)
#   OTLS_PATH           HTTP request path   (default: /v3.1/name/peru)
#   OTLS_SKIP_BUILD=1   skip C++ rebuild

set -e
HERE=$(cd "$(dirname "$0")"; pwd)
SPDZROOT="$HERE/.."
cd "$SPDZROOT"

# Curve25519 field prime (2^255 - 19). Not user-configurable; fixed by X25519.
OTLS_PRIME=57896044618658097711785492504343953926634992332820282019728792003956564819949

export OTLS_HOST="${OTLS_HOST:-restcountries.com}"
export OTLS_PATH="${OTLS_PATH:-/v3.1/name/peru}"
PROGRAM="otls_demo_field_vm"

echo "=== OTLS Config ==="
echo "  Host: $OTLS_HOST"
echo "  Path: $OTLS_PATH"
echo ""

echo "=== Compile $PROGRAM ==="
./compile.py -F 253 -P "$OTLS_PRIME" "$PROGRAM"

if [ "${OTLS_SKIP_BUILD:-0}" != "1" ]; then
    echo "=== Build replicated-field-party ==="
    touch "$SPDZROOT/Machines/replicated-field-party.cpp"
    make -j4 replicated-field-party.x
fi

echo "=== Run 3 parties (connecting to $OTLS_HOST:443) ==="
export PLAYERS=3
PORT=14000 ./Scripts/rep-field.sh "$PROGRAM" -P "$OTLS_PRIME" 2>&1 \
    | python3 Scripts/otls-decode-response.py
