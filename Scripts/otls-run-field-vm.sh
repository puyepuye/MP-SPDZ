#!/usr/bin/env bash
# Run OTLS field VM: full TLS 1.3 handshake + HTTP fetch.
#
# Usage:
#   ./Scripts/otls-run-field-vm.sh                          # uses defaults from otls.conf
#   OTLS_HOST=example.com OTLS_PATH=/api ./Scripts/otls-run-field-vm.sh
#
# Environment variables (override otls.conf):
#   OTLS_HOST   target HTTPS host
#   OTLS_PATH   HTTP request path
#   OTLS_SKIP_BUILD=1   skip C++ rebuild

set -e
HERE=$(cd "$(dirname "$0")"; pwd)
SPDZROOT="$HERE/.."
cd "$SPDZROOT"

# Load config (env vars take priority)
if [ -f "$SPDZROOT/otls.conf" ]; then
    source "$SPDZROOT/otls.conf"
fi
export OTLS_HOST="${OTLS_HOST:-$OTLS_HOST}"
export OTLS_PATH="${OTLS_PATH:-$OTLS_PATH}"
PRIME="${OTLS_PRIME}"
PROGRAM="otls_demo_field_vm"

echo "=== OTLS Config ==="
echo "  Host: $OTLS_HOST"
echo "  Path: $OTLS_PATH"
echo ""

echo "=== Compile $PROGRAM ==="
./compile.py -F 253 -P "$PRIME" "$PROGRAM"

if [ "${OTLS_SKIP_BUILD:-0}" != "1" ]; then
    echo "=== Build replicated-field-party ==="
    touch "$SPDZROOT/Machines/replicated-field-party.cpp"
    make -j4 replicated-field-party.x
fi

echo "=== Run 3 parties (connecting to $OTLS_HOST:443) ==="
export PLAYERS=3
PORT=14000 ./Scripts/rep-field.sh "$PROGRAM" -P "$PRIME" 2>&1 \
    | python3 Scripts/otls-decode-response.py
