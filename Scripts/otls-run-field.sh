#!/usr/bin/env bash
# Launch MPC field-mode OTLS demo + Python gateway in MPC-X25519 mode.
# Usage: ./Scripts/otls-run-field.sh [host] [port] [path]

set -e
HERE=$(cd "$(dirname "$0")"; pwd)
SPDZROOT="$HERE/.."
cd "$SPDZROOT"

HOST="${1:-restcountries.com}"
PORT="${2:-443}"
PATH_ARG="${3:-/v3.1/name/deutschland}"
MPC_PORT=18000
PRIME=57896044618658097711785492504343953926634992332820282019728792003956564819949
PROGRAM="otls_demo_field"

echo "=== Compile field-mode program ==="
if [ "${OTLS_SKIP_COMPILE:-0}" = "1" ]; then
  echo "Skipping compile (OTLS_SKIP_COMPILE=1)"
else
  ./compile.py -F 253 -P "$PRIME" "$PROGRAM" >/dev/null
fi

echo "=== Ensure field party binary exists ==="
if [ ! -x ./replicated-field-party.x ]; then
  make -j2 MOD='-DGFP_MOD_SZ=5' replicated-field-party.x >/dev/null
fi

echo "=== Starting gateway in MPC-X25519 mode ==="
OTLS_MPC_X25519=1 python3 ExternalIO/otls_gateway.py "$HOST" "$PORT" "$PATH_ARG" "$MPC_PORT" &
GW_PID=$!

sleep 2

echo "=== Starting 3 replicated-field parties (prime set at runtime) ==="
PORT=14000 ./Scripts/rep-field.sh "$PROGRAM" -P "$PRIME" &
MPC_PID=$!

wait $GW_PID 2>/dev/null
GW_EXIT=$?
wait $MPC_PID 2>/dev/null || true
echo "=== Done (gateway exit=$GW_EXIT) ==="
