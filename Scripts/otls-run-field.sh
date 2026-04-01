#!/usr/bin/env bash
# Field-mode OTLS: otls_demo_field.mpc + C++ ExternalIO client (otls-external-io-client.x).
# Wire order: MPC X25519 field path. TLS runs in the ExternalIO client only.
# Usage: ./Scripts/otls-run-field.sh [host] [port] [path]
#
# Requires: make MOD='-DGFP_MOD_SZ=5' for both replicated-field-party.x and otls-external-io-client.x (same gfp limbs).

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
MOD="-DGFP_MOD_SZ=5"
[ -n "${OTLS_MOD:-}" ] && MOD="$OTLS_MOD"

echo "=== Compile field-mode program ==="
if [ "${OTLS_SKIP_COMPILE:-0}" = "1" ]; then
  echo "Skipping compile (OTLS_SKIP_COMPILE=1)"
else
  ./compile.py -F 253 -P "$PRIME" "$PROGRAM" >/dev/null
fi

echo "=== Ensure field party + C++ bridge (MOD=$MOD) ==="
make -j2 MOD="$MOD" replicated-field-party.x otls-external-io-client.x >/dev/null

echo "=== Starting 3 replicated-field parties (must listen before bridge connects) ==="
PORT=14000 ./Scripts/rep-field.sh "$PROGRAM" -P "$PRIME" &
MPC_PID=$!

sleep 3

echo "=== Starting C++ ExternalIO TLS client (field MPC: 3 scalar shares + server pub) ==="
./otls-external-io-client.x "$HOST" "$PORT" "$PATH_ARG" "$MPC_PORT" &
GW_PID=$!

wait $GW_PID 2>/dev/null
GW_EXIT=$?
wait $MPC_PID 2>/dev/null || true
echo "=== Done (bridge exit=$GW_EXIT) ==="
