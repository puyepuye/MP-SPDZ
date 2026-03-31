#!/usr/bin/env bash
# Launch MPC parties + C++ OTLS bridge.
# Usage: ./Scripts/otls-run-cpp.sh [host] [port] [path]

set -e
HERE=$(cd "$(dirname "$0")"; pwd)
SPDZROOT="$HERE/.."
cd "$SPDZROOT"

HOST="${1:-restcountries.com}"
PORT="${2:-443}"
PATH_ARG="${3:-/v3.1/name/deutschland}"
MPC_PORT=18000
PARTY_PORT=14000
PROGRAM="${OTLS_PROGRAM:-otls_demo}"

echo "=== Building C++ OTLS bridge ==="
make -j2 otls-gateway.x >/dev/null

echo "=== Starting 3 replicated-ring parties (inter-party port $PARTY_PORT, client port $MPC_PORT) ==="
PORT=$PARTY_PORT ./Scripts/ring.sh "$PROGRAM" &
MPC_PID=$!

echo "=== Waiting for MPC parties to initialize ==="
sleep 4

echo "=== Starting C++ gateway: $HOST:$PORT$PATH_ARG ==="
./otls-gateway.x "$HOST" "$PORT" "$PATH_ARG" "$MPC_PORT"
GW_EXIT=$?

wait $MPC_PID 2>/dev/null || true
echo "=== Done (gateway exit=$GW_EXIT) ==="
