#!/usr/bin/env bash
# Launch replicated-ring MPC parties + C++ ExternalIO TLS client (otls-external-io-client.x).
# Usage: ./Scripts/otls-run.sh [host] [port] [path]

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

echo "=== Building C++ ExternalIO TLS client ==="
make -j2 otls-external-io-client.x >/dev/null

echo "=== Starting 3 replicated-ring parties (inter-party port $PARTY_PORT, client port $MPC_PORT) ==="
PORT=$PARTY_PORT ./Scripts/ring.sh "$PROGRAM" &
MPC_PID=$!

echo "=== Waiting for MPC parties to initialize ==="
sleep 4

echo "=== Starting C++ bridge: $HOST:$PORT$PATH_ARG ==="
./otls-external-io-client.x "$HOST" "$PORT" "$PATH_ARG" "$MPC_PORT"
GW_EXIT=$?

wait $MPC_PID 2>/dev/null || true
echo "=== Done (bridge exit=$GW_EXIT) ==="
