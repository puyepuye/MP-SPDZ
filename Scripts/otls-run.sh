#!/usr/bin/env bash
# Launch MPC parties + gateway in one go.
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

# Start gateway first — it connects to the TLS server and reads HS records,
# then retries MPC connection until parties are ready.
echo "=== Starting gateway: $HOST:$PORT$PATH_ARG ==="
python3 ExternalIO/otls_gateway.py "$HOST" "$PORT" "$PATH_ARG" "$MPC_PORT" &
GW_PID=$!

# Give the gateway a moment to start the TLS handshake before MPC parties.
sleep 2

echo "=== Starting 3 replicated-ring parties (inter-party port $PARTY_PORT, client port $MPC_PORT) ==="
PORT=$PARTY_PORT ./Scripts/ring.sh otls_demo &
MPC_PID=$!

wait $GW_PID 2>/dev/null
GW_EXIT=$?
wait $MPC_PID 2>/dev/null || true
echo "=== Done (gateway exit=$GW_EXIT) ==="
