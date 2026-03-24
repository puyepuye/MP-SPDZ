#!/usr/bin/env bash
# OTLS demo: compile the MPC program, start 3 ring parties, run the TLS driver.
#
# Usage:  Scripts/otls-demo.sh <https-url>
# Example: Scripts/otls-demo.sh https://pokeapi.co/api/v2/pokemon/ditto
set -e

URL="${1:?Usage: Scripts/otls-demo.sh <https-url>}"

cd "$(dirname "$0")/.."          # MP-SPDZ root

# Inter-party port (parties talk to each other) -- must differ from ExternalIO port (14000)
PARTY_PORT=7770
# ExternalIO port (set inside otls_demo.mpc = 14000, client connects here)
CLIENT_PORT=18000

# ---------- compile MPC program ----------
echo "[otls-demo] compiling otls_demo.mpc ..."
./compile.py otls_demo

# ---------- start 3 replicated-ring parties in background ----------
echo "[otls-demo] starting 3 replicated-ring parties ..."
echo "[otls-demo]   inter-party port base: $PARTY_PORT"
echo "[otls-demo]   ExternalIO client port base: $CLIENT_PORT"
PORT=$PARTY_PORT Scripts/ring.sh otls_demo &
MPC_PID=$!

cleanup() { kill $MPC_PID 2>/dev/null; wait $MPC_PID 2>/dev/null; }
trap cleanup EXIT INT TERM

sleep 4   # give parties time to start and listen

# ---------- run the TLS + MPC driver ----------
echo "[otls-demo] running OTLS driver against $URL ..."
python3 ExternalIO/otls_driver.py "$URL" --parties 3 --port "$CLIENT_PORT"
