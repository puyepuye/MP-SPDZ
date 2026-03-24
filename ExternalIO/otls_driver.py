#!/usr/bin/env python3
"""
OTLS driver: performs a TLS 1.3 handshake against a real HTTPS server,
routing the X25519 shared secret through MP-SPDZ MPC parties (ExternalIO).

Usage:
    python3 ExternalIO/otls_driver.py https://example.com/path [--parties 3] [--port 14000]

Requires:
  - MP-SPDZ parties already running the otls_demo program
  - gmpy2  (pip install gmpy2)
  - otls repo at ../otls relative to MP-SPDZ root
"""

import argparse
import os
import socket as socket_mod
import sys

from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Path setup  (must happen before tls.* imports)
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MPSPDZ_ROOT = os.path.dirname(SCRIPT_DIR)
OTLS_ROOT = os.path.abspath(os.path.join(MPSPDZ_ROOT, "..", "otls"))
sys.path.insert(0, OTLS_ROOT)

# ExternalIO client lives next to this script
from client import Client, octetStream  # noqa: E402

# otls TLS primitives (no stdlib name conflict for "tls")
from tls.crypto import (  # noqa: E402
    x25519_private_key,
    x25519_public_key,
    x25519_derive_shared_secret,
)
from tls.handshake import encode_client_hello, decode_server_hello, encode_finished  # noqa: E402
from tls.key_schedule import (  # noqa: E402
    handshake_secret_and_server_handshake_keys,
    client_handshake_keys_and_finished_key,
    application_traffic_secrets,
    compute_finished,
)
from tls.record import (  # noqa: E402
    send_plaintext,
    read_record,
    read_record_with_len,
    send_application_data,
    decrypt_application_data,
    strip_inner_plaintext,
    RECORD_TYPE_HANDSHAKE,
    RECORD_TYPE_APPLICATION_DATA,
    RECORD_TYPE_CHANGE_CIPHER_SPEC,
)
from tls.connection import TLSConnection  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers (inlined to avoid stdlib "http" package name collision)
# ---------------------------------------------------------------------------
MSG_FINISHED = 20


def _build_get(host: str, path: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "User-Agent: otls/0.1\r\n"
        "\r\n"
    ).encode()


def _parse_status(raw: bytes) -> int:
    idx = raw.find(b"\r\n")
    if idx == -1:
        return 0
    line = raw[:idx].decode("ascii", errors="replace")
    parts = line.split(" ", 2)
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


def _find_finished(stream: bytes):
    off = 0
    while off + 4 <= len(stream):
        t = stream[off]
        length = int.from_bytes(stream[off + 1 : off + 4], "big")
        if off + 4 + length > len(stream):
            return None
        if t == MSG_FINISHED:
            return off + 4 + length
        off += 4 + length
    return None


def _split(data: bytes, chunk: int = 8) -> list[int]:
    return [int.from_bytes(data[i : i + chunk], "big") for i in range(0, len(data), chunk)]


def _join(vals: list[int], chunk: int = 8) -> bytes:
    mask = (1 << (chunk * 8)) - 1
    return b"".join((v & mask).to_bytes(chunk, "big") for v in vals)


# ---------------------------------------------------------------------------
# MPC round-trip: send 32 bytes through parties, get 32 bytes back
# ---------------------------------------------------------------------------
def _mpc_passthrough(mpc: Client, data_32: bytes) -> bytes:
    chunks = _split(data_32)
    for sock in mpc.sockets:
        o = octetStream()
        o.store(1)  # finish flag
        o.Send(sock)
    mpc.send_private_inputs(chunks)
    out = mpc.receive_outputs(len(chunks))
    return _join(out)


# ---------------------------------------------------------------------------
# Main: TLS 1.3 handshake + HTTP fetch
# ---------------------------------------------------------------------------
def otls_fetch(url: str, n_parties: int = 3, port_base: int = 14000) -> int:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    log = lambda m: print(f"[OTLS] {m}", file=sys.stderr)  # noqa: E731
    log(f"target {host}:{port}{path}")

    # 1) Connect to MPC parties ------------------------------------------
    log(f"connecting to {n_parties} MPC parties (port base {port_base}) ...")
    mpc = Client(["localhost"] * n_parties, port_base, 0)
    log("MPC parties connected")

    # 2) TCP to real server -----------------------------------------------
    log(f"TCP -> {host}:{port}")
    sock = socket_mod.create_connection((host, port), timeout=15)
    sock.settimeout(15)
    log("TCP connected")

    # 3) ClientHello ------------------------------------------------------
    priv = x25519_private_key()
    pub = x25519_public_key(priv)
    ch = encode_client_hello(os.urandom(32), pub, "http/1.1", server_name=host)
    send_plaintext(sock.send, RECORD_TYPE_HANDSHAKE, ch)
    log("ClientHello sent")

    # 4) ServerHello ------------------------------------------------------
    ct, payload = read_record(sock.recv)
    if ct != RECORD_TYPE_HANDSHAKE:
        raise ConnectionError(f"expected handshake, got type {ct}")
    sh_len = int.from_bytes(payload[1:4], "big")
    sh = payload[: 4 + sh_len]
    _, srv_pub, cipher = decode_server_hello(sh[4:])
    log(f"ServerHello OK  cipher=0x{cipher:04x}")

    # 5) Shared secret: compute locally, then route through MPC -----------
    shared = x25519_derive_shared_secret(priv, srv_pub)
    log("routing shared secret through MPC parties ...")
    mpc_shared = _mpc_passthrough(mpc, shared)
    log(f"MPC round-trip OK  (match={mpc_shared == shared})")

    # 6) Key schedule (uses MPC-returned secret) --------------------------
    hs_sec, s_hs_keys, _ = handshake_secret_and_server_handshake_keys(
        mpc_shared, ch, sh, cipher
    )

    # 7) Encrypted server handshake (EE, Cert, CertVerify, Finished) ------
    seq = 0
    srv_hs = b""
    while True:
        ct2, enc, _, hdr = read_record_with_len(sock.recv)
        if ct2 == RECORD_TYPE_CHANGE_CIPHER_SPEC:
            continue
        if ct2 != RECORD_TYPE_APPLICATION_DATA:
            raise ConnectionError(f"expected app-data, got {ct2}")
        raw = decrypt_application_data(s_hs_keys.key, s_hs_keys.iv, seq, enc, hdr, cipher)
        seq += 1
        inner_t, frag = strip_inner_plaintext(raw)
        if inner_t != RECORD_TYPE_HANDSHAKE:
            raise ConnectionError(f"expected handshake inner, got {inner_t}")
        srv_hs += frag
        end = _find_finished(srv_hs)
        if end is not None:
            srv_hs = srv_hs[:end]
            break
    log("server handshake decrypted")

    # 8) Client keys + Finished -------------------------------------------
    c_hs_keys, fin_key, th_full = client_handshake_keys_and_finished_key(
        hs_sec, ch, sh, srv_hs, cipher
    )
    vd = compute_finished(fin_key, th_full, cipher)
    finished_msg = encode_finished(vd)

    c_app, s_app = application_traffic_secrets(hs_sec, ch + sh + srv_hs, cipher)

    send_application_data(
        sock.send, c_hs_keys.key, c_hs_keys.iv, 0, finished_msg + b"\x16", cipher
    )
    log("Client Finished sent  -- handshake complete")

    # 9) HTTP GET ---------------------------------------------------------
    conn = TLSConnection(sock, c_app, s_app, "http/1.1", cipher_suite=cipher)
    conn.send(_build_get(host, path))
    log("HTTP GET sent")

    resp = b""
    while True:
        try:
            chunk = conn.recv(16384)
        except Exception:
            break
        if not chunk:
            break
        resp += chunk

    status = _parse_status(resp)
    log(f"HTTP {status}  ({len(resp)} bytes)")
    print(resp.decode("utf-8", errors="replace"))
    conn.close()
    return status


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="OTLS: MPC-backed TLS 1.3 client")
    p.add_argument("url", help="HTTPS URL to fetch")
    p.add_argument("--parties", type=int, default=3)
    p.add_argument("--port", type=int, default=14000)
    args = p.parse_args()
    rc = otls_fetch(args.url, args.parties, args.port)
    sys.exit(0 if 200 <= rc < 400 else 1)
