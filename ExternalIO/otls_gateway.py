#!/usr/bin/env python3
"""OTLS Gateway: thin TCP proxy between HTTPS server and MPC parties.

Handles: TLS record framing, transcript hashing (public). If OTLS_MPC_X25519=1,
does not compute the shared secret locally — sends three additive shares of the
client scalar (12 private words) + server public key for MPC X25519 (otls_demo_field).
Otherwise derives shared secret in-process for
the ring demo (otls_demo). Key derivation and AEAD run inside MPC in both cases.
"""
import sys, os, struct, socket, hashlib, select, secrets
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'otls'))
sys.path.insert(0, os.path.dirname(__file__))

from client import Client, octetStream
from tls.crypto import x25519_private_key, x25519_public_key, x25519_derive_shared_secret
from tls.handshake import encode_client_hello, decode_server_hello

RECORD_TYPE_CHANGE_CIPHER_SPEC = 20
RECORD_TYPE_HANDSHAKE = 22
RECORD_TYPE_APPLICATION_DATA = 23

MAX_REC_WORDS = 320   # 2560 bytes per HS record (must match otls_demo.mpc REC_BUF_WORDS)
MAX_APP_WORDS = 128   # 1024 bytes per app data (must match otls_demo.mpc APP_BUF_WORDS)
RESP_CT_BYTES = MAX_APP_WORDS * 8 - 21  # must match otls_demo.mpc
MAX_HS_RECORDS = 5
MAX_RESP_RECORDS = 2

def log(msg):
    print(f'[gateway] {msg}', file=sys.stderr, flush=True)

def pack_bytes(data, max_words):
    words = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8].ljust(8, b'\x00')
        words.append(int.from_bytes(chunk, 'big'))
    words += [0] * (max_words - len(words))
    return words[:max_words]

def unpack_words(values, length):
    result = b''
    for w in values:
        if w < 0:
            w += (1 << 64)
        result += (w & ((1 << 64) - 1)).to_bytes(8, 'big')
    return result[:length]

def scalar_int_to_be_words(k):
    """256-bit scalar as int -> 4 x 64-bit BE words (must match otls_demo_field sint packing)."""
    b = k.to_bytes(32, 'little')
    return [int.from_bytes(b[i:i + 8], 'big') for i in range(0, 32, 8)]

def split_scalar_three_shares_mod_2_256(scalar_raw32):
    """Additive shares r0,r1,r2 with (r0+r1+r2) ≡ k (mod 2^256), k = LE scalar bytes."""
    mod = 1 << 256
    k = int.from_bytes(scalar_raw32, 'little')
    r0 = secrets.randbelow(mod)
    r1 = secrets.randbelow(mod)
    r2 = (k - r0 - r1) % mod
    return r0, r1, r2

def read_tls_record(sock):
    buf = b''
    while len(buf) < 5:
        chunk = sock.recv(5 - len(buf))
        if not chunk:
            raise ConnectionError('connection closed reading header')
        buf += chunk
    ct, ver, length = struct.unpack('!BHH', buf[:5])
    while len(buf) < 5 + length:
        need = 5 + length - len(buf)
        chunk = sock.recv(need)
        if not chunk:
            raise ConnectionError('connection closed reading payload')
        buf += chunk
    return ct, buf[:5], buf[5:5+length]

def gateway_main(host, port, path, mpc_port=18000):
    # --- Phase 0: TLS handshake with server (record level only) ---
    log(f'Connecting to {host}:{port}')
    sock = socket.create_connection((host, port), timeout=15)

    priv_key = x25519_private_key()
    pub_key = x25519_public_key(priv_key)
    client_random = os.urandom(32)
    ch_msg = encode_client_hello(client_random, pub_key, 'http/1.1',
                                 server_name=host,
                                 cipher_suites=[0x1301])

    header = struct.pack('!BHH', RECORD_TYPE_HANDSHAKE, 0x0301, len(ch_msg))
    sock.sendall(header + ch_msg)
    log('ClientHello sent')

    ct, sh_hdr, sh_payload = read_tls_record(sock)
    if ct != RECORD_TYPE_HANDSHAKE:
        raise Exception(f'Expected ServerHello (got type {ct})')
    sh_msg = sh_payload  # full handshake message
    server_random, server_pub, cipher_suite = decode_server_hello(sh_msg[4:])
    log(f'ServerHello received, cipher_suite=0x{cipher_suite:04x}')

    if cipher_suite != 0x1301:
        raise Exception(f'Server chose cipher 0x{cipher_suite:04x}, but MPC only supports 0x1301 (AES-128-GCM-SHA256)')

    # OTLS_MPC_X25519=1: shared secret computed only inside MP-SPDZ (otls_demo_field.mpc).
    # OTLS_MPC_X25519=0: gateway derives SS and sends it as private input (otls_demo.mpc ring path).
    mpc_x25519 = os.getenv('OTLS_MPC_X25519', '0') == '1'
    if mpc_x25519:
        log('X25519 deferred to MPC (sending 3 scalar shares + server pub)')
    else:
        shared_secret = x25519_derive_shared_secret(priv_key, server_pub)
        log('X25519 shared secret computed (gateway)')

    # Read encrypted server handshake records + any NewSessionTickets
    enc_records = []
    while len(enc_records) < MAX_HS_RECORDS:
        ct, hdr, payload = read_tls_record(sock)
        if ct == RECORD_TYPE_CHANGE_CIPHER_SPEC:
            continue
        if ct == RECORD_TYPE_APPLICATION_DATA:
            enc_records.append(hdr + payload)
            log(f'  HS-phase record {len(enc_records)}: {len(hdr)+len(payload)} bytes')
            ready, _, _ = select.select([sock], [], [], 0.5)
            if not ready:
                break
        else:
            break
    log(f'Read {len(enc_records)} encrypted server HS-phase records')
    # First record = actual HS messages (HS key). Remaining = NewSessionTickets (APP key).
    n_nst_phase0 = max(0, len(enc_records) - 1)
    log(f'NewSessionTickets in HS phase: {n_nst_phase0}')

    # Compute transcript hash of CH || SH (public data)
    th_ch_sh = hashlib.sha256(ch_msg + sh_msg).digest()
    log(f'th(CH||SH) = {th_ch_sh.hex()[:16]}...')

    # --- Phase 1: Connect to MPC, send setup data ---
    log(f'Connecting to MPC parties on port {mpc_port}...')
    mpc = Client(['localhost'] * 3, mpc_port, 0)
    log('Connected to MPC')

    # Send transcript hash (4 x 64-bit words, BE) — public regint path
    th_words = [int.from_bytes(th_ch_sh[i:i+8], 'big') for i in range(0, 32, 8)]
    mpc.send_public_inputs_raw64(th_words)

    if mpc_x25519:
        client_scalar_raw = priv_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        r0, r1, r2 = split_scalar_three_shares_mod_2_256(client_scalar_raw)
        cs_words = (
            scalar_int_to_be_words(r0)
            + scalar_int_to_be_words(r1)
            + scalar_int_to_be_words(r2))
        mpc.send_private_inputs(cs_words)
        sp_words = [int.from_bytes(server_pub[i:i+8], 'big')
                    for i in range(0, 32, 8)]
        mpc.send_public_inputs_raw64(sp_words)
    else:
        ss_words = [int.from_bytes(shared_secret[i:i+8], 'big')
                    for i in range(0, 32, 8)]
        mpc.send_private_inputs(ss_words)

    # Send encrypted records
    mpc.send_public_inputs_raw64([len(enc_records)])
    for rec in enc_records:
        mpc.send_public_inputs_raw64([len(rec)] + pack_bytes(rec, MAX_REC_WORDS))
    for _ in range(MAX_HS_RECORDS - len(enc_records)):
        mpc.send_public_inputs_raw64([0] + [0] * MAX_REC_WORDS)

    # --- Phase 2: Receive ALL decrypted server HS records from MPC ---
    log('Waiting for MPC to decrypt server handshake records...')
    n_hs_out = 1 + MAX_REC_WORDS
    server_hs_messages = b''
    n_nst_actual = 0
    for ri in range(MAX_HS_RECORDS):
        hs_result = mpc.receive_outputs(n_hs_out)
        if ri >= len(enc_records):
            log(f'  HS record {ri}: padding (no data)')
            continue
        actual_rec_len = len(enc_records[ri])
        actual_ct = actual_rec_len - 5 - 16
        pt = unpack_words(hs_result[1:], actual_ct)
        # Strip trailing zero padding and inner content type
        while pt and pt[-1] == 0:
            pt = pt[:-1]
        if not pt:
            log(f'  HS record {ri}: empty after stripping')
            continue
        inner_ct = pt[-1]
        pt = pt[:-1]
        log(f'  HS record {ri}: {len(pt)} bytes, inner_ct=0x{inner_ct:02x}')
        if inner_ct == 0x16:
            server_hs_messages += pt
        else:
            n_nst_actual += 1
            log(f'  HS record {ri}: not handshake (inner_ct=0x{inner_ct:02x}), counting as NST')

    n_nst_phase0 = n_nst_actual
    log(f'Decrypted server HS: {len(server_hs_messages)} bytes, NSTs in HS phase: {n_nst_phase0}')

    # Compute transcript hashes
    transcript_sf = ch_msg + sh_msg + server_hs_messages
    th_sf = hashlib.sha256(transcript_sf).digest()
    log(f'th(through server Finished) = {th_sf.hex()[:16]}...')

    # Build HTTP request
    req = f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode()
    log(f'HTTP request: {len(req)} bytes')

    # --- Phase 3: Send transcript hash + HTTP request to MPC ---
    th_sf_words = [int.from_bytes(th_sf[i:i+8], 'big') for i in range(0, 32, 8)]
    mpc.send_public_inputs_raw64(th_sf_words)
    mpc.send_public_inputs_raw64([len(req)] + pack_bytes(req, MAX_APP_WORDS))

    # --- Phase 4: Receive encrypted records from MPC ---
    log('Waiting for MPC to encrypt Client Finished + HTTP GET...')
    fin_result = mpc.receive_outputs(1 + MAX_APP_WORDS)
    fin_len = fin_result[0] & ((1 << 64) - 1)
    fin_record = unpack_words(fin_result[1:], fin_len)

    app_result = mpc.receive_outputs(1 + MAX_APP_WORDS)
    app_len = app_result[0] & ((1 << 64) - 1)
    app_record = unpack_words(app_result[1:], app_len)

    sock.sendall(fin_record)
    log(f'Forwarded encrypted Finished ({fin_len} bytes)')
    sock.sendall(app_record)
    log(f'Forwarded encrypted HTTP GET ({app_len} bytes)')

    # --- Phase 5: Receive server response, forward to MPC ---
    import time
    time.sleep(1.5)

    # Read all available records. Some may be NewSessionTickets (small, < 300 bytes).
    # The HTTP response record is typically the largest.
    all_resp = []
    for _ in range(MAX_RESP_RECORDS + 4):
        try:
            ct, hdr, payload = read_tls_record(sock)
            rec_bytes = hdr + payload
            log(f'  post-HS record ct={ct} len={len(rec_bytes)} payload={len(payload)}')
            if ct == RECORD_TYPE_APPLICATION_DATA:
                all_resp.append(rec_bytes)
            ready, _, _ = select.select([sock], [], [], 2.0)
            if not ready:
                break
        except Exception as e:
            log(f'  read error: {e}')
            break
    log(f'Read {len(all_resp)} post-handshake records total')

    # Heuristic: NewSessionTickets are small (< 300 bytes).
    # Skip them and find the actual HTTP response record(s).
    nst_in_resp = 0
    resp_records = []
    for rec in all_resp:
        if len(rec) < 300 and not resp_records:
            nst_in_resp += 1
            log(f'  skipping small record ({len(rec)} bytes, likely NST)')
        else:
            resp_records.append(rec)

    srv_app_seq = n_nst_phase0 + nst_in_resp
    log(f'Server app seq offset: {srv_app_seq} (phase0={n_nst_phase0} + resp={nst_in_resp})')
    log(f'HTTP response records: {len(resp_records)}')
    for i, rec in enumerate(resp_records):
        log(f'  resp[{i}]: {len(rec)} bytes')
        if len(rec) > MAX_APP_WORDS * 8:
            log(f'  WARNING: record {len(rec)} exceeds buffer {MAX_APP_WORDS*8}, truncating')

    # Send to MPC: sequence offset, then records
    mpc.send_public_inputs_raw64([srv_app_seq])
    mpc.send_public_inputs_raw64([len(resp_records)])
    for rec in resp_records[:MAX_RESP_RECORDS]:
        mpc.send_public_inputs_raw64([len(rec)] + pack_bytes(rec, MAX_APP_WORDS))
    for _ in range(MAX_RESP_RECORDS - min(len(resp_records), MAX_RESP_RECORDS)):
        mpc.send_public_inputs_raw64([0] + [0] * MAX_APP_WORDS)

    # --- Phase 6: Receive decrypted response ---
    log('Waiting for MPC to decrypt response...')
    resp_result = mpc.receive_outputs(1 + MAX_APP_WORDS)

    if resp_records:
        actual_rec_len = len(resp_records[0])
        actual_ct_bytes = actual_rec_len - 5 - 16
        log(f'Actual response ciphertext: {actual_ct_bytes} bytes (record={actual_rec_len})')
    else:
        actual_ct_bytes = resp_result[0] & ((1 << 64) - 1)

    resp_body = unpack_words(resp_result[1:], min(actual_ct_bytes, RESP_CT_BYTES))
    while resp_body and resp_body[-1] == 0:
        resp_body = resp_body[:-1]
    if resp_body:
        inner_ct = resp_body[-1]
        log(f'Inner content type: 0x{inner_ct:02x} (0x16=handshake, 0x17=appdata)')
        resp_body = resp_body[:-1]

    sock.close()
    log('Connection closed')
    log(f'Response body: {len(resp_body)} bytes')
    log(f'First 200 bytes: {resp_body[:200]}')
    print(resp_body.decode('utf-8', errors='replace'))

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else 'restcountries.com'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    path = sys.argv[3] if len(sys.argv) > 3 else '/v3.1/name/deutschland'
    mpc_port = int(sys.argv[4]) if len(sys.argv) > 4 else 18000
    gateway_main(host, port, path, mpc_port)
