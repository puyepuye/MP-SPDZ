# OTLS: Oblivious TLS 1.3 in MP-SPDZ

OTLS performs a full TLS 1.3 handshake and HTTPS fetch inside the MP-SPDZ
MPC framework. Three parties jointly compute the handshake. Party 1 owns the
real TCP socket. The other parties see the same data through MP-SPDZ broadcast
channels. The TLS private key (X25519 scalar) is secret-shared across all
three parties and never revealed.

## How to run

```bash
cd MP-SPDZ

# compile (takes about 18 minutes)
PRIME=57896044618658097711785492504343953926634992332820282019728792003956564819949
python3 compile.py -F 253 -P "$PRIME" otls_demo_field_vm

# run (with decoded response output)
export PLAYERS=3 OTLS_HOST=restcountries.com
PORT=14000 ./Scripts/rep-field.sh otls_demo_field_vm -P "$PRIME" 2>&1 \
  | python3 Scripts/otls-decode-response.py
```

Or use the convenience script which compiles, builds, and runs in one step:

```bash
OTLS_HOST=restcountries.com ./Scripts/otls-run-field-vm.sh
```

To change the HTTP request, edit the `req_str` line in
`Programs/Source/otls_demo_field_vm.mpc` and recompile.

## What the prime is

The prime is P25519 = 2^255 - 19. This is the field prime for Curve25519.
MP-SPDZ needs it because the X25519 ECDH computation runs inside MPC and all
the arithmetic (ladder multiplications, modular inversion) happens mod this
prime.

## Files

### MPC programs (.mpc)

| File | What it does |
|------|-------------|
| `Programs/Source/otls_demo_field_vm.mpc` | Main program. Full TLS 1.3 handshake and HTTP fetch using VM opcodes. This is the one you run. |
| `Programs/Source/otls_demo_field.mpc` | Alternative version that uses an external client process (ExternalIO) instead of VM opcodes. Not needed for normal use. |

### C++ (VM opcodes)

| File | What it does |
|------|-------------|
| `Processor/OtlsConnection.h` | Header for the OTLS C++ opcodes. |
| `Processor/OtlsConnection.cpp` | Implementation of TCP connect, TLS record send/receive, ServerHello parsing, transcript hashing (SHA-256), and meta export. Party 1 does the real socket I/O and broadcasts to other parties. |
| `Processor/Instruction.hpp` | Where the OTLS opcodes are wired into the MP-SPDZ VM dispatch loop (look for `OTLS_` cases). |

### Compiler (Python-side opcode wrappers)

| File | What it does |
|------|-------------|
| `Compiler/instructions.py` | Defines the OTLS VM instructions (opcode numbers, register formats). Search for `OTLS_` to find them. |
| `Compiler/library.py` | Python wrapper functions like `otls_tcp_connect()`, `otls_tcp_send_record_be()`, etc. These are what the .mpc program calls. Also contains `otls_regint_bytes_be()` for packing byte strings into regint words. |

### Scripts

| File | What it does |
|------|-------------|
| `Scripts/otls-run-field-vm.sh` | Convenience script. Compiles the .mpc, rebuilds the C++ binary, and runs 3 parties. |
| `Scripts/otls-run-field.sh` | Same but for the ExternalIO version (`otls_demo_field.mpc`). |
| `Scripts/otls-decode-response.py` | Pipe the MPC output through this to decode the response words into readable ASCII text. |

## How the pipeline works

1. Party 1 opens a TCP connection to the target HTTPS server.
2. Party 1 sends a TLS ClientHello and receives the ServerHello.
3. The server's X25519 public key and the transcript hash (SHA-256 of
   ClientHello + ServerHello) are broadcast to all parties.
4. Each party loads its share of the X25519 private scalar from an input file.
   The three shares are added (mod 2^256) in MPC to reconstruct the scalar
   in secret-shared form.
5. X25519 ECDH runs entirely in MPC (Montgomery ladder, 255 iterations).
   The shared secret is computed without revealing the private scalar.
6. TLS 1.3 key derivation (HKDF-SHA256) and AES-128-GCM decryption of the
   server's handshake records run in MPC using binary circuits.
7. The transcript hash is finalized and Client Finished is computed,
   encrypted, and sent over the TCP socket.
8. An encrypted HTTP request (e.g. GET /v3.1/name/peru) is sent.
9. The server's encrypted response records are received, decrypted in MPC,
   and the plaintext is revealed and printed as integer words.
10. The decoder script converts those words into readable HTTP text.
