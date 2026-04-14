# OTLS: Oblivious TLS 1.3 in MP-SPDZ

OTLS performs a full TLS 1.3 handshake and HTTPS fetch inside the MP-SPDZ
MPC framework. Three parties jointly compute the handshake. Party 1 owns the
real TCP socket. The other parties see the same data through MP-SPDZ broadcast
channels. The TLS private key (X25519 scalar) is secret-shared across all
three parties and never revealed.

## How to run

Edit `otls.conf` to set the host and path you want to fetch:

```
OTLS_HOST=restcountries.com
OTLS_PATH="/v3.1/name/peru"
```

Then run:

```bash
cd MP-SPDZ
./Scripts/otls-run-field-vm.sh
```

This compiles the MPC program (about 18 minutes), builds the C++ binary,
runs 3 parties locally, and prints the decoded HTTP response.

You can also override the config with environment variables:

```bash
OTLS_HOST=restcountries.com OTLS_PATH="/v3.1/name/canada" ./Scripts/otls-run-field-vm.sh
```

If you only changed the request (host or path) and not the C++ code, you can
skip the C++ rebuild:

```bash
OTLS_SKIP_BUILD=1 ./Scripts/otls-run-field-vm.sh
```

## Configuration

All settings live in `otls.conf` at the root of the MP-SPDZ directory:

| Setting | What it is |
|---------|-----------|
| `OTLS_PRIME` | The field prime (2^255 - 19). Do not change this. |
| `OTLS_HOST` | The HTTPS host to connect to. |
| `OTLS_PATH` | The HTTP request path (e.g. `/v3.1/name/peru`). |

The prime is 2^255 - 19 because the X25519 ECDH computation runs inside MPC
and all the arithmetic happens in the Curve25519 field.

## Files

### MPC program

| File | What it does |
|------|-------------|
| `Programs/Source/otls_demo_field_vm.mpc` | The main program. Full TLS 1.3 handshake and HTTP fetch. Reads `OTLS_HOST` and `OTLS_PATH` from environment variables at compile time. |

### C++ (VM opcodes)

| File | What it does |
|------|-------------|
| `Processor/OtlsConnection.h` | Header for the OTLS C++ opcodes. |
| `Processor/OtlsConnection.cpp` | TCP connect, TLS record send/receive, ServerHello parsing, transcript hashing (SHA-256), and meta export. Party 1 does the real socket I/O and broadcasts to other parties. |
| `Processor/Instruction.hpp` | Where the OTLS opcodes are wired into the MP-SPDZ VM dispatch loop (look for the `OTLS_` cases). |

### Compiler (Python-side opcode wrappers)

| File | What it does |
|------|-------------|
| `Compiler/instructions.py` | Defines the OTLS VM instructions (opcode numbers, register formats). Search for `OTLS_` to find them. |
| `Compiler/library.py` | Python wrapper functions like `otls_tcp_connect()`, `otls_tcp_send_record_be()`, etc. Also has `otls_regint_bytes_be()` for packing byte strings into regint words. |

### Scripts

| File | What it does |
|------|-------------|
| `Scripts/otls-run-field-vm.sh` | Compile, build, and run. Sources `otls.conf` for settings. |
| `Scripts/otls-decode-response.py` | Decodes the integer output words into readable HTTP text. Called automatically by the run script. |

### Config

| File | What it does |
|------|-------------|
| `otls.conf` | Stores the prime, host, and path. Sourced by the run script. |

## Architecture diagrams

### File interactions (compile time vs runtime)

```mermaid
graph TD
    subgraph "Compile Time (Python)"
        CONF[otls.conf<br/>OTLS_HOST, OTLS_PATH, OTLS_PRIME]
        SCRIPT[otls-run-field-vm.sh<br/>sources config, runs compile + run]
        MPC[otls_demo_field_vm.mpc<br/>MPC program source]
        LIB[Compiler/library.py<br/>otls_tcp_connect etc wrappers]
        INST[Compiler/instructions.py<br/>opcode numbers + arg formats]
        INSTBASE[Compiler/instructions_base.py<br/>OTLS_ opcode hex values]
        BC[Programs/Bytecode/*.bc<br/>compiled bytecode]

        SCRIPT -->|sets env vars| MPC
        CONF -->|sourced by| SCRIPT
        MPC -->|imports from| LIB
        LIB -->|emits| INST
        INST -->|reads opcodes from| INSTBASE
        MPC -->|compile.py produces| BC
    end

    subgraph "Runtime (C++)"
        VM[replicated-field-party.x<br/>MP-SPDZ VM binary]
        DISPATCH[Processor/Instruction.hpp<br/>opcode dispatch switch]
        OTLS_CPP[Processor/OtlsConnection.cpp<br/>TCP, TLS records, SHA-256]
        SERVER[HTTPS Server<br/>e.g. restcountries.com]

        BC -->|loaded by| VM
        VM -->|executes via| DISPATCH
        DISPATCH -->|OTLS_ cases call| OTLS_CPP
        OTLS_CPP -->|TCP socket| SERVER
    end

    subgraph "Post-processing (Python)"
        DECODER[Scripts/otls-decode-response.py<br/>integer words to ASCII]
        VM -->|stdout piped to| DECODER
    end
```

### Runtime sequence (TLS 1.3 handshake + HTTP fetch)

```mermaid
sequenceDiagram
    participant P0 as Party 0
    participant P1 as Party 1 (TCP owner)
    participant P2 as Party 2
    participant S as HTTPS Server

    Note over P0,P2: All 3 parties run the same bytecode in sync

    rect rgb(230, 245, 255)
    Note right of P1: 1. TCP + ClientHello (C++ opcodes)
    P1->>S: TCP connect
    P1->>S: TLS ClientHello (X25519)
    S->>P1: ServerHello + server pubkey
    P1->>P0: broadcast ServerHello data
    P1->>P2: broadcast ServerHello data
    end

    rect rgb(255, 245, 230)
    Note right of P1: 2. Export meta (C++ opcode)
    Note over P0,P2: All parties get: transcript_hash(CH||SH) + server_pub
    end

    rect rgb(230, 255, 230)
    Note right of P1: 3. Scalar shares (party 1 input file)
    P1-->>P0: sint.input_from(1): secret-shared scalar
    P1-->>P2: sint.input_from(1): secret-shared scalar
    Note over P0,P2: Reconstruct k = k0 + k1 + k2 (mod 2^256) in MPC
    end

    rect rgb(255, 230, 255)
    Note right of P1: 4. X25519 ECDH (MPC, 255 ladder steps)
    Note over P0,P2: shared_secret = k * server_pub (never revealed)
    end

    rect rgb(230, 245, 255)
    Note right of P1: 5. Fetch encrypted HS records (C++ opcode)
    S->>P1: encrypted handshake records
    P1->>P0: broadcast records
    P1->>P2: broadcast records
    end

    rect rgb(255, 230, 230)
    Note right of P1: 6. Derive keys + decrypt (MPC binary circuits)
    Note over P0,P2: HKDF-SHA256 key derivation in MPC
    Note over P0,P2: AES-128-GCM decrypt each HS record in MPC
    Note over P0,P2: Feed plaintext into transcript hash (C++ opcode)
    end

    rect rgb(230, 255, 245)
    Note right of P1: 7. Finalize + send Client Finished (MPC + C++ opcode)
    Note over P0,P2: Compute Client Finished MAC in MPC
    Note over P0,P2: Encrypt with AES-GCM in MPC, reveal ciphertext
    P1->>S: Client Finished (encrypted)
    end

    rect rgb(245, 245, 230)
    Note right of P1: 8. Send HTTP request (MPC + C++ opcode)
    Note over P0,P2: Encrypt GET request with app keys in MPC
    P1->>S: Application Data (encrypted HTTP GET)
    end

    rect rgb(230, 240, 255)
    Note right of P1: 9. Receive + decrypt response (C++ opcode + MPC)
    S->>P1: Application Data (encrypted HTTP response)
    P1->>P0: broadcast response records
    P1->>P2: broadcast response records
    Note over P0,P2: AES-GCM decrypt response in MPC
    Note over P0,P2: Reveal plaintext, print as integer words
    end

    rect rgb(240, 240, 240)
    Note right of P1: 10. Decode (post-processing Python script)
    Note over P0,P2: otls-decode-response.py converts words to ASCII
    end
```

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
8. An encrypted HTTP request is sent.
9. The server's encrypted response records are received, decrypted in MPC,
   and the plaintext is revealed and printed as integer words.
10. The decoder script converts those words into readable HTTP text.
