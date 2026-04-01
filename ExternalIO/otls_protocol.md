# OTLS ExternalIO Contract

This document freezes the wire contract between:

- `Programs/Source/otls_demo.mpc`
- `ExternalIO/otls_external_io_client.cpp` / `otls-external-io-client.x` (ExternalIO client + TLS)

All integer words are 64-bit ring elements (`Z2^64`) represented as big-endian
byte groups when packing/unpacking application bytes.

## Constants (must match both sides)

- `REC_BUF_WORDS = 320` (`REC_BUF_BYTES = 2560`)
- `APP_BUF_WORDS = 128` (`APP_BUF_BYTES = 1024`)
- `MAX_HS_RECORDS = 5`
- `MAX_RESP_RECORDS = 2`

Derived:

- `HS_CT_BYTES = REC_BUF_BYTES - 21`
- `RESP_CT_BYTES = APP_BUF_BYTES - 21`

`21 = 5-byte TLS record header + 16-byte GCM tag`.

## Phase-by-phase socket contract

The gateway connects as one ExternalIO client (`client id 0`) and performs:

### Phase 1: setup inputs

1. Public transcript hash through ServerHello:
   - send `4` words: `th_ch_sh[0..31]` as 4 x 8-byte chunks
2. Private shared secret:
   - send `4` secret words: X25519 shared secret bytes
3. Number of encrypted HS records:
   - send `1` public word: `n_enc`
4. HS records payload:
   - for `i in [0, MAX_HS_RECORDS)` send `1 + REC_BUF_WORDS` public words:
     - `len_i` (actual record length in bytes, `0` for padding entries)
     - packed record bytes padded/truncated to `REC_BUF_WORDS`

### Phase 2: receive decrypted HS records

For each `i in [0, MAX_HS_RECORDS)`, receive `1 + REC_BUF_WORDS` secret outputs:

- word 0: plaintext length (currently fixed to `HS_CT_BYTES` in program output)
- words 1..N: packed plaintext bytes

Gateway must trim with actual ciphertext length (`record_len - 21`) and then strip
TLSInnerPlaintext trailer (`... + content_type + zero_padding`).

### Phase 3: send transcript hash + request

1. Public full transcript hash through Server Finished:
   - send `4` words
2. HTTP request buffer:
   - send `1 + APP_BUF_WORDS` public words:
     - `req_len`
     - packed request bytes, padded/truncated to `APP_BUF_WORDS`

### Phase 4: receive encrypted client records

Receive two blocks of `1 + APP_BUF_WORDS` secret outputs:

1. Client Finished TLS record (`len + packed bytes`)
2. Client ApplicationData (HTTP GET) TLS record (`len + packed bytes`)

Gateway forwards both record byte strings directly to TLS server.

### Phase 5: send response metadata + records

1. Public app sequence offset:
   - send `1` word `srv_app_seq`
2. Public response record count:
   - send `1` word `n_resp`
3. Response records:
   - for `i in [0, MAX_RESP_RECORDS)` send `1 + APP_BUF_WORDS` public words:
     - `len_i`
     - packed response record bytes (padding entries are zero)

### Phase 6: receive decrypted response

Receive `1 + APP_BUF_WORDS` secret outputs:

- word 0: plaintext length (currently fixed to `RESP_CT_BYTES`)
- words 1..N: packed plaintext bytes

Gateway trims with known ciphertext length of selected response record and strips
TLSInnerPlaintext trailer.

## Packing rules

- `pack_bytes(data, max_words)`:
  - split data into 8-byte chunks
  - pad final chunk with zero bytes on the right
  - interpret each chunk as unsigned 64-bit big-endian integer
  - pad list with zero words to `max_words`
- `unpack_words(words, length)`:
  - for each word, emit 8-byte big-endian bytes
  - truncate final concatenation to `length`

## Notes

- This contract intentionally keeps network framing/public transcript processing
  outside MPC while all key schedule and AEAD operations stay in `.mpc`.
- Any C++ bridge replacement must preserve the ordering and fixed buffer contract
  exactly to stay compatible with existing bytecode.
