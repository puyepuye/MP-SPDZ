#!/usr/bin/env python3
"""Decode RESP_WORD lines from otls_demo_field_vm output into ASCII.

Usage:
    ./Scripts/otls-run-field-vm.sh 2>&1 | python3 Scripts/otls-decode-response.py
    # or from a saved log:
    python3 Scripts/otls-decode-response.py < /tmp/otls_vm_test.log
"""
import sys
import struct

P = (1 << 255) - 19
inside = False
raw = bytearray()

for line in sys.stdin:
    line = line.rstrip('\n')

    if 'RESPONSE BEGIN' in line:
        inside = True
        continue
    if 'RESPONSE END' in line:
        inside = False
        continue

    if inside and line.startswith('RESP_WORD '):
        parts = line.split()
        val = int(parts[2])
        if val < 0:
            val += P
        val &= 0xFFFFFFFFFFFFFFFF
        raw.extend(val.to_bytes(8, 'big'))
    else:
        print(line)

if raw:
    text = raw.rstrip(b'\x00')
    body_start = text.find(b'\r\n\r\n')
    print('\n' + '=' * 60)
    print('DECRYPTED HTTP RESPONSE')
    print('=' * 60)
    try:
        print(text.decode('utf-8', errors='replace'))
    except Exception:
        print(text.decode('latin-1'))
    print('=' * 60)

    if body_start >= 0:
        body = text[body_start + 4:]
        print('\nHTTP BODY ONLY:')
        print('-' * 60)
        try:
            print(body.decode('utf-8', errors='replace'))
        except Exception:
            print(body.decode('latin-1'))
        print('-' * 60)
