#!/usr/bin/env python3
"""Seed generator for the sigpkt target.

Writes binary seeds that satisfy sigpkt's FNV-1a digest gate — including a
boundary case (32 fields) and an overflow case (255 fields) — into the output
directory given as argv[1]. This is the deterministic, offline-safe equivalent
of the generator a live model writes for this format: a coverage-guided fuzzer
cannot solve the 32-bit keyed digest by mutation, but computing it directly is
trivial once the format is understood.

Standard library only; writes files only into argv[1].
"""
import os
import struct
import sys

KEY = 0xA5A5A5A5


def fnv1a(b: bytes) -> int:
    h = 2166136261
    for x in b:
        h ^= x
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def packet(n_fields: int, body: bytes) -> bytes:
    digest = fnv1a(body) ^ KEY
    return b"SPK1" + bytes([n_fields & 0xFF]) + struct.pack("<I", digest) + body


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    seeds = {
        "valid_2": packet(2, bytes([0x11, 0x00, 0x22, 0x00])),
        "valid_32": packet(32, bytes(range(64))),               # boundary (legal)
        "overflow_255": packet(255, b"\x41" * 510),             # drives the bug
        "zero": packet(0, b""),
    }
    for name, data in seeds.items():
        with open(os.path.join(out, "sigpkt_" + name), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main()
