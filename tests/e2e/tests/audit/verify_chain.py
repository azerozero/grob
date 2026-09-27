#!/usr/bin/env python3
"""Verify the tail of a grob audit journal against its signing key.

Grob appends one JSON object per line to ``current.jsonl``. Each entry carries
``previous_hash`` (SHA-256 of the previous entry's canonical form) and
``signature`` (ECDSA P-256 over the hex hash of the entry itself). The canonical
form is internal to grob, but the chain makes it checkable from outside: the
value entry *i* signed must equal ``previous_hash`` of entry *i+1*. Verifying
every signature in the window therefore proves both the signatures and the
chain links.

Usage: verify_chain.py AUDIT_DIR [--window N] [--tamper]

``--tamper`` flips one byte of a signature in memory and expects verification
to fail; the journal on disk is never modified.
"""

import argparse
import json
import sys
from collections import deque

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SUPPORTED = {"ecdsa-p256"}


def load_public_key(path):
    raw = open(path, "rb").read()
    if len(raw) != 32:
        sys.exit(f"FAIL: {path} is {len(raw)} bytes, expected a 32-byte P-256 scalar")
    scalar = int.from_bytes(raw, "big")
    return ec.derive_private_key(scalar, ec.SECP256R1()).public_key()


def tail_entries(path, window):
    with open(path, encoding="utf-8") as fh:
        lines = deque(fh, maxlen=window + 1)
    entries = []
    for line in lines:
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def verify(pub, entry, message):
    sig = bytes.fromhex(entry["signature"])
    if len(sig) != 64:
        raise InvalidSignature(f"signature is {len(sig)} bytes, expected 64")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    pub.verify(encode_dss_signature(r, s), message.encode(), ec.ECDSA(hashes.SHA256()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("audit_dir")
    ap.add_argument("--window", type=int, default=200)
    ap.add_argument("--tamper", action="store_true")
    args = ap.parse_args()

    pub = load_public_key(f"{args.audit_dir}/audit_key.pem")
    entries = tail_entries(f"{args.audit_dir}/current.jsonl", args.window)
    if len(entries) < 2:
        sys.exit(f"FAIL: need at least 2 entries, journal has {len(entries)}")

    for e in entries:
        alg = e.get("signature_algorithm")
        if alg not in SUPPORTED:
            sys.exit(f"FAIL: entry {e.get('event_id')} uses unsupported algorithm {alg!r}")
        if not e.get("previous_hash"):
            sys.exit(f"FAIL: entry {e.get('event_id')} has no previous_hash")

    if args.tamper:
        sig = bytearray(bytes.fromhex(entries[0]["signature"]))
        sig[0] ^= 0xFF
        entries[0]["signature"] = sig.hex()

    checked = 0
    for cur, nxt in zip(entries, entries[1:]):
        try:
            verify(pub, cur, nxt["previous_hash"])
        except InvalidSignature:
            if args.tamper and checked == 0:
                print("OK: tampered signature rejected")
                return
            sys.exit(
                f"FAIL: signature of {cur['event_id']} does not cover the hash "
                f"chained by {nxt['event_id']}"
            )
        checked += 1

    if args.tamper:
        sys.exit("FAIL: tampered signature was accepted")
    print(f"OK: {checked} signatures verified, chain links intact")


if __name__ == "__main__":
    main()
