#!/usr/bin/env python3
"""telos-sign — companion signer/keygen for telos-verify's Ed25519 path.

This is the operator-invoked SIGN side of the receipt chain. telos-verify only
verifies; this tool can (a) generate a signing keypair and (b) sign receipt
payloads, producing telos/0.2-ed25519 receipts that telos-verify --key checks.

Boundary: this is a TOOL. It signs whatever key you hand it. It does NOT touch any
production key on its own and publishes nothing. Generating the real key and
signing the real chain is an operator act. It does not validate input or output
against either bundled JSON Schema; use a Draft 2020-12 validator separately
when schema conformance matters.

Format is kept byte-identical to what telos_verify.py verifies:
  - integrity_hash = "sha256:" + sha256(canonical JSON of payload)
  - canonical JSON = json.dumps(payload, sort_keys=True, separators=(",",":"),
                                ensure_ascii=True, allow_nan=False).encode("utf-8")
  - signature.value = base64(ed25519_sign(ASCII bytes of the integrity_hash string))
  - signature.public_key = base64(raw 32-byte public key)

Usage:
  telos_sign.py keygen --out-dir DIR
      -> writes DIR/telos-signing-key.pem (private, 0600) and
         DIR/telos-public-key.pem (public, to publish). Prints the public key.
  telos_sign.py sign INPUT --key PRIVKEY.pem --out OUTDIR
      INPUT is a telos/0.1-unsigned receipt file or a directory of them.
      -> writes signed telos/0.2-ed25519 receipts into OUTDIR (same filenames).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

COVERED = "payload (canonical JSON, sort_keys, compact separators)"
SIG_COVERS = "integrity_hash (ASCII bytes of the sha256: string)"
SIG_ALGORITHM = "ed25519"


def _reject_duplicate_keys(pairs):
    """Parse hook: refuse duplicate JSON keys. json.loads keeps the LAST of a duplicate,
    but a human (and first-wins parsers) sees the FIRST — a split view that lets a signed
    receipt cover a payload different from the one displayed.
    Signing must never sign the last of a duplicated payload while a reader sees another."""
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate key {k!r}: receipt has a split view, refusing to sign")
        seen.add(k)
    return dict(pairs)


def load_receipt_json(text: str) -> dict:
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)


def canonical_bytes(payload) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")


def integrity_hash(payload) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def keygen(out_dir: pathlib.Path) -> int:
    priv_path = out_dir / "telos-signing-key.pem"
    pub_path = out_dir / "telos-public-key.pem"
    created = []
    try:
        # Refuse before any create, including dangling symlinks. Exclusive opens
        # below also refuse targets created after this preflight.
        for path in (priv_path, pub_path):
            if os.path.lexists(path):
                print(f"keygen refused: target already exists: {path}", file=sys.stderr)
                return 1
        out_dir.mkdir(parents=True, exist_ok=True)
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        for path, data, mode in ((priv_path, priv_pem, 0o600), (pub_path, pub_pem, 0o644)):
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            created.append(path)
            try:
                if path == priv_path:
                    os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as f:
                    fd = None  # the file context now owns and closes it
                    f.write(data)
            finally:
                if fd is not None:
                    os.close(fd)
    except OSError as e:
        # Remove only targets whose exclusive create succeeded in this call.
        # A concurrent creator's target is never ours to remove.
        for path in reversed(created):
            try:
                path.unlink()
            except OSError as cleanup_error:
                print(f"keygen cleanup failed for {path}: {cleanup_error}", file=sys.stderr)
        print(f"keygen refused: could not create key pair: {e}", file=sys.stderr)
        return 1
    print(f"private key (KEEP SECRET, do not publish, do not commit): {priv_path} [mode 0600]")
    print(f"public key  (PUBLISH this): {pub_path}")
    print(pub_pem.decode("ascii"))
    return 0


def sign_one(source: dict) -> dict:
    """Sign one telos/0.1-unsigned receipt's payload, returning a telos/0.2-ed25519 receipt.
    Preserves the source metadata; only the version, signing_status and signature change.
    Sanity-checks that the source's own integrity_hash matches its payload before signing —
    signing a receipt whose hash already disagrees with its payload would sign a lie."""
    if "payload" not in source:
        raise ValueError("receipt has no payload")
    payload = source["payload"]
    ih = integrity_hash(payload)
    recorded = source.get("integrity_hash")
    if recorded is not None and recorded != ih:
        raise ValueError(
            f"source integrity_hash {recorded!r} does not match its payload ({ih!r}); refusing to sign a mismatch"
        )
    out = dict(source)
    out["receipt_version"] = "telos/0.2-ed25519"
    out["integrity_hash"] = ih
    out["covered_fields"] = COVERED
    out["signing_status"] = "ed25519_signed"
    out["signature"] = None  # filled by caller who holds the key
    return out, ih


def sign(input_path: pathlib.Path, key_path: pathlib.Path, out_dir: pathlib.Path) -> int:
    data = key_path.read_bytes()
    priv = serialization.load_pem_private_key(data, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise SystemExit(f"{key_path}: not an Ed25519 private key")
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    if input_path.is_dir():
        sources = sorted(input_path.glob("*.json"))
    elif input_path.is_file():
        sources = [input_path]
    else:
        raise SystemExit(f"{input_path}: no such file or directory")
    if not sources:
        raise SystemExit(f"{input_path}: no .json receipts")

    out_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for src_path in sources:
        try:
            source = load_receipt_json(src_path.read_text(encoding="utf-8"))
        except ValueError as e:
            raise SystemExit(f"{src_path}: {e}")
        signed, ih = sign_one(source)
        signed["signature"] = {
            "algorithm": SIG_ALGORITHM,
            "covers": SIG_COVERS,
            "public_key": pub_b64,
            "value": base64.b64encode(priv.sign(ih.encode("ascii"))).decode("ascii"),
        }
        (out_dir / src_path.name).write_text(
            json.dumps(signed, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
        n += 1
    print(f"signed {n} receipt(s) -> {out_dir}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="telos-sign — sign the receipt chain for telos-verify")
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    kg.add_argument("--out-dir", type=pathlib.Path, required=True)
    sg = sub.add_parser("sign", help="sign unsigned receipts into telos/0.2-ed25519 receipts")
    sg.add_argument("input", type=pathlib.Path, help="a receipt .json or a directory of them")
    sg.add_argument("--key", type=pathlib.Path, required=True, help="Ed25519 private key PEM")
    sg.add_argument("--out", type=pathlib.Path, required=True, help="output directory")
    args = ap.parse_args(argv[1:])
    if args.cmd == "keygen":
        return keygen(args.out_dir)
    if args.cmd == "sign":
        return sign(args.input, args.key, args.out)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
