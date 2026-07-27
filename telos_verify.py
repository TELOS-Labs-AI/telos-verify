#!/usr/bin/env python3
"""telos-verify: offline verifier for TELOS integrity-hash receipts.

WHAT THIS PROVES
  1. The payload matches the hash recorded on the receipt.
  2. Where receipts form a chain, each link points at the previous receipt's
     hash and the sequence is contiguous.

WHAT THIS DOES NOT PROVE
  It does not establish WHO issued a receipt, or WHEN. The telos/0.1-unsigned
  contract carries no digital signature: `signature` is null and the receipt
  says so about itself in `signing_status`. A matching hash means the payload
  has not changed relative to the recorded hash. It does not authenticate the
  issuer. This tool refuses to imply otherwise, which is why an unsigned result
  is reported as VERIFIED (UNSIGNED) rather than a bare pass.

NO NETWORK. This tool makes no network calls. It reads local files, hashes
bytes, and compares. Standard library only, so there is nothing to install.

EXIT CODES, three states
  0  VERIFIED    every check that could be run, passed
  1  FAILED      a hash mismatch or a broken chain link. The record is not intact.
  2  INCOMPLETE  verification could not be completed: unreadable input, an
                 unknown contract version, or a receipt that claims to be signed
                 while the material needed to check the signature is absent.
                 INCOMPLETE is never reported as a pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

VERIFIED, FAILED, INCOMPLETE = 0, 1, 2

# The one contract version this tool understands. A receipt announcing anything
# else is INCOMPLETE rather than FAILED: we decline to judge what we do not know.
KNOWN_VERSION = "telos/0.1-unsigned"
UNSIGNED_STATUS = "unsigned_integrity_hash"

# Exactly what the receipt's own `covered_fields` declares, and what the
# published schema documents. Canonical JSON over `payload`: sorted keys,
# compact separators, ensure_ascii escaping, UTF-8 bytes.
COVERED = "payload (canonical JSON, sort_keys, compact separators)"


def canonical_bytes(payload) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def compute_hash(payload) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


class Result:
    def __init__(self):
        self.state = VERIFIED
        self.lines: list[str] = []
        self.unsigned = 0

    def note(self, s): self.lines.append(s)

    def fail(self, s):
        self.lines.append("FAIL  " + s)
        self.state = FAILED

    def incomplete(self, s):
        self.lines.append("INCOMPLETE  " + s)
        # FAILED outranks INCOMPLETE: a proven break is worse than an unknown.
        if self.state != FAILED:
            self.state = INCOMPLETE


def load(path: pathlib.Path, r: Result):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        r.incomplete(f"{path}: no such file")
    except json.JSONDecodeError as e:
        r.incomplete(f"{path}: not valid JSON: {e}")
    except OSError as e:
        r.incomplete(f"{path}: unreadable: {e}")
    return None


def verify_one(path: pathlib.Path, receipt: dict, r: Result) -> bool:
    """Check a single receipt's integrity hash. True if it verified."""
    name = path.name

    version = receipt.get("receipt_version")
    if version != KNOWN_VERSION:
        r.incomplete(f"{name}: unknown receipt_version {version!r}; this tool knows {KNOWN_VERSION!r}")
        return False

    if "payload" not in receipt:
        r.fail(f"{name}: no payload to hash")
        return False

    recorded = receipt.get("integrity_hash")
    if not isinstance(recorded, str) or not recorded.startswith("sha256:"):
        r.fail(f"{name}: missing or malformed integrity_hash")
        return False

    covered = receipt.get("covered_fields")
    if covered != COVERED:
        # The receipt claims the hash covers something other than what this tool
        # recomputes. Refuse rather than compare the wrong bytes and call it a pass.
        r.incomplete(f"{name}: covered_fields is {covered!r}; this tool only recomputes {COVERED!r}")
        return False

    try:
        actual = compute_hash(receipt["payload"])
    except (TypeError, ValueError) as e:
        r.incomplete(f"{name}: payload has no canonical JSON form: {e}")
        return False

    if actual != recorded:
        r.fail(f"{name}: payload does not match recorded hash")
        r.note(f"        recorded  {recorded}")
        r.note(f"        recomputed {actual}")
        return False

    # Signature posture, stated plainly and never skipped silently.
    status = receipt.get("signing_status")
    sig = receipt.get("signature")
    if status == UNSIGNED_STATUS and sig is None:
        r.unsigned += 1
    elif sig is not None:
        r.incomplete(
            f"{name}: receipt carries a signature, but this tool has no published "
            "root key material to check it against. Integrity hash verified; "
            "signature NOT checked."
        )
        return False
    else:
        r.incomplete(f"{name}: inconsistent signing state (signing_status={status!r}, signature present={sig is not None})")
        return False

    r.note(f"ok    {name}  hash matches")
    return True


def verify_chain(receipts: list[tuple[pathlib.Path, dict]], r: Result) -> None:
    """Check sequence contiguity and prev-hash linkage across a chain."""
    linked = []
    for path, rec in receipts:
        p = rec.get("payload", {})
        if isinstance(p, dict) and "sequence" in p:
            linked.append((path, rec, p))
    if not linked:
        r.note("chain  no sequence fields present; single-receipt mode, no linkage to check")
        return

    linked.sort(key=lambda t: t[2].get("sequence", 0))
    expected_prev = None
    for i, (path, rec, p) in enumerate(linked):
        seq = p.get("sequence")
        if seq != i:
            r.fail(f"{path.name}: sequence {seq} is not contiguous, expected {i}")
            return
        prev = p.get("previous_receipt_integrity_hash")
        if prev != expected_prev:
            r.fail(f"{path.name}: broken link at sequence {seq}")
            r.note(f"        points at {prev}")
            r.note(f"        expected  {expected_prev}")
            return
        expected_prev = rec.get("integrity_hash")
    r.note(f"ok    chain of {len(linked)} receipts links cleanly from genesis to head")
    r.note(f"      head {expected_prev}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="telos-verify",
        description="Verify TELOS integrity-hash receipts offline. Makes no network calls.",
    )
    ap.add_argument("path", help="a receipt .json file, or a directory of them")
    ap.add_argument("--quiet", action="store_true", help="print only the verdict line")
    args = ap.parse_args(argv[1:])

    target = pathlib.Path(args.path).expanduser()
    r = Result()

    if target.is_dir():
        files = sorted(p for p in target.glob("*.json"))
        if not files:
            r.incomplete(f"{target}: directory contains no .json receipts")
            files = []
    elif target.exists():
        files = [target]
    else:
        r.incomplete(f"{target}: no such file or directory")
        files = []

    loaded = []
    for f in files:
        rec = load(f, r)
        if rec is None:
            continue
        if verify_one(f, rec, r):
            loaded.append((f, rec))

    if loaded and len(files) == len(loaded):
        verify_chain(loaded, r)

    if not args.quiet:
        for line in r.lines:
            print(line)
        print()

    verdict = {VERIFIED: "VERIFIED", FAILED: "FAILED", INCOMPLETE: "INCOMPLETE"}[r.state]
    if r.state == VERIFIED and r.unsigned:
        print(f"VERIFIED (UNSIGNED): {r.unsigned} receipt(s). The payload matches the "
              f"recorded hash and the chain is intact.")
        print("NOTE: these receipts carry no signature, so this does NOT establish "
              "who issued them or when.")
    else:
        print(f"{verdict}: {len(loaded)} of {len(files)} receipt(s) verified.")
        if r.state == INCOMPLETE:
            print("NOTE: INCOMPLETE is not a pass. Something could not be checked, see above.")

    return r.state


if __name__ == "__main__":
    sys.exit(main(sys.argv))
