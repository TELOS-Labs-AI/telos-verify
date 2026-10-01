#!/usr/bin/env python3
"""telos-verify: offline verifier for TELOS receipts.

It knows telos/0.1-unsigned, telos/0.2-ed25519 and telos/0.3-ed25519. Any other
receipt_version is INCOMPLETE (TV-VER-001), not judged.

WHAT A PASS SHOWS (only the checks that applied, each named in the output)
  1. Structure and field forms. Every receipt is checked against section 1 of
     the TELOS Receipt Standard v0.1 (TV-SCHEMA-001) and, for action_governed
     payloads, the section 2 field rules (TV-S2-*); payload numbers and strings
     must lie in the canonical JSON domain (TV-CANON-*). These rules are
     implemented in telos_verify_lib/schema.py with the standard library. The
     bundled JSON Schema files under docs/ are not read or run by this tool.
  2. The recorded hash matches the canonical JSON encoding of the payload
     supplied to this run. For an unsigned receipt this is an integrity
     relationship, NOT validation of any claim inside the payload: anyone can
     fabricate both content and hash.
  3. Where receipts form a chain, each link points at the previous receipt's
     hash and the sequence is contiguous from genesis. This catches a receipt
     removed from the START or the MIDDLE. It does NOT catch one removed from
     the newest end: nothing inside a set of receipts anchors its tail, so a
     truncated chain and a complete one are indistinguishable from within. The
     tool prints the head hash and says what it did not check; pinning that head
     against an independently held record with --expected-head or
     --expected-head-file is what closes the gap.
  4. Where a receipt is signed AND you supply a public key you already trust,
     that the Ed25519 signature over the integrity hash verifies under that key.
     In anchored mode (--root-key with --trust-dir, or a test bundle), that it
     verifies under a deployment key certified by the root key you supplied.

WHAT A PASS DOES NOT SHOW
  The structure and field checks look at the shape of a record, not at whether
  what it says is true. They are not a run of a JSON Schema validator against
  the bundled schema files.

  Without a signature it does not establish WHO issued a receipt, or WHEN. The
  telos/0.1-unsigned contract carries no digital signature: `signature` is null
  and the receipt says so about itself in `signing_status`. A matching hash
  means the payload has not changed relative to the recorded hash. It does not
  authenticate the issuer. This tool refuses to imply otherwise. An unsigned
  success is reported as VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT
  VALIDATED), followed by an explicit warning that anyone can mint content with
  a matching hash. The warning survives --quiet.

  With a signature it still proves only what the signature covers. The signature
  is over the integrity hash, so it commits to the payload. Envelope metadata
  that sits outside the hash — `issued_at`, `agent_id`, `kind`, `engine` — is
  NOT covered by either the hash or the signature.

  The public key embedded in a receipt is NEVER a trust anchor: a forger writes
  both the signature and the key. A signature is only checked against a key you
  supply out of band with --key, or, in anchored mode, against a certified key
  that traces to the root key you supply with --root-key. With no such key the
  tool reports INCOMPLETE and says the signature was not checked. It never
  manufactures a pass.

NO NETWORK. This tool makes no network calls. It reads local files, hashes the
canonical JSON encoding of each supplied payload, and compares digests.

DEPENDENCIES. The structure, integrity-hash and chain paths are standard library
only, so the unsigned case needs nothing installed. Checking an Ed25519
signature, and anchored mode, need `cryptography` (pip install cryptography).
If it is absent, a signed receipt is reported INCOMPLETE — never a pass. See
"Why a dependency" in the README.

EXIT CODES, three states (every FAIL and INCOMPLETE line names its check id;
--list-checks prints them all)
  0  VERIFIED    every implemented check that applied passed, including the
                 structure and field checks.
  1  FAILED      at least one named check was contradicted: for example a
                 structure or field check, a hash mismatch, a payload value
                 outside the canonical domain, a broken chain link, a head-pin
                 mismatch, or a signature that does not verify under a key you
                 supplied. The tool does not decide which conflicting input is
                 authoritative. FAILED outranks INCOMPLETE in one run.
  2  INCOMPLETE  verification could not be completed: for example unreadable
                 input, a file that repeats a JSON member name, an unknown
                 contract version, a refused key, or a receipt that claims to be
                 signed while the material needed to check the signature is
                 absent. INCOMPLETE is never reported as a pass.
"""
from __future__ import annotations

import sys

from telos_verify_lib.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv))
