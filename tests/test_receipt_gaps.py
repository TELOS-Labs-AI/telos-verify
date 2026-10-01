#!/usr/bin/env python3
"""Per-receipt failures the suite did not pin (gaps found by mutation testing).

Two kinds of test:
- inputs no test built (signature value forms, no payload, a foreign
  covered_fields, a payload with no canonical JSON form, the unsigned version carrying a signature or an inconsistent
  signing state, and which of TV-SIG-006 / TV-SIG-007 a mismatch reports);
- every failure also pins the verdict count, so a receipt that failed a check
  cannot be counted as passed after its FAIL or INCOMPLETE line.

Each invalid receipt runs in one directory beside a valid receipt, after a
baseline of two valid receipts. Keys are generated in-test.
"""
from __future__ import annotations

import base64
import json
import re
import unittest

from test_s3_conformance import (
    FAILED,
    INCOMPLETE,
    VERIFIED,
    Base,
    Key,
    ag_payload,
    signed,
    unsigned,
)

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def noncanonical(b64text: str) -> str:
    """The same bytes spelled with an unused trailing bit set: a second spelling."""
    body = b64text.rstrip("=")
    return body[:-1] + ALPHABET[ALPHABET.index(body[-1]) + 1] + b64text[len(body):]


def foreign(b64text: str) -> str:
    """A character outside the base64 alphabet inside an otherwise valid value."""
    return b64text[:5] + "*" + b64text[5:]


class ReceiptBase(Base):
    def setUp(self):
        super().setUp()
        self.k, self.other = Key(), Key()
        self.kf = self.keyfile(self.k)

    def run_dir(self, receipts, *, key=True):
        self.n += 1
        d = self.tmp / f"d{self.n}"
        d.mkdir()
        for i, rec in enumerate(receipts):
            (d / f"r{i}.json").write_text(json.dumps(rec, indent=1))
        return self.run_tool(d, *(("--key", self.kf) if key else ()))

    def good(self, label="good"):
        return signed(self.k, ag_payload(action_name=label))

    def bad(self, change):
        rec = signed(self.k, ag_payload(action_name="bad"))
        change(rec)
        return rec

    def baseline(self):
        rc, out = self.run_dir([self.good("a"), self.good("b")])
        self.assertEqual(rc, VERIFIED, out)
        self.assertIn("SIGNATURE CHECKED", out)

    def outcome(self, rc_out, rc_expected, check, passed=1, total=2):
        """rc, primary tag, and the verdict count."""
        rc, out = rc_out
        self.assertNotIn("Traceback", out)
        self.assertEqual(rc, rc_expected, out)
        self.assertRegex(out, rf"(?m)^(FAIL|INCOMPLETE) \[{check}\] ")
        verdict = "FAILED" if rc_expected == FAILED else "INCOMPLETE"
        self.assertRegex(out, rf"(?m)^{verdict}: {passed} of {total} receipt\(s\) passed ")


class SignedReceiptFailures(ReceiptBase):
    def cases(self):
        o = self.other
        return {
            "unknown-version": (INCOMPLETE, "TV-VER-001",
                                self.bad(lambda r: r.update(receipt_version="telos/9"))),
            "schema": (FAILED, "TV-SCHEMA-001", self.bad(lambda r: r.update(extra=1))),
            "scoring": (FAILED, "TV-S2-006",
                        signed(self.k, ag_payload(action_name="bad", pa_id=""))),
            "no-payload": (FAILED, "TV-HASH-001", self.bad(lambda r: r.pop("payload"))),
            "hash-form": (FAILED, "TV-HASH-002",
                          self.bad(lambda r: r.update(integrity_hash="sha256:XYZ"))),
            "covered-fields": (INCOMPLETE, "TV-HASH-003",
                               self.bad(lambda r: r.update(covered_fields=["payload", "x"]))),
            "canon-domain": (FAILED, "TV-CANON-001",
                             signed(self.k, ag_payload(action_name="bad", scores={"dim_a": 1e-5}))),
            "hash-mismatch": (FAILED, "TV-HASH-004",
                              self.bad(lambda r: r["payload"].update(action_name="tampered"))),
            "signing-status": (INCOMPLETE, "TV-SIG-002",
                               self.bad(lambda r: r.update(signing_status="unsigned_integrity_hash"))),
            "algorithm": (INCOMPLETE, "TV-SIG-003",
                          self.bad(lambda r: r["signature"].update(algorithm="ed448"))),
            "covers": (INCOMPLETE, "TV-SIG-004",
                       self.bad(lambda r: r["signature"].update(covers="x"))),
            "value-missing": (FAILED, "TV-SIG-005", self.bad(lambda r: r["signature"].pop("value"))),
            "value-not-base64": (FAILED, "TV-SIG-005",
                                 self.bad(lambda r: r["signature"].update(value="!!!!"))),
            "value-63-bytes": (FAILED, "TV-SIG-005", self.bad(
                lambda r: r["signature"].update(value=base64.b64encode(bytes(63)).decode()))),
            "value-noncanonical": (FAILED, "TV-SIG-005", self.bad(
                lambda r: r["signature"].update(value=noncanonical(r["signature"]["value"])))),
            "value-foreign-char": (FAILED, "TV-SIG-005", self.bad(
                lambda r: r["signature"].update(value=foreign(r["signature"]["value"])))),
            "hash-first-digit": (FAILED, "TV-HASH-002", self.bad(
                lambda r: r.update(integrity_hash="sha256:g" + r["integrity_hash"][8:]))),
            "public-key-form": (FAILED, "TV-SCHEMA-001",
                                self.bad(lambda r: r["signature"].update(public_key="!!!!"))),
            "key-id-not-string": (FAILED, "TV-SCHEMA-001",
                                  self.bad(lambda r: r["signature"].update(key_id=5))),
            "key-id-form": (FAILED, "TV-SCHEMA-001",
                            self.bad(lambda r: r["signature"].update(key_id="not-a-digest"))),
            "untrusted-key": (FAILED, "TV-SIG-006", signed(o)),
            "wrong-signature": (FAILED, "TV-SIG-007", signed(self.k, sign_key=o)),
            "key-id-not-verifier": (FAILED, "TV-SIG-009",
                                    self.bad(lambda r: r["signature"].update(key_id=o.kid))),
        }

    def test_failed_receipt_is_not_counted(self):
        for name, (rc_expected, check, rec) in self.cases().items():
            with self.subTest(case=name):
                self.baseline()
                self.outcome(self.run_dir([self.good(), rec]), rc_expected, check)

    def test_no_caller_key_counts_nothing(self):
        self.baseline()
        self.outcome(self.run_dir([self.good("a"), self.good("b")], key=False),
                     INCOMPLETE, "TV-OFFLINE-001", passed=0)


class MismatchNamesTheClaim(ReceiptBase):
    """TV-SIG-006 when the receipt names an untrusted key, TV-SIG-007 when it names none."""

    def strip(self, rec, *members, **over):
        for m in members:
            del rec["signature"][m]
        rec["signature"].update(over)
        return rec

    def test_claim_selects_006_or_007(self):
        k, o = self.k, self.other
        cases = {
            "key-id-only-untrusted": ("TV-SIG-006", self.strip(signed(o), "public_key")),
            "no-claim": ("TV-SIG-007", self.strip(signed(k, sign_key=o), "public_key", "key_id")),
            "public-key-not-base64": ("TV-SIG-007",
                                      self.strip(signed(k, sign_key=o), "key_id", public_key="!!!!")),
            "public-key-foreign-char": ("TV-SIG-007",
                                        self.strip(signed(o), "key_id", public_key=foreign(o.pub))),
            "public-key-wins-over-key-id": ("TV-SIG-006", self.strip(signed(o), key_id=k.kid)),
        }
        for name, (check, rec) in cases.items():
            with self.subTest(case=name):
                self.baseline()
                rc, out = self.run_dir([self.good(), rec])
                self.outcome((rc, out), FAILED, check)
                other = "TV-SIG-007" if check == "TV-SIG-006" else "TV-SIG-006"
                self.assertNotRegex(out, rf"(?m)^FAIL \[{other}\] ")


class UnsignedReceiptFailures(ReceiptBase):
    """Unsigned receipts: no signature check follows to mask a hash failure."""

    def with_hash(self, payload, digest):
        rec = unsigned(ag_payload())
        rec["payload"], rec["integrity_hash"] = payload, digest
        return rec

    def test_failed_unsigned_receipt_is_not_counted(self):
        any_digest = "sha256:" + "0" * 64
        cases = {
            "hash-form": (FAILED, "TV-HASH-002",
                          self.with_hash(ag_payload(action_name="bad"), "sha256:XYZ")),
            "no-canonical-form": (INCOMPLETE, "TV-HASH-005",
                                  self.with_hash(ag_payload(scores={"dim_a": float("nan")}),
                                                 any_digest)),
            "canon-domain": (FAILED, "TV-CANON-001",
                             unsigned(ag_payload(action_name="bad", scores={"dim_a": 1e-5}))),
        }
        for name, (rc_expected, check, rec) in cases.items():
            with self.subTest(case=name):
                rc, out = self.run_dir([unsigned(ag_payload(action_name="a")),
                                        unsigned(ag_payload(action_name="b"))], key=False)
                self.assertEqual(rc, VERIFIED, out)
                self.outcome(self.run_dir([unsigned(ag_payload(action_name="a")), rec], key=False),
                             rc_expected, check)


class UnsignedPosture(ReceiptBase):
    def test_unsigned_version_signature_states(self):
        sig_present = unsigned(ag_payload(action_name="bad"))
        sig_present["signature"] = {"algorithm": "ed25519"}
        inconsistent = unsigned(ag_payload(action_name="bad"))
        inconsistent["signing_status"] = "ed25519_signed"
        cases = {"signature-present": (sig_present, "defines `signature` as null"),
                 "inconsistent": (inconsistent, "inconsistent signing state")}
        for name, (rec, text) in cases.items():
            with self.subTest(case=name):
                rc, out = self.run_dir([unsigned(ag_payload(action_name="a")),
                                        unsigned(ag_payload(action_name="b"))], key=False)
                self.assertEqual(rc, VERIFIED, out)
                rc, out = self.run_dir([unsigned(ag_payload(action_name="a")), rec], key=False)
                self.outcome((rc, out), INCOMPLETE, "TV-SIG-001")
                self.assertTrue(re.search(rf"(?m)^INCOMPLETE \[TV-SIG-001\] .*{re.escape(text)}", out),
                                out)


if __name__ == "__main__":
    unittest.main()
