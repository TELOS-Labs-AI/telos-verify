#!/usr/bin/env python3
"""Anchored-mode inputs the suite did not exercise (gaps found by mutation testing).

Two kinds of test:
- inputs no test built (a projection that is not a list, an empty projection,
  a non-object entry, a wrong entry_version, misnumbered sequences, a second
  key's certificate, a certificate of the wrong shape, a child_key_id that is
  not its key's, and conflicting checkpoints across two key events);
- every anchored failure scenario also pins the verdict count and that no
  receipt is reported ANCHORED, so a failed receipt or a rejected projection
  cannot be counted or used after its FAIL line.

Each invalid input runs beside the valid baseline. Keys are generated in-test.
"""
from __future__ import annotations

import base64
import copy
import json
import re
import unittest

from test_anchored03 import SCOPE, chain03, checkpoint, world03
from test_checkpoint_order import Proj
from test_s3_conformance import (
    FAILED,
    INCOMPLETE,
    LINEAGE_HEAD,
    VERIFIED,
    Base,
    Key,
    bundle,
    certificate,
    entry,
)
from test_small_order import IDENTITY
from test_telos03 import DROP

TRACE_ANCHORED = re.compile(r"(?m)^ok +\S.*  ANCHORED: ")
CHAIN_CHECKED = re.compile(r"(?m)^ok +CHAIN LINKAGE CHECKED")
DIAGNOSTIC = re.compile(r"(?m)^(?:FAIL|INCOMPLETE) \[(TV-[A-Z0-9-]+)\] ")


class AnchoredGaps(Base):
    def setUp(self):
        super().setUp()
        self.root, self.dep, self.c, self.ch, self.certs, self.reg = world03()

    def run_b(self, ch=None, certs=None, reg=None):
        b = bundle(self.root, self.ch if ch is None else ch,
                   self.certs if certs is None else certs, self.reg if reg is None else reg)
        return self.run_tool(self.put(b, suffix=".bundle.json"),
                             "--root-key", self.keyfile(self.root))

    def baseline(self):
        rc, out = self.run_b()
        self.assertEqual(rc, VERIFIED, out)
        self.assertEqual(len(TRACE_ANCHORED.findall(out)), 3, out)
        self.assertIn("VERIFIED (SIGNED — CONTENT NOT VALIDATED): 3 receipt(s).", out)
        return out

    def outcome(self, rc_out, rc_expected, check, passed=0, anchored=0):
        """rc, primary tag, the verdict count, and how many receipts the trace anchors."""
        rc, out = rc_out
        self.assertNotIn("Traceback", out)
        self.assertEqual(rc, rc_expected, out)
        self.assertRegex(out, rf"(?m)^(FAIL|INCOMPLETE) \[{check}\] ")
        verdict = "FAILED" if rc_expected == FAILED else "INCOMPLETE"
        self.assertRegex(out, rf"(?m)^{verdict}: {passed} of 3 receipt\(s\) passed ")
        self.assertEqual(len(TRACE_ANCHORED.findall(out)), anchored, out)
        self.assertNotRegex(out, CHAIN_CHECKED)

    # -- projection shapes never built before
    def test_projection_not_a_list(self):
        self.baseline()
        self.outcome(self.run_b(reg={"entries": self.reg}), FAILED, "TV-REGISTRY-001")

    def test_empty_projection_logs_no_issuance(self):
        self.baseline()
        self.outcome(self.run_b(reg=[]), FAILED, "TV-TRUST-004")

    def test_projection_entry_not_an_object(self):
        self.baseline()
        self.outcome(self.run_b(reg=[*self.reg, "not-an-object"]), FAILED, "TV-REGISTRY-003")

    def test_every_defective_entry_is_reported(self):
        self.baseline()
        reg = ["not-an-object",
               entry(1, LINEAGE_HEAD, self.c, self.root, "child_key_suspend"),
               entry(2, LINEAGE_HEAD, self.c, self.root, extra={"x": 1})]
        rc, out = self.run_b(reg=reg)
        self.outcome((rc, out), FAILED, "TV-REGISTRY-003")
        self.assertEqual(len(re.findall(r"(?m)^FAIL \[TV-REGISTRY-003\] ", out)), 3, out)

    def test_projection_entry_version_wrong(self):
        self.baseline()
        reg = [entry(0, LINEAGE_HEAD, self.c, self.root, entry_version="trs-lineage-projection/9")]
        self.outcome(self.run_b(reg=reg), FAILED, "TV-REGISTRY-003")

    def test_projection_sequence_misnumbered_but_linked(self):
        self.baseline()
        self.outcome(self.run_b(reg=[entry(1, LINEAGE_HEAD, self.c, self.root)]),
                     FAILED, "TV-REGISTRY-001")

    # -- every projection failure: nothing is counted or anchored afterwards
    def test_projection_failures_are_not_used(self):
        rogue = Key()
        cases = {
            "undeclared-member": ("TV-REGISTRY-003",
                                  [entry(0, LINEAGE_HEAD, self.c, self.root, extra={"x": 1})]),
            "missing-member": ("TV-REGISTRY-003",
                               [*self.reg, checkpoint(1, self.reg[0]["this_hash"], self.c, self.root,
                                                      self.ch[2]["integrity_hash"], 2,
                                                      drop=("withheld_digest",))]),
            "unknown-event": ("TV-REGISTRY-003",
                              [*self.reg, entry(1, self.reg[0]["this_hash"], self.c, self.root,
                                                "child_key_suspend")]),
            "no-lineage-anchor": ("TV-REGISTRY-004", [entry(0, None, self.c, self.root)]),
            "broken-link": ("TV-REGISTRY-001",
                            [*self.reg, entry(1, LINEAGE_HEAD, self.c, self.root,
                                              "child_key_rotate")]),
            "not-root-signed": ("TV-REGISTRY-002",
                                [entry(0, LINEAGE_HEAD, self.c, self.root, signer=rogue)]),
        }
        for name, (check, reg) in cases.items():
            with self.subTest(case=name):
                self.baseline()
                self.outcome(self.run_b(reg=reg), FAILED, check)

    # -- certificate selection and shape
    def test_other_keys_certificate_listed_first(self):
        other = Key()
        oc = certificate(other, self.root, scope_id=SCOPE)
        reg = Proj(self.root).issue(oc).issue(self.c).items
        rc, out = self.run_b(certs=[oc, self.c], reg=reg)
        self.assertEqual(rc, VERIFIED, out)
        self.assertEqual(len(TRACE_ANCHORED.findall(out)), 3, out)

    def test_certificate_shape_with_valid_root_signature(self):
        cases = {
            "undeclared-member": ({"extra": 1}, "TV-TRUST-001"),
            "cert-version": ({"cert_version": "trs-cert/9"}, "TV-TRUST-001"),
        }
        for name, (over, check) in cases.items():
            with self.subTest(case=name):
                self.baseline()
                c = certificate(self.dep, self.root, scope_id=SCOPE, **over)
                self.outcome(self.run_b(certs=[c], reg=[entry(0, LINEAGE_HEAD, c, self.root)]),
                             FAILED, check)

    def test_child_key_id_not_the_certified_keys(self):
        self.baseline()
        fake = "sha256:" + "ab" * 32
        c = certificate(self.dep, self.root, scope_id=SCOPE, child_key_id=fake)
        ch = copy.deepcopy(self.ch)
        for r in ch:
            r["signature"]["key_id"] = fake      # outside the signed hash
        self.outcome(self.run_b(ch=ch, certs=[c], reg=[entry(0, LINEAGE_HEAD, c, self.root)]),
                     FAILED, "TV-TRUST-003")

    # -- per-receipt failures: the failed receipt is not counted or anchored
    def test_receipt_failures_are_not_counted(self):
        rogue, other = Key(), Key()
        no_kid = copy.deepcopy(self.ch)
        for r in no_kid:
            del r["signature"]["key_id"]
        oc = certificate(other, self.root, scope_id=SCOPE)
        cases = {
            "anchor-001": (FAILED, "TV-ANCHOR-001", {"ch": no_kid}),
            "trust-002": (INCOMPLETE, "TV-TRUST-002",
                          {"certs": [oc], "reg": [entry(0, LINEAGE_HEAD, oc, self.root)]}),
            "trust-001": (FAILED, "TV-TRUST-001",
                          {"certs": [certificate(self.dep, self.root, signer=rogue, scope_id=SCOPE)]}),
            "anchor-002": (FAILED, "TV-ANCHOR-002", self.with_cert(purpose="other")),
            "anchor-004": (FAILED, "TV-ANCHOR-004", {"ch": chain03(self.dep, scope_id=DROP)}),
            "anchor-005": (FAILED, "TV-ANCHOR-005", {"ch": chain03(self.dep, scope_id="scope:other")}),
            "trust-004": (FAILED, "TV-TRUST-004",
                          {"reg": [entry(0, LINEAGE_HEAD, oc, self.root)]}),
            "anchor-003": (INCOMPLETE, "TV-ANCHOR-003",
                           {"reg": Proj(self.root).issue(self.c).event(self.c).items}),
        }
        for name, (rc_expected, check, kw) in cases.items():
            with self.subTest(case=name):
                self.baseline()
                self.outcome(self.run_b(**kw), rc_expected, check)

    def with_cert(self, **over):
        c = certificate(self.dep, self.root, scope_id=SCOPE, **over)
        return {"certs": [c], "reg": [entry(0, LINEAGE_HEAD, c, self.root)]}

    def test_closing_checkpoint_counts_only_the_preceding_receipt(self):
        self.baseline()
        reg = (Proj(self.root).issue(self.c).cp(self.c, self.ch[0]["integrity_hash"], 0)
               .event(self.c).items)
        self.outcome(self.run_b(reg=reg), FAILED, "TV-ANCHOR-006", passed=1, anchored=1)

    # -- two key events: a later closing checkpoint still decides
    def test_later_event_closing_checkpoint_is_not_skipped(self):
        self.baseline()
        reg = (Proj(self.root).issue(self.c)
               .cp(self.c, self.ch[2]["integrity_hash"], 2).event(self.c, "child_key_rotate")
               .cp(self.c, self.ch[0]["integrity_hash"], 0).event(self.c, "child_key_revoke")
               .items)
        self.outcome(self.run_b(reg=reg), FAILED, "TV-ANCHOR-006", passed=1, anchored=1)

    def test_receipt_payload_not_an_object(self):
        self.baseline()
        odd = dict(self.ch[0], payload="not-an-object")
        rc, out = self.run_b(ch=[*self.ch, odd])
        self.assertNotIn("Traceback", out)
        self.assertEqual(rc, FAILED, out)
        self.assertRegex(out, r"(?m)^FAIL \[TV-SCHEMA-001\] ")
        self.assertRegex(out, r"(?m)^FAILED: 3 of 4 receipt\(s\) passed ")


class AnchorGating(Base):
    """Trust material that is incomplete or unusable keeps the run anchored and counts nothing.

    A directory of receipts is verified in anchored mode (--root-key plus
    --trust-dir). Each unusable combination must stay INCOMPLETE under exactly
    one diagnostic, and must never fall back to checking under --key.
    """

    def setUp(self):
        super().setUp()
        self.root, self.dep, self.c, self.ch, self.certs, self.reg = world03()
        self.rdir = self.tmp / "receipts"
        self.rdir.mkdir()
        for i, rec in enumerate(self.ch):
            (self.rdir / f"r{i}.json").write_text(json.dumps(rec, indent=1))
        self.trust = self.tmp / "trust"
        self.trust.mkdir()
        (self.trust / "dep0.cert.json").write_text(json.dumps(self.c))
        (self.trust / "projection.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in self.reg))

    def raw_keyfile(self, text):
        return self.put(raw=text + "\n", suffix=".pub.b64")

    def test_directory_verifies_anchored(self):
        rc, out = self.run_tool(self.rdir, "--root-key", self.keyfile(self.root),
                                "--trust-dir", self.trust)
        self.assertEqual(rc, VERIFIED, out)
        self.assertEqual(len(TRACE_ANCHORED.findall(out)), 3, out)
        self.assertIn("NOTE: ANCHORED for 3 receipt(s)", out)

    def test_unusable_trust_material_counts_nothing(self):
        empty = self.tmp / "empty-trust"
        empty.mkdir()
        dep_key = ("--key", self.keyfile(self.dep))
        root = ("--root-key", self.keyfile(self.root))
        cases = {
            "trust-dir-without-root-key": ("TV-LOAD-002", ("--trust-dir", self.trust)),
            "root-key-without-trust": ("TV-LOAD-002", root),
            "empty-trust-dir": ("TV-LOAD-002", (*root, "--trust-dir", empty)),
            "unreadable-root-key": ("TV-LOAD-002", ("--root-key", self.raw_keyfile("garbage"),
                                                    "--trust-dir", self.trust)),
            "refused-root-key": ("TV-KEY-001", ("--root-key",
                                                self.raw_keyfile(base64.b64encode(IDENTITY).decode()),
                                                "--trust-dir", self.trust)),
        }
        for name, (check, args) in cases.items():
            with self.subTest(case=name):
                self.test_directory_verifies_anchored()
                rc, out = self.run_tool(self.rdir, *dep_key, *args)
                self.assert_one_incomplete(rc, out, check)

    def test_bundle_with_unusable_root_counts_nothing(self):
        rc, out = self.run_tool(self.put(bundle(self.root, self.ch, self.certs, self.reg),
                                         suffix=".bundle.json"))
        self.assertEqual(rc, VERIFIED, out)                  # self-rooted baseline
        b = bundle(self.root, self.ch, self.certs, self.reg)
        b["trusted_root_public_key"] = "!!!!"
        rc, out = self.run_tool(self.put(b, suffix=".bundle.json"))
        self.assert_one_incomplete(rc, out, "TV-LOAD-002")

    def assert_one_incomplete(self, rc, out, check):
        self.assertNotIn("Traceback", out)
        self.assertEqual(rc, INCOMPLETE, out)
        self.assertEqual(DIAGNOSTIC.findall(out), [check], out)
        self.assertRegex(out, r"(?m)^INCOMPLETE: 0 of 3 receipt\(s\) passed ")
        self.assertNotRegex(out, TRACE_ANCHORED)
        self.assertNotIn("SIGNATURE CHECKED", out)       # never checked under --key instead


if __name__ == "__main__":
    unittest.main()
