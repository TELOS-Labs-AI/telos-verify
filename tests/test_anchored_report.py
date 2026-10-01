#!/usr/bin/env python3
"""The anchored verdict describes placement truthfully (S4 section 4.9).

A key may carry a rotate or revoke entry and still anchor a receipt that a
closing checkpoint places before it. The verdict must then say where the
receipts were placed, never that the key has no such entry. Keys, certificates,
projections and receipts are generated inside the tests.
"""
from __future__ import annotations

import re
import unittest

from test_anchored03 import world03
from test_checkpoint_order import Proj
from test_s3_conformance import VERIFIED, Base, bundle

ABSENCE_CLAIM = re.compile(r"no rotate or revoke entry")
PLACEMENT = "Each receipt precedes every rotate or revoke entry for its key"


class AnchoredVerdictPlacement(Base):
    def setUp(self):
        super().setUp()
        self.root, self.dep, self.c, self.ch, _, _ = world03()

    def run_b(self, reg, *extra):
        return self.run_tool(self.put(bundle(self.root, self.ch, [self.c], reg),
                                      suffix=".bundle.json"),
                             "--root-key", self.keyfile(self.root), *extra)

    def no_event(self):
        return Proj(self.root).issue(self.c).items

    def closed(self, kind):
        # Checkpoint at chain sequence 2 (the whole chain), then the key event.
        return (Proj(self.root).issue(self.c).cp(self.c, self.ch[2]["integrity_hash"], 2)
                .event(self.c, kind).items)

    def assert_truthful(self, rc, out):
        self.assertEqual(rc, VERIFIED, out)
        self.assertIn("NOTE: ANCHORED for 3 receipt(s)", out)
        self.assertIsNone(ABSENCE_CLAIM.search(out), out)
        self.assertIn(PLACEMENT, " ".join(out.split()))

    def test_baseline_no_key_event_verifies_anchored(self):
        for extra in ((), ("--quiet",)):
            with self.subTest(extra=extra):
                rc, out = self.run_b(self.no_event(), *extra)
                self.assertEqual(rc, VERIFIED, out)
                self.assertIn("NOTE: ANCHORED for 3 receipt(s)", out)

    def test_closed_revoke_valid_makes_no_absence_claim(self):
        for extra in ((), ("--quiet",)):
            with self.subTest(extra=extra):
                rc, out = self.run_b(self.no_event(), *extra)       # GREEN baseline beside it
                self.assertEqual(rc, VERIFIED, out)
                self.assert_truthful(*self.run_b(self.closed("child_key_revoke"), *extra))

    def test_closed_rotate_valid_makes_no_absence_claim(self):
        for extra in ((), ("--quiet",)):
            with self.subTest(extra=extra):
                rc, out = self.run_b(self.no_event(), *extra)       # GREEN baseline beside it
                self.assertEqual(rc, VERIFIED, out)
                self.assert_truthful(*self.run_b(self.closed("child_key_rotate"), *extra))

    def test_no_event_verdict_states_placement(self):
        for extra in ((), ("--quiet",)):
            with self.subTest(extra=extra):
                self.assert_truthful(*self.run_b(self.no_event(), *extra))


class ListChecksAnchor001(Base):
    def test_anchor_001_names_both_signed_versions(self):
        rc, out = self.run_tool("--list-checks")
        self.assertEqual(rc, VERIFIED, out)
        line = re.search(r"(?m)^CHECK TV-ANCHOR-001\s+FAILED\s+(.*)$", out)
        self.assertIsNotNone(line, out)
        self.assertIn("telos/0.3-ed25519", line.group(1))
        self.assertIn("telos/0.2-ed25519", line.group(1))
        self.assertIn("key_id", line.group(1))


if __name__ == "__main__":
    unittest.main()
