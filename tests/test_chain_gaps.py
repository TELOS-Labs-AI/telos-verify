#!/usr/bin/env python3
"""Chain inputs the suite did not pin (gaps found by mutation testing).

- receipts whose file order is not their sequence order (the tool must sort
  by `sequence`, not by the order the files were read);
- a non-contiguous sequence (TV-CHAIN-002);
- a payload carrying the previous-hash member without `sequence`;
- after any chain failure, linkage is never reported as CHECKED and no
  second, derived chain failure is added;
- the verdict names the linked subset when an unsequenced receipt is present,
  and states the head-pin outcome, matched or not.

Each invalid set runs beside the valid baseline. Keys are generated in-test.
"""
from __future__ import annotations

import json
import re
import unittest

from test_s3_conformance import FAILED, VERIFIED, Base, Key, chain, h, signed

CHECKED = re.compile(r"(?m)^ok +CHAIN LINKAGE CHECKED")
CHAIN_TAG = re.compile(r"(?m)^FAIL \[(TV-CHAIN-\d+)\] ")


class ChainGaps(Base):
    def setUp(self):
        super().setUp()
        self.k = Key()
        self.kf = self.keyfile(self.k)

    def run_dir(self, named, *extra):
        self.n += 1
        d = self.tmp / f"d{self.n}"
        d.mkdir()
        for name, rec in named:
            (d / name).write_text(json.dumps(rec, indent=1))
        return self.run_tool(d, "--key", self.kf, *extra)

    def in_order(self, c):
        return [(f"r{i}.json", rec) for i, rec in enumerate(c)]

    def baseline(self):
        rc, out = self.run_dir(self.in_order(chain(self.k)))
        self.assertEqual(rc, VERIFIED, out)
        self.assertRegex(out, CHECKED)

    def failed_once(self, rc_out, check):
        """FAILED under `check` alone among chain tags, and linkage never reported CHECKED."""
        rc, out = rc_out
        self.assertNotIn("Traceback", out)
        self.assertEqual(rc, FAILED, out)
        self.assertEqual(set(CHAIN_TAG.findall(out)), {check}, out)
        self.assertNotRegex(out, CHECKED)

    def resigned(self, c, i, **payload):
        """Receipt i of c with its payload changed and its hash and signature redone."""
        p = dict(c[i]["payload"], **payload)
        for m in [m for m, v in payload.items() if v is DROP]:
            del p[m]
        return signed(self.k, p)

    def test_file_order_differs_from_sequence_order(self):
        self.baseline()
        c = chain(self.k)
        rc, out = self.run_dir([("c.json", c[0]), ("b.json", c[1]), ("a.json", c[2])])
        self.assertEqual(rc, VERIFIED, out)
        self.assertRegex(out, CHECKED)

    def test_sequence_gap_is_chain_002(self):
        self.baseline()
        c = chain(self.k)
        c[2] = self.resigned(c, 2, sequence=3)
        self.failed_once(self.run_dir(self.in_order(c)), "TV-CHAIN-002")

    def test_broken_link_is_chain_003(self):
        self.baseline()
        c = chain(self.k)
        c[2] = self.resigned(c, 2, previous_receipt_integrity_hash=h({"not": "receipt 1"}))
        self.failed_once(self.run_dir(self.in_order(c)), "TV-CHAIN-003")

    def test_previous_hash_without_sequence_is_chain_004(self):
        self.baseline()
        c = chain(self.k)
        c[1] = self.resigned(c, 1, sequence=DROP)
        self.failed_once(self.run_dir(self.in_order(c)), "TV-CHAIN-004")

    def test_sequence_without_previous_hash_is_not_linked(self):
        # The genesis previous hash is null, so a missing member would otherwise link.
        self.baseline()
        c = chain(self.k)
        c[0] = self.resigned(c, 0, previous_receipt_integrity_hash=DROP)
        self.failed_once(self.run_dir(self.in_order(c)), "TV-CHAIN-004")

    def test_duplicate_sequence_adds_no_linkage_failure(self):
        self.baseline()
        c = chain(self.k)
        dup = self.resigned(c, 1, action_name="fork")
        self.failed_once(self.run_dir([*self.in_order(c), ("r1b.json", dup)]), "TV-CHAIN-005")

    def test_failed_bystander_stops_linkage(self):
        self.baseline()
        tampered = signed(self.k)
        tampered["payload"]["action_name"] = "tampered"
        self.failed_outside_chain(self.run_dir([*self.in_order(chain(self.k)), ("z.json", tampered)]))

    def failed_outside_chain(self, rc_out):
        rc, out = rc_out
        self.assertEqual(rc, FAILED, out)
        self.assertRegex(out, r"(?m)^FAIL \[TV-HASH-004\] ")
        self.assertNotRegex(out, CHECKED)
        self.assertRegex(out, r"(?m)^FAILED: 3 of 4 receipt\(s\) passed ")

    # -- verdict text about the chain
    def verdict(self, out):
        return " ".join(out.split())

    def test_verdict_names_the_linked_subset(self):
        self.baseline()
        c = chain(self.k)
        rc, out = self.run_dir([*self.in_order(c), ("z.json", signed(self.k))])
        self.assertEqual(rc, VERIFIED, out)
        v = self.verdict(out)
        self.assertIn("NOTE: CHAIN LINKAGE CHECKED for 3 of 4 receipt(s): 2 neighbouring link(s)", v)
        self.assertIn("NOTE: 1 receipt(s) carry no `sequence` field and were NOT linked at all.", v)
        self.assertNotIn("for all 3 receipt(s)", v)

    def test_head_pin_matched_keeps_the_linkage_note(self):
        self.baseline()
        c = chain(self.k)
        head = c[-1]["integrity_hash"]
        rc, out = self.run_dir(self.in_order(c), "--expected-head", head)
        self.assertEqual(rc, VERIFIED, out)
        v = self.verdict(out)
        self.assertIn("NOTE: CHAIN LINKAGE CHECKED for all 3 receipt(s)", v)
        self.assertIn(f"NOTE: HEAD PIN CHECKED: the observed chain head matches the expected "
                      f"head supplied by the caller: {head}", v)
        self.assertNotIn("expected chain head:", v)

    def test_head_pin_mismatch_verdict(self):
        self.baseline()
        c = chain(self.k)
        other = h({"not": "the head"})
        rc, out = self.run_dir(self.in_order(c), "--expected-head", other)
        self.assertEqual(rc, FAILED, out)
        v = self.verdict(out)
        self.assertIn("FAILED: 3 of 3 individual receipt check(s) passed; the chain-head check "
                      "failed.", v)
        self.assertIn(f"NOTE: expected chain head: {other}", v)
        self.assertIn(f"observed chain head: {c[-1]['integrity_hash']}", v)

    def test_no_head_pin_notes_without_a_pin(self):
        self.baseline()
        c = chain(self.k)
        c[2] = self.resigned(c, 2, sequence=3)
        rc, out = self.run_dir(self.in_order(c))
        self.assertEqual(rc, FAILED, out)
        self.assertNotIn("expected chain head:", out)
        self.assertIn("FAILED: 3 of 3 receipt(s) passed the implemented per-receipt checks", out)


DROP = object()


if __name__ == "__main__":
    unittest.main()
