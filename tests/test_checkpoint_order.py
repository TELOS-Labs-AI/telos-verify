#!/usr/bin/env python3
"""Conformance tests: checkpoint ordering (S4 4.9).

Let E be a child_key_rotate/child_key_revoke entry for key K, R a receipt
signed by K at chain sequence s, and C the checkpoint for K with the highest
projection sequence below E's. C applies when R's chain holds a receipt at
C.chain_sequence whose integrity_hash is C.chain_head.
  R precedes E : C applies and s <= chain_sequence          -> passes
  R follows E  : C applies, s > chain_sequence, C closes E  -> FAILED  [TV-ANCHOR-006]
  otherwise    : undecided                                   -> INCOMPLETE [TV-ANCHOR-003]
A non-null valid_until is always undecided. Only projection position is used:
timestamp, effective_at and issued_at never change the outcome.

Every case sits beside a GREEN valid anchored bundle. Keys are generated in-test.
"""
from __future__ import annotations

import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_anchored03 import SCOPE, chain03, checkpoint, world03
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

T_OTHER = "2031-01-01T00:00:00Z"


class Proj:
    """Build a hash-linked projection entry by entry."""

    def __init__(self, root):
        self.root, self.items = root, []

    def _parent(self):
        return self.items[-1]["this_hash"] if self.items else LINEAGE_HEAD

    def issue(self, cert, **over):
        self.items.append(entry(len(self.items), self._parent(), cert, self.root, **over))
        return self

    def event(self, cert, kind="child_key_revoke", **over):
        self.items.append(entry(len(self.items), self._parent(), cert, self.root, kind, **over))
        return self

    def cp(self, cert, head, cs, **extra):
        e = checkpoint(len(self.items), self._parent(), cert, self.root, head, cs,
                       extra=extra or None)
        self.items.append(e)
        return self


class CheckpointOrder(Base):
    def setUp(self):
        super().setUp()
        self.root, self.dep, self.c, self.ch, _, _ = world03()

    def run_b(self, ch, certs, reg):
        rc, out = self.run_tool(self.put(bundle(self.root, ch, certs, reg), suffix=".bundle.json"),
                                "--root-key", self.keyfile(self.root))
        return rc, out

    def baseline(self):
        # GREEN control: valid anchored bundle, no key events.
        rc, out = self.run_b(self.ch, [self.c], Proj(self.root).issue(self.c).items)
        self.assertEqual(rc, VERIFIED, out)
        self.assertIn("ANCHORED", out)

    def expect(self, reg, rc_expected, check=None, text=None, certs=None, ch=None):
        self.baseline()
        if rc_expected == VERIFIED:
            rc, out = self.run_b(ch or self.ch, certs or [self.c], reg)
            self.assertEqual(rc, VERIFIED, out)
            self.assertNotRegex(out, r"(?m)^(FAIL|INCOMPLETE) ")
            return out
        return self.bad([self.put(bundle(self.root, ch or self.ch, certs or [self.c], reg),
                                  suffix=".bundle.json"), "--root-key", self.keyfile(self.root)],
                        rc_expected, check, text)

    def head(self, i):
        return self.ch[i]["integrity_hash"]

    # ---- precedes
    def test_checkpoint_places_all_before_revoke_verifies(self):
        reg = Proj(self.root).issue(self.c).cp(self.c, self.head(2), 2).event(self.c).items
        self.expect(reg, VERIFIED)

    def test_checkpoint_places_all_before_rotate_verifies(self):
        reg = (Proj(self.root).issue(self.c).cp(self.c, self.head(2), 2)
               .event(self.c, "child_key_rotate").items)
        self.expect(reg, VERIFIED)

    def test_boundary_sequence_equal_to_chain_sequence_precedes(self):
        # s == chain_sequence precedes (<=); only the last receipt sits on the boundary.
        reg = Proj(self.root).issue(self.c).cp(self.c, self.head(2), 2).event(self.c).items
        out = self.expect(reg, VERIFIED)
        self.assertNotIn("TV-ANCHOR-006", out)

    # ---- follows (FAILED)
    def test_anchor_006_closing_checkpoint_places_receipt_after(self):
        reg = Proj(self.root).issue(self.c).cp(self.c, self.head(1), 1).event(self.c).items
        out = self.expect(reg, FAILED, "TV-ANCHOR-006", "after the key's")
        self.assertRegex(out, r"(?m)^FAIL \[TV-ANCHOR-006\] .*chain\[2\]")
        self.assertNotRegex(out, r"(?m)^FAIL \[TV-ANCHOR-006\] .*chain\[[01]\]")

    def test_highest_checkpoint_below_event_is_used(self):
        # C1 would place all before; the later C2 (closing) places 1 and 2 after.
        reg = (Proj(self.root).issue(self.c).cp(self.c, self.head(2), 2)
               .cp(self.c, self.head(0), 0).event(self.c).items)
        out = self.expect(reg, FAILED, "TV-ANCHOR-006", "after the key's")
        self.assertRegex(out, r"(?m)^FAIL \[TV-ANCHOR-006\] .*chain\[1\]")

    def test_failed_outranks_undecided_across_events(self):
        # E1 closed by C (FAILED for seq 2); E2 not closed (undecided): FAILED wins.
        reg = (Proj(self.root).issue(self.c).cp(self.c, self.head(1), 1)
               .event(self.c, "child_key_rotate").event(self.c).items)
        self.expect(reg, FAILED, "TV-ANCHOR-006", "after the key's")

    def test_failed_outranks_undecided_when_undecided_event_first(self):
        # E1 (no checkpoint below it) is undecided and comes first; E2 is closed by C.
        reg = (Proj(self.root).issue(self.c).event(self.c, "child_key_rotate")
               .cp(self.c, self.head(1), 1).event(self.c).items)
        self.expect(reg, FAILED, "TV-ANCHOR-006", "after the key's")

    # ---- undecided (INCOMPLETE)
    def test_no_checkpoint_is_undecided(self):
        reg = Proj(self.root).issue(self.c).event(self.c).items
        self.expect(reg, INCOMPLETE, "TV-ANCHOR-003",
                    "cannot be placed relative to the key's effective time")

    def test_checkpoint_head_on_another_chain_is_undecided(self):
        other = chain03(Key(), pa_id="pa-other-chain")  # different payloads, different hashes
        self.assertNotEqual(other[2]["integrity_hash"], self.head(2))
        reg = (Proj(self.root).issue(self.c).cp(self.c, other[2]["integrity_hash"], 2)
               .event(self.c).items)
        self.expect(reg, INCOMPLETE, "TV-ANCHOR-003", "cannot be placed")

    def test_checkpoint_head_at_wrong_sequence_is_undecided(self):
        # the hash is on this chain, but at sequence 1, not the claimed 2
        reg = Proj(self.root).issue(self.c).cp(self.c, self.head(1), 2).event(self.c).items
        self.expect(reg, INCOMPLETE, "TV-ANCHOR-003", "cannot be placed")

    def test_non_adjacent_checkpoint_higher_sequence_is_undecided(self):
        c2 = certificate(Key(), self.root, scope_id=SCOPE)
        reg = (Proj(self.root).issue(self.c).cp(self.c, self.head(1), 1).issue(c2)
               .event(self.c).items)
        out = self.expect(reg, INCOMPLETE, "TV-ANCHOR-003", "cannot be placed",
                          certs=[self.c, c2])
        self.assertNotIn("TV-ANCHOR-006", out)

    def test_checkpoint_after_event_does_not_count(self):
        reg = Proj(self.root).issue(self.c).event(self.c).cp(self.c, self.head(2), 2).items
        self.expect(reg, INCOMPLETE, "TV-ANCHOR-003", "cannot be placed")

    def test_checkpoint_for_other_key_does_not_count(self):
        k2 = Key()
        c2 = certificate(k2, self.root, scope_id=SCOPE)
        reg = (Proj(self.root).issue(self.c).issue(c2).cp(c2, self.head(2), 2)
               .event(self.c).items)
        self.expect(reg, INCOMPLETE, "TV-ANCHOR-003", "cannot be placed", certs=[self.c, c2])

    def test_valid_until_is_undecided_even_with_checkpoint(self):
        c = certificate(self.dep, self.root, scope_id=SCOPE, valid_until="2027-01-01T00:00:00Z")
        reg = Proj(self.root).issue(c).cp(c, self.head(2), 2).event(c).items
        self.expect(reg, INCOMPLETE, "TV-ANCHOR-003", "cannot be placed", certs=[c])

    def test_event_for_other_key_is_ignored(self):
        c2 = certificate(Key(), self.root, scope_id=SCOPE)
        reg = Proj(self.root).issue(self.c).issue(c2).event(c2).items
        self.expect(reg, VERIFIED, certs=[self.c, c2])

    # ---- timestamps never used
    def outcome(self, rc, out):
        return rc, sorted(set(re.findall(r"(?m)^(?:FAIL|INCOMPLETE) \[(TV-[A-Z0-9-]+)\]", out)))

    def test_timestamps_do_not_change_outcome(self):
        self.baseline()
        for build in (
            lambda ts, eff: Proj(self.root).issue(self.c, timestamp=ts, effective_at=eff)
                .cp(self.c, self.head(1), 1).event(self.c, timestamp=ts, effective_at=eff).items,
            lambda ts, eff: Proj(self.root).issue(self.c, timestamp=ts, effective_at=eff)
                .cp(self.c, self.head(2), 2).event(self.c, timestamp=ts, effective_at=eff).items,
            lambda ts, eff: Proj(self.root).issue(self.c, timestamp=ts, effective_at=eff)
                .event(self.c, timestamp=ts, effective_at=eff).items,
        ):
            a = self.outcome(*self.run_b(self.ch, [self.c], build("2026-09-30T12:00:00Z",
                                                                  "2026-09-30T12:00:00Z")))
            ch2 = [dict(r, issued_at=T_OTHER) for r in self.ch]  # issued_at is not covered
            reg2 = build(T_OTHER, "1999-01-01T00:00:00Z")
            b = self.outcome(*self.run_b(ch2, [self.c], reg2))
            self.assertEqual(a, b, "a timestamp changed the ordering outcome")
        # checkpoint timestamps too
        r1 = Proj(self.root).issue(self.c).cp(self.c, self.head(1), 1).event(self.c).items
        a = self.outcome(*self.run_b(self.ch, [self.c], r1))
        r2 = Proj(self.root).issue(self.c)
        r2.items.append(checkpoint(1, r2.items[-1]["this_hash"], self.c, self.root,
                                   self.head(1), 1, extra={"timestamp": T_OTHER}))
        r2.event(self.c)
        self.assertEqual(a, self.outcome(*self.run_b(self.ch, [self.c], r2.items)))
        self.assertEqual(a[0], FAILED)
        self.assertIn("TV-ANCHOR-006", a[1])

    def test_list_checks_declares_anchor_006(self):
        rc, out = self.run_tool("--list-checks")
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"(?m)^CHECK TV-ANCHOR-006\s+FAILED\s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
