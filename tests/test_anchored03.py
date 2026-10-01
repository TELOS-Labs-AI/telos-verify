#!/usr/bin/env python3
"""Conformance tests: anchored telos/0.3.

Checks covered:
  TRS-S1-025/026  scope_id admitted on 0.3 only; non-empty string (TV-SCHEMA-001)
  TRS-S4-010      anchored mode accepts telos/0.3-ed25519 (TV-ANCHOR-001)
  TRS-S4-019      anchored 0.3 receipt without payload.scope_id (TV-ANCHOR-004)
  TRS-S4-020      payload.scope_id differs from the certificate's (TV-ANCHOR-005)
  TRS-S4-021      checkpoint entry members exactly Table 8 (TV-REGISTRY-003)
  TRS-S4-023      first projection entry carries a lineage anchor (TV-REGISTRY-004)
Checkpoint ORDERING (TRS-S4-022, TV-ANCHOR-006) is tested in test_checkpoint_order.py.

Every invalid input is tested BESIDE a valid one. Keys are generated in-test.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_s3_conformance import (
    ENTRY_COVERS,
    FAILED,
    LINEAGE_HEAD,
    T0,
    Base,
    Key,
    bundle,
    certificate,
    entry,
    h,
)
from test_telos03 import DROP, payload03, receipt

SCOPE = "scope:test"


def chain03(key: Key, n=3, **over):
    out, prev = [], None
    for i in range(n):
        kw = {"scope_id": SCOPE, **over}
        p = payload03(sequence=i, previous_receipt_integrity_hash=prev,
                      action_name=f"step{i}", **kw)
        r = receipt(key, p)
        out.append(r)
        prev = r["integrity_hash"]
    return out


def checkpoint(seq, parent, cert, root: Key, chain_head, chain_sequence, *, extra=None,
               drop=()):
    e = {"entry_version": "trs-lineage-projection/0.1", "sequence": seq,
         "event_type": "receipt_chain_checkpoint", "timestamp": T0, "parent_hash": parent,
         "root_key_id": root.kid, "child_key_id": cert["child_key_id"],
         "scope_id": cert["scope_id"], "chain_head": chain_head,
         "chain_sequence": chain_sequence, "withheld_digest": None}
    if extra:
        e.update(extra)
    for m in drop:
        e.pop(m)
    e["this_hash"] = h(e)
    e["root_signature"] = {"algorithm": "ed25519", "covers": ENTRY_COVERS,
                           "value": root.sign(e["this_hash"].encode("ascii"))}
    return e


def world03():
    root, dep = Key(), Key()
    c = certificate(dep, root, scope_id=SCOPE)
    return root, dep, c, chain03(dep), [c], [entry(0, LINEAGE_HEAD, c, root)]


class Anchored03(Base):
    def run_anchored(self, b, root):
        return [self.put(b, suffix=".bundle.json"), "--root-key", self.keyfile(root)]

    def valid(self):
        root, _dep, _c, ch, certs, reg = world03()
        out = self.good(*self.run_anchored(bundle(root, ch, certs, reg), root))
        self.assertIn("ANCHORED", out)
        return out

    def check_bad(self, b, root, rc, check, text):
        self.valid()
        return self.bad(self.run_anchored(b, root), rc, check, text)

    # -- TV-ANCHOR-001 accepts 0.3
    def test_anchored_03_verifies(self):
        out = self.valid()
        self.assertNotIn("TV-ANCHOR-001", out)

    def test_anchor_001_03_without_key_id(self):
        root, _dep, _c, ch, certs, reg = world03()
        for r in ch:
            del r["signature"]["key_id"]
        self.check_bad(bundle(root, ch, certs, reg), root, FAILED, "TV-ANCHOR-001",
                       "anchored receipt has no key_id")

    # -- TV-ANCHOR-004 / 005 (TRS-S4-019 / 020)
    def test_anchor_004_03_without_scope_id(self):
        root, dep, _c, ch, certs, reg = world03()
        ch = chain03(dep, scope_id=DROP)
        self.check_bad(bundle(root, ch, certs, reg), root, FAILED, "TV-ANCHOR-004",
                       "anchored telos/0.3 receipt has no scope_id")

    def test_anchor_005_scope_differs(self):
        root, dep, _c, ch, certs, reg = world03()
        ch = chain03(dep, scope_id="scope:other")
        self.check_bad(bundle(root, ch, certs, reg), root, FAILED, "TV-ANCHOR-005",
                       "scope_id differs from the certificate's")

    def test_anchor_005_equality_is_exact(self):
        root, dep, _c, ch, certs, reg = world03()
        ch = chain03(dep, scope_id=SCOPE.upper())
        self.check_bad(bundle(root, ch, certs, reg), root, FAILED, "TV-ANCHOR-005",
                       "scope_id differs from the certificate's")

    def test_02_anchored_checked_by_purpose_only(self):
        # Historical 0.2 receipts carry no covered scope (section 4.7).
        from test_s3_conformance import chain as chain02
        root, dep = Key(), Key()
        c = certificate(dep, root, scope_id=SCOPE)
        self.valid()
        self.good(*self.run_anchored(bundle(root, chain02(dep), [c],
                                            [entry(0, LINEAGE_HEAD, c, root)]), root))

    # -- TRS-S1-025/026: scope_id as a receipt member
    def test_unanchored_03_scope_id_admitted_not_scope_checked(self):
        k = Key()
        kf = self.keyfile(k)
        self.good(self.put(receipt(k, payload03())), "--key", kf)
        self.good(self.put(receipt(k, payload03(scope_id="anything"))), "--key", kf)

    def test_s1_026_scope_id_empty(self):
        k = Key()
        kf = self.keyfile(k)
        self.good(self.put(receipt(k, payload03(scope_id="s"))), "--key", kf)
        self.bad([self.put(receipt(k, payload03(scope_id=""))), "--key", kf], FAILED,
                 "TV-SCHEMA-001", "`scope_id` is not a non-empty string")

    def test_s1_026_scope_id_not_string(self):
        k = Key()
        kf = self.keyfile(k)
        self.good(self.put(receipt(k, payload03(scope_id="s"))), "--key", kf)
        self.bad([self.put(receipt(k, payload03(scope_id=7))), "--key", kf], FAILED,
                 "TV-SCHEMA-001", "`scope_id` is not a non-empty string")

    def test_scope_id_on_02_is_undeclared(self):
        from test_s3_conformance import ag_payload
        k = Key()
        kf = self.keyfile(k)
        self.good(self.put(receipt(k, ag_payload(), "telos/0.2-ed25519")), "--key", kf)
        self.bad([self.put(receipt(k, ag_payload(scope_id=SCOPE), "telos/0.2-ed25519")),
                  "--key", kf], FAILED, "TV-SCHEMA-001", "undeclared member(s) scope_id")

    # -- TV-REGISTRY-004 (TRS-S4-023)
    def test_registry_004_first_parent_null(self):
        root, _dep, c, ch, certs, _reg = world03()
        self.check_bad(bundle(root, ch, certs, [entry(0, None, c, root)]), root, FAILED,
                       "TV-REGISTRY-004", "first projection entry has no lineage anchor")

    def test_registry_004_first_parent_malformed(self):
        root, _dep, c, ch, certs, _reg = world03()
        bad = "sha256:" + LINEAGE_HEAD[7:].upper()
        self.check_bad(bundle(root, ch, certs, [entry(0, bad, c, root)]), root, FAILED,
                       "TV-REGISTRY-004", "first projection entry has no lineage anchor")

    def test_registry_001_later_entry_still_linked(self):
        root, _dep, c, ch, certs, reg = world03()
        e1 = checkpoint(1, LINEAGE_HEAD, c, root, ch[-1]["integrity_hash"], 2)
        self.check_bad(bundle(root, ch, certs, [reg[0], e1]), root, FAILED, "TV-REGISTRY-001",
                       "registry projection link is broken")

    # -- checkpoint entries (TRS-S4-021): parsed and member-checked
    def test_checkpoint_entry_parsed(self):
        root, _dep, c, ch, certs, reg = world03()
        e1 = checkpoint(1, reg[0]["this_hash"], c, root, ch[-1]["integrity_hash"], 2)
        out = self.good(*self.run_anchored(bundle(root, ch, certs, [reg[0], e1]), root))
        self.assertIn("ANCHORED", out)

    def test_registry_003_checkpoint_extra_member(self):
        root, _dep, c, ch, certs, reg = world03()
        e1 = checkpoint(1, reg[0]["this_hash"], c, root, ch[-1]["integrity_hash"], 2,
                        extra={"note": "x"})
        self.check_bad(bundle(root, ch, certs, [reg[0], e1]), root, FAILED, "TV-REGISTRY-003",
                       "registry entry has an undeclared member: note")

    def test_registry_003_checkpoint_missing_member(self):
        root, _dep, c, ch, certs, reg = world03()
        e1 = checkpoint(1, reg[0]["this_hash"], c, root, ch[-1]["integrity_hash"], 2,
                        drop=("chain_sequence",))
        self.check_bad(bundle(root, ch, certs, [reg[0], e1]), root, FAILED, "TV-REGISTRY-003",
                       "registry entry lacks member(s) chain_sequence")

    def test_registry_003_key_event_with_checkpoint_member(self):
        root, _dep, c, ch, certs, _reg = world03()
        self.check_bad(bundle(root, ch, certs,
                              [entry(0, LINEAGE_HEAD, c, root, extra={"chain_head": LINEAGE_HEAD})]),
                       root, FAILED, "TV-REGISTRY-003",
                       "registry entry has an undeclared member: chain_head")

    def test_registry_003_unknown_event_type(self):
        root, _dep, c, ch, certs, _reg = world03()
        self.check_bad(bundle(root, ch, certs,
                              [entry(0, LINEAGE_HEAD, c, root, event="child_key_pause")]),
                       root, FAILED, "TV-REGISTRY-003", "event_type 'child_key_pause' is not")

    def test_list_checks_declares_new_ids(self):
        rc, out = self.run_tool("--list-checks")
        self.assertEqual(rc, 0, out)
        for cid in ("TV-ANCHOR-004", "TV-ANCHOR-005", "TV-REGISTRY-004"):
            self.assertRegex(out, rf"(?m)^CHECK {cid}\s+FAILED\s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
