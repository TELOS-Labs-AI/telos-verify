#!/usr/bin/env python3
"""Conformance tests: telos/0.3-ed25519 Section 2 checks.

TRS-S2-002 (0.3 noun vocabulary; historical labels only on 0.1/0.2),
TRS-S2-010 (0.3 scores in [0, 1]; historical contracts type-only),
TRS-S2-011 (boundary_flag boolean), TRS-S2-012 (specification_version,
observation_config_hash, optional profile_id). Every invalid input is tested
BESIDE a valid one in the same test. Keys are generated inside the test.

Out of scope here (see test_anchored03.py): S1 scope_id, S4 checkpoint and anchor rules.

Run:  python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import hashlib
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_s3_conformance import (
    COVERED,
    FAILED,
    SIG_COVERS,
    T0,
    VERIFIED,
    Base,
    Key,
    ag_payload,
    h,
)

V03 = "telos/0.3-ed25519"
CFG = "sha256:" + hashlib.sha256(b"observation config").hexdigest()


def payload03(**over):
    p = ag_payload(verdict="ALIGNMENT", composite_score=0.5, scores={"dim_a": 0.5})
    p.update(boundary_flag=False, specification_version="spec-test-001",
             observation_config_hash=CFG)
    for k, v in over.items():
        if v is DROP:
            p.pop(k, None)
        else:
            p[k] = v
    return p


DROP = object()


def receipt(key: Key, payload, version=V03):
    return {"receipt_version": version, "kind": "action_governed", "agent_id": "test-agent",
            "payload": payload, "issued_at": T0, "integrity_hash": h(payload),
            "covered_fields": COVERED, "signing_status": "ed25519_signed",
            "signature": {"algorithm": "ed25519", "covers": SIG_COVERS, "public_key": key.pub,
                          "key_id": key.kid,
                          "value": key.sign(h(payload).encode("ascii"))},
            "engine": "test engine"}


class Telos03(Base):
    def setUp(self):
        super().setUp()
        self.k = Key()
        self.kf = self.keyfile(self.k)

    def ok03(self, **over):
        return self.good(self.put(receipt(self.k, payload03(**over))), "--key", self.kf)

    def bad03(self, check, text, **over):
        self.ok03()
        return self.bad([self.put(receipt(self.k, payload03(**over))), "--key", self.kf],
                        FAILED, check, text)

    # -- contract recognised
    def test_valid_03_verifies(self):
        out = self.ok03()
        self.assertNotIn("TV-VER-001", out)

    def test_03_all_noun_labels_and_optional_profile_id(self):
        for label in ("ALIGNMENT", "UNCERTAINTY", "ADVISORY", "DIVERGENCE", "INERT"):
            self.ok03(verdict=label)
        self.ok03(profile_id="profile-x")

    # -- TRS-S2-002: vocabulary per contract
    def test_s2_002_historical_label_on_03_failed(self):
        self.bad03("TV-S2-002", "verdict is not in the public vocabulary", verdict="EXECUTE")

    def test_s2_002_noun_label_on_02_failed(self):
        p = ag_payload(verdict="EXECUTE")
        self.good(self.put(receipt(self.k, p, "telos/0.2-ed25519")), "--key", self.kf)
        p = ag_payload(verdict="ALIGNMENT")
        self.bad([self.put(receipt(self.k, p, "telos/0.2-ed25519")), "--key", self.kf],
                 FAILED, "TV-S2-002", "verdict is not in the public vocabulary")

    # -- TRS-S2-010: range on 0.3 only
    def test_s2_010_composite_above_one(self):
        self.ok03(composite_score=1)
        self.ok03(composite_score=0)
        self.bad03("TV-S2-010", "composite_score is outside [0, 1]", composite_score=1.5)

    def test_s2_010_composite_below_zero(self):
        self.bad03("TV-S2-010", "composite_score is outside [0, 1]", composite_score=-0.25)

    def test_s2_010_scores_value_out_of_range(self):
        self.ok03(scores={"a": 0, "b": 1})
        self.bad03("TV-S2-010", "scores value is outside [0, 1]", scores={"a": 0.5, "b": 2})

    def test_s2_010_historical_contract_stays_type_only(self):
        # A 0.2 receipt with 1.5 is not FAILED for range (Section 2, historical).
        p = ag_payload(composite_score=1.5, scores={"a": 7})
        out = self.good(self.put(receipt(self.k, p, "telos/0.2-ed25519")), "--key", self.kf)
        self.assertNotIn("TV-S2-010", out)
        self.bad03("TV-S2-010", "composite_score is outside [0, 1]", composite_score=1.5)

    # -- TRS-S2-011: boundary_flag
    def test_s2_011_boundary_flag_missing(self):
        self.bad03("TV-S2-011", "boundary_flag is absent or not a boolean", boundary_flag=DROP)

    def test_s2_011_boundary_flag_not_boolean(self):
        self.ok03(boundary_flag=True)
        self.bad03("TV-S2-011", "boundary_flag is absent or not a boolean", boundary_flag="false")

    def test_s2_011_boundary_flag_integer_is_not_boolean(self):
        self.bad03("TV-S2-011", "boundary_flag is absent or not a boolean", boundary_flag=0)

    # -- TRS-S2-012: provenance commitments
    def test_s2_012_specification_version_missing(self):
        self.bad03("TV-S2-012", "specification_version is absent or not a string",
                   specification_version=DROP)

    def test_s2_012_specification_version_not_string(self):
        self.bad03("TV-S2-012", "specification_version is absent or not a string", specification_version=3)

    def test_s2_012_observation_config_hash_missing(self):
        self.bad03("TV-S2-012", "observation_config_hash is absent or not sha256:",
                   observation_config_hash=DROP)

    def test_s2_012_observation_config_hash_malformed(self):
        self.bad03("TV-S2-012", "observation_config_hash is absent or not sha256:",
                   observation_config_hash=CFG.upper().replace("SHA256", "sha256"))

    def test_s2_012_profile_id_not_string(self):
        self.bad03("TV-S2-012", "profile_id is not a string", profile_id=5)

    # -- regressions: 0.3 members are not allowed on historical contracts
    def test_03_members_on_02_are_undeclared(self):
        p = ag_payload()
        self.good(self.put(receipt(self.k, p, "telos/0.2-ed25519")), "--key", self.kf)
        p = ag_payload(boundary_flag=False)
        self.bad([self.put(receipt(self.k, p, "telos/0.2-ed25519")), "--key", self.kf],
                 FAILED, "TV-SCHEMA-001", "undeclared member(s) boundary_flag")

    def test_03_undeclared_member_still_schema_failed(self):
        self.bad03("TV-SCHEMA-001", "undeclared member(s) surprise", surprise=1)

    def test_03_signature_block_checked_like_02(self):
        self.ok03()
        r = receipt(self.k, payload03())
        r["signature"]["note"] = "x"
        self.bad([self.put(r), "--key", self.kf], FAILED, "TV-SCHEMA-001",
                 "signature has undeclared member(s) note")

    def test_list_checks_declares_s2_010_to_012(self):
        rc, out = self.run_tool("--list-checks")
        self.assertEqual(rc, VERIFIED, out)
        for cid in ("TV-S2-010", "TV-S2-011", "TV-S2-012"):
            self.assertRegex(out, rf"(?m)^CHECK {cid}\s+FAILED\s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
