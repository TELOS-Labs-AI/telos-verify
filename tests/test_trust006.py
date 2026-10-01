#!/usr/bin/env python3
"""TV-TRUST-006: the self-rooted test-bundle reporting rule (S3 3.4, TRS-S3-036).

TV-TRUST-006 is a contract check like TV-OUT-001: declared in --list-checks
with state ANY, never printed as a FAIL or INCOMPLETE line. It names the rule
that a passing self-rooted test-bundle run prints the TEST BUNDLE warning and
makes no anchored or certified claim.

Every self-rooted case sits beside its GREEN baseline: the same bundle with
the caller's --root-key is anchored and carries no TEST BUNDLE warning.
Keys are generated in-test.
"""
from __future__ import annotations

import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_s3_conformance import VERIFIED, Base, anchored_world, bundle

WARNING_LINE = re.compile(r"(?m)^WARNING: TEST BUNDLE\. ")
# A claim is the upper-case status word not negated by "NOT " (the verifier's claim
# forms are "ANCHORED:" and "NOTE: ANCHORED for"), or "certified" in any case. Plain
# prose such as "no receipt is reported as anchored" is not a claim.
CLAIM = re.compile(r"(?<!NOT )\b(ANCHORED|CERTIFIED)\b|(?i:\bcertified\b)")
TRUST006_LINE = re.compile(r"(?m)^(FAIL|INCOMPLETE) \[TV-TRUST-006\]")


class Trust006(Base):
    def world(self):
        root, _dep, _c, ch, certs, reg = anchored_world()
        return root, self.put(bundle(root, ch, certs, reg), suffix=".bundle.json")

    def test_list_checks_declares_trust_006_as_contract(self):
        rc, out = self.run_tool("--list-checks")
        self.assertEqual(rc, VERIFIED, out)
        self.assertRegex(out, r"(?m)^CHECK TV-TRUST-006  ANY  \S")
        # declared exactly as TV-OUT-001 is
        self.assertRegex(out, r"(?m)^CHECK TV-OUT-001  ANY  \S")

    def test_root_key_baseline_is_anchored_without_warning(self):
        root, p = self.world()
        rc, out = self.run_tool(p, "--root-key", self.keyfile(root))
        self.assertEqual(rc, VERIFIED, out)
        self.assertRegex(out, r"(?<!NOT )\bANCHORED\b")
        self.assertNotRegex(out, WARNING_LINE)

    def test_self_rooted_run_warns_and_claims_nothing(self):
        root, p = self.world()
        rc, ctl = self.run_tool(p, "--root-key", self.keyfile(root))     # baseline beside it
        self.assertEqual(rc, VERIFIED, ctl)
        self.assertRegex(ctl, r"(?<!NOT )\bANCHORED\b")
        rc, out = self.run_tool(p)
        self.assertEqual(rc, VERIFIED, out)
        self.assertRegex(out, WARNING_LINE)
        for line in out.splitlines():
            self.assertNotRegex(line, CLAIM, f"anchored/certified claim in: {line}")
        self.assertIn("NOT ANCHORED", out)
        self.assertNotRegex(out, TRUST006_LINE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
