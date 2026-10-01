#!/usr/bin/env python3
"""Executable tests for telos-verify, including the Ed25519 signature path.

Run:  python3 -m unittest discover -s tests -v
  or: python3 tests/test_ed25519.py

NO KEY MATERIAL IS COMMITTED TO THIS REPOSITORY. Every keypair used here is
generated fresh in a temporary directory at test time and destroyed with it.
The tests drive the real command-line tool in a subprocess and assert on its
exit code, because the exit code is what a stranger wires into CI. Reading the
source and believing it would prove nothing.

The signature tests are negative-control-first on purpose: a signature checker
that cannot be made to say FAILED has not been shown to check anything.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from typing import ClassVar

REPO = pathlib.Path(__file__).resolve().parent.parent
TOOL = REPO / "telos_verify.py"

VERIFIED, FAILED, INCOMPLETE = 0, 1, 2

COVERED = "payload (canonical JSON, sort_keys, compact separators)"
SIG_COVERS = "integrity_hash (ASCII bytes of the sha256: string)"

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def canonical_bytes(payload) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")


def integrity_hash(payload) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def run(*args, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *[str(a) for a in args]],
        capture_output=True, text=True, env=env, check=False,
    )


def crypto_blocked_env(tmp: pathlib.Path) -> dict:
    """An environment where `import cryptography` raises, to prove the fallback.

    This is how the dependency claim gets tested instead of asserted: a stub
    module earlier on the path than the real package makes the import fail the
    same way it fails on a machine that never installed it.
    """
    blockdir = tmp / "_no_cryptography"
    blockdir.mkdir(exist_ok=True)
    (blockdir / "cryptography.py").write_text('raise ImportError("blocked for test")\n')
    return dict(os.environ, PYTHONPATH=str(blockdir))


def mint_signed(payload: dict, priv, agent_id="TELOS-Labs-AI/ephemeral-test") -> dict:
    """Build a telos/0.2-ed25519 receipt over `payload`, signed by `priv`."""
    ih = integrity_hash(payload)
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "receipt_version": "telos/0.2-ed25519",
        "kind": "benchmark_reverification_projection",
        "agent_id": agent_id,
        "payload": payload,
        "issued_at": "2026-08-10T00:00:00.000000Z",
        "integrity_hash": ih,
        "covered_fields": COVERED,
        "signing_status": "ed25519_signed",
        "signature": {
            "algorithm": "ed25519",
            "covers": SIG_COVERS,
            "public_key": base64.b64encode(raw_pub).decode("ascii"),
            "value": base64.b64encode(priv.sign(ih.encode("ascii"))).decode("ascii"),
        },
        "engine": "ephemeral test fixture (no governance engine wired)",
    }


def payload_at(seq: int, prev: str | None, current="0.00%") -> dict:
    return {
        "benchmark": f"EPHEMERAL_TEST_{seq}",
        "current": current,
        "disposition": "REPRODUCES",
        "previous_receipt_integrity_hash": prev,
        "published": "0.00%",
        "sequence": seq,
    }


class ExistingBehaviourUnchanged(unittest.TestCase):
    """The rehearsed tamper-evidence demo must behave exactly as before."""

    def test_valid_chain_still_verifies_unsigned(self):
        p = run(REPO / "vectors" / "valid")
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)
        self.assertIn("PAYLOAD-TO-HASH BINDING ESTABLISHED for 9 receipt(s)", p.stdout)
        self.assertIn("CHAIN LINKAGE CHECKED for all 9 receipt(s): 8 neighbouring link(s)",
                      p.stdout)
        self.assertIn("Anyone can fabricate an unsigned receipt", p.stdout)
        self.assertNotIn("HEAD PIN CHECKED", p.stdout)
        self.assertNotIn("SIGNATURE CHECKED", p.stdout)

    def test_tampered_chain_still_fails(self):
        p = run(REPO / "vectors" / "tampered")
        self.assertEqual(p.returncode, FAILED, p.stdout + p.stderr)
        self.assertIn(
            "FAILED: 8 of 9 receipt(s) passed the implemented per-receipt checks; "
            "one or more required checks failed.", p.stdout)

    def test_tampered_chain_quiet_output_is_standalone_and_not_contradictory(self):
        p = run(REPO / "vectors" / "tampered", "--quiet")
        self.assertEqual(p.returncode, FAILED, p.stdout + p.stderr)
        self.assertIn("one or more required checks failed", p.stdout)
        self.assertIn("Re-run without --quiet", p.stdout)
        self.assertNotIn("receipt(s) verified", p.stdout)

    def test_single_receipt_says_chain_not_evaluable(self):
        p = run(REPO / "vectors" / "valid" / "004_harmbench.json")
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)
        self.assertIn("CHAIN LINKAGE NOT EVALUABLE from this set", p.stdout)
        self.assertIn("PAYLOAD-TO-HASH BINDING ESTABLISHED for 1 receipt(s)", p.stdout)

    def test_require_signature_downgrades_unsigned_to_incomplete(self):
        p = run(REPO / "vectors" / "valid", "--require-signature")
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("INCOMPLETE is not a pass", p.stdout)


def render_with_members(members) -> str:
    """Serialize an ordered member list by hand, so a key CAN appear twice.

    json.dumps cannot emit a duplicate key from a dict, so the attack file has
    to be built at the text layer. The tests assert the result is still valid
    JSON, otherwise the probe would be testing a parse error instead of the
    duplicate-key split view.
    """
    parts = [f"  {json.dumps(k)}: {json.dumps(v, indent=2)}" for k, v in members]
    return "{\n" + ",\n".join(parts) + "\n}\n"


class DuplicateKeys(unittest.TestCase):
    """F1 — a file that says two things must be refused, not silently resolved.

    Python's json keeps the LAST occurrence of a repeated key; a human reading
    the file sees the FIRST. A receipt exploiting that gap gets a signed pass
    over a payload the auditor never saw.
    """

    EVIL: ClassVar[dict] = {"claim": "MALICIOUS PAYLOAD", "result": "pass"}

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="telos-verify-dup-"))
        self.base = json.loads((REPO / "vectors" / "valid" / "000_sb243.json").read_text())

    def write_dup(self, name, evil_first: bool) -> pathlib.Path:
        members = list(self.base.items())
        i = [k for k, _ in members].index("payload")
        at = i if evil_first else i + 1
        members = members[:at] + [("payload", self.EVIL)] + members[at:]
        path = self.tmp / name
        text = render_with_members(members)
        path.write_text(text)
        # The probe is only meaningful if the attack file is WELL-FORMED JSON.
        parsed = json.loads(text)
        self.assertEqual(text.count('"payload"'), 2)
        expect = self.EVIL if not evil_first else self.base["payload"]
        self.assertEqual(parsed["payload"], expect, "stdlib json is not last-wins here")
        return path

    def test_duplicate_payload_evil_first_is_refused(self):
        """The bypass: signed pass over a payload the reader never sees."""
        p = self.write_dup("evil_first.json", evil_first=True)
        r = run(p)
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("duplicate key 'payload'", r.stdout)
        self.assertNotIn("VERIFIED", r.stdout)

    def test_duplicate_payload_evil_last_is_refused(self):
        p = self.write_dup("evil_last.json", evil_first=False)
        r = run(p)
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("duplicate key 'payload'", r.stdout)

    def test_duplicate_key_nested_inside_payload_is_refused(self):
        """The hook must apply recursively, not just to the top-level object."""
        inner = '{"benchmark": "A", "benchmark": "B"}'
        text = render_with_members([(k, v) for k, v in self.base.items() if k != "payload"])
        text = text[:-2] + f',\n  "payload": {inner}\n}}\n'
        path = self.tmp / "nested_dup.json"
        path.write_text(text)
        json.loads(text)  # still well-formed
        r = run(path)
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("duplicate key 'benchmark'", r.stdout)

    def test_duplicate_key_refusal_is_not_a_traceback(self):
        p = self.write_dup("evil_first2.json", evil_first=True)
        r = run(p)
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(r.stderr, "")
        # A mutation review found this stayed green with duplicate-key detection
        # removed entirely, because a clean stderr says nothing about whether
        # the refusal happened. Assert the refusal AND its reason, so deleting
        # the mechanism turns this red.
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("duplicate key", r.stdout)

    def test_probe_control_an_unmodified_receipt_still_verifies(self):
        """Guard against a parser that now refuses everything."""
        path = self.tmp / "clean.json"
        path.write_text(render_with_members(list(self.base.items())))
        r = run(path)
        self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)


class MalformedInput(unittest.TestCase):
    """F4 — a crafted file must not crash, and must not silence its neighbours."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="telos-verify-malformed-"))

    def test_non_object_json_is_incomplete_not_a_traceback(self):
        p = self.tmp / "notdict.json"
        p.write_text("[1,2,3]\n")
        r = run(p)
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("not an object", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_one_poisoned_file_does_not_abort_the_directory(self):
        (self.tmp / "000.json").write_text(
            (REPO / "vectors" / "valid" / "000_sb243.json").read_text())
        (self.tmp / "zzz.json").write_text('"just a string"\n')
        r = run(self.tmp)
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("ok    000_sb243.json", r.stdout.replace("000.json", "000_sb243.json"))
        self.assertIn("1 of 2 receipt(s) passed the implemented per-receipt checks", r.stdout)
        self.assertNotIn("Traceback", r.stderr)


class ChainClaimHonesty(unittest.TestCase):
    """F2 — the verdict may only speak about linkage that was actually checked."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="telos-verify-chain-"))

    def mint_unsigned(self, name, payload):
        ih = integrity_hash(payload)
        rec = {
            "receipt_version": "telos/0.1-unsigned", "kind": "k", "agent_id": "a",
            "payload": payload, "issued_at": "2026-08-11T00:00:00Z", "integrity_hash": ih,
            "covered_fields": COVERED, "signing_status": "unsigned_integrity_hash",
            "signature": None, "engine": "e",
        }
        (self.tmp / name).write_text(json.dumps(rec, indent=2))

    def test_directory_without_sequence_fields_does_not_claim_a_chain(self):
        for i in range(3):
            self.mint_unsigned(f"{i:03d}.json", {"benchmark": f"NOLINK_{i}"})
        r = run(self.tmp)
        self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
        self.assertNotIn("the chain is intact", r.stdout)
        self.assertIn("CHAIN LINKAGE NOT EVALUABLE from this set", r.stdout)
        self.assertIn("no linkage to check", r.stdout)

    def test_the_tool_does_not_contradict_itself(self):
        """It said NOT EVALUABLE and 'the chain is intact' four lines apart."""
        for i in range(3):
            self.mint_unsigned(f"{i:03d}.json", {"benchmark": f"NOLINK_{i}"})
        out = run(self.tmp).stdout
        self.assertFalse("NOT EVALUABLE" in out and "chain is intact" in out,
                         "verdict contradicts its own trace:\n" + out)

    def test_a_real_chain_reports_what_linkage_actually_established(self):
        """Control: a good chain must still pass, and say what it proved.

        This test previously asserted "the chain is intact". That sentence was
        the F3 defect: it reads as completeness to a non-expert while the run
        only established internal linkage from genesis.
        """
        r = run(REPO / "vectors" / "valid")
        self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
        self.assertIn("CHAIN LINKAGE CHECKED for all 9 receipt(s): 8 neighbouring link(s)",
                      r.stdout)
        self.assertNotIn("the chain is intact", r.stdout)
        self.assertNotIn("CHAIN LINKAGE NOT EVALUABLE", r.stdout)

    def test_no_output_line_claims_a_bare_intact_chain(self):
        """The retired phrase must not creep back in on any path."""
        for args in ([REPO / "vectors" / "valid"],
                     [REPO / "vectors" / "valid", "--quiet"],
                     [REPO / "vectors" / "valid" / "000_sb243.json"]):
            out = run(*args).stdout
            self.assertNotIn("the chain is intact", out, f"for args {args}")


class ChainCompleteness(unittest.TestCase):
    """F3 — a truncated tail passes, and the tool must not imply otherwise.

    This is inherent: without an external anchor a missing newest receipt is
    undetectable from inside the set. The fix is claim discipline, not a new
    scheme. The two ends are NOT symmetric and the tests pin that asymmetry.
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="telos-verify-complete-"))

    def copy_chain(self, name, drop=(), rename=()):
        d = self.tmp / name
        d.mkdir()
        for f in sorted((REPO / "vectors" / "valid").glob("*.json")):
            if f.name in drop:
                continue
            target = d / (f.name + ".bak" if f.name in rename else f.name)
            target.write_text(f.read_text())
        return d

    def test_control_chain_checker_distinguishes_intact_from_broken_link(self):
        """The positive control also makes the real linkage target go red.

        The old test only required an untouched chain to exit 0; it stayed green
        with verify_chain replaced by a no-op. This paired control first checks
        the good chain, then changes the last receipt's previous-head claim and
        recomputes its own integrity hash. Individual hashes still pass, so only
        the linkage checker can reject the second run.
        """
        d = self.copy_chain("control")
        good = run(d)
        self.assertEqual(good.returncode, VERIFIED, good.stdout + good.stderr)
        self.assertIn("CHAIN LINKAGE CHECKED", good.stdout)

        last = d / "008_agentdojo.json"
        receipt = json.loads(last.read_text())
        receipt["payload"]["previous_receipt_integrity_hash"] = "sha256:" + "0" * 64
        receipt["integrity_hash"] = integrity_hash(receipt["payload"])
        last.write_text(json.dumps(receipt, indent=2))
        broken = run(d)
        self.assertEqual(broken.returncode, FAILED, broken.stdout + broken.stderr)
        self.assertIn("broken link at sequence 8", broken.stdout)

    def test_broken_link_quiet_output_is_standalone_and_not_contradictory(self):
        d = self.copy_chain("quiet_broken")
        last = d / "008_agentdojo.json"
        receipt = json.loads(last.read_text())
        receipt["payload"]["previous_receipt_integrity_hash"] = "sha256:" + "0" * 64
        receipt["integrity_hash"] = integrity_hash(receipt["payload"])
        last.write_text(json.dumps(receipt, indent=2))

        broken = run(d, "--quiet")
        self.assertEqual(broken.returncode, FAILED, broken.stdout + broken.stderr)
        self.assertIn("9 of 9 receipt(s) passed the implemented per-receipt checks", broken.stdout)
        self.assertIn("one or more required checks failed", broken.stdout)
        self.assertIn("Re-run without --quiet", broken.stdout)
        self.assertNotIn("receipt(s) verified", broken.stdout)

    def test_truncated_tail_passes_but_claims_no_completeness(self):
        d = self.copy_chain("trunc", drop={"006_agentharm.json",
                                           "007_propensitybench.json",
                                           "008_agentdojo.json"})
        r = run(d, "--quiet")
        self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
        self.assertNotIn("the chain is intact", r.stdout)
        self.assertIn("COMPLETENESS was NOT assessed", r.stdout)
        self.assertIn("Receipts newer than sequence 5 could be", r.stdout)

    def test_hidden_newest_receipt_passes_but_claims_no_completeness(self):
        d = self.copy_chain("hidden", rename={"008_agentdojo.json"})
        r = run(d, "--quiet")
        self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
        self.assertNotIn("the chain is intact", r.stdout)
        self.assertIn("Receipts newer than sequence 7 could be", r.stdout)

    def test_the_head_hash_survives_quiet_so_it_can_be_pinned(self):
        """The head is the only value an outside record can be pinned against."""
        r = run(self.copy_chain("headq"), "--quiet")
        self.assertIn("sha256:0f7a0cf9c137739aa0afa37e376e600d7bed49bdbc2e458ea874d1f9a608e3b3",
                      r.stdout)

    def test_truncation_changes_the_head_which_is_what_makes_it_detectable(self):
        """The remedy the NOTE points at must actually work."""
        full = run(self.copy_chain("h_full"), "--quiet").stdout
        cut = run(self.copy_chain("h_cut", drop={"008_agentdojo.json"}), "--quiet").stdout
        self.assertNotEqual(full, cut)
        self.assertIn("sha256:0f7a0cf9", full)
        self.assertNotIn("sha256:0f7a0cf9", cut)

    def test_ASYMMETRY_removing_genesis_still_FAILS(self):
        """The genesis end IS anchored. Rewording must not have weakened it."""
        d = self.copy_chain("nogenesis", drop={"000_sb243.json"})
        r = run(d, "--quiet")
        self.assertEqual(r.returncode, FAILED, r.stdout + r.stderr)
        self.assertNotIn("VERIFIED", r.stdout)

    def test_ASYMMETRY_removing_a_middle_receipt_still_FAILS(self):
        d = self.copy_chain("nomiddle", drop={"004_harmbench.json"})
        r = run(d, "--quiet")
        self.assertEqual(r.returncode, FAILED, r.stdout + r.stderr)


class ExpectedHeadPinning(unittest.TestCase):
    """An external head turns otherwise invisible tail truncation into failure."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="telos-verify-head-pin-"))
        self.head_file = REPO / "vectors" / "valid" / "HEAD.sha256"
        self.full_head = self.head_file.read_text().strip()

    def copy_chain(self, name, drop=()):
        d = self.tmp / name
        d.mkdir()
        for f in sorted((REPO / "vectors" / "valid").glob("*.json")):
            if f.name not in drop:
                (d / f.name).write_text(f.read_text())
        return d

    def test_published_vector_head_matches_the_full_chain(self):
        r = run(REPO / "vectors" / "valid", "--expected-head-file", self.head_file)
        self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
        self.assertIn("PAYLOAD-TO-HASH BINDING ESTABLISHED", r.stdout)
        self.assertIn("CHAIN LINKAGE CHECKED", r.stdout)
        self.assertIn("HEAD PIN CHECKED: observed chain head matches the caller-supplied", r.stdout)
        self.assertIn("HEAD PIN CHECKED: the observed chain head matches the expected", r.stdout)
        self.assertNotIn("SIGNATURE CHECKED", r.stdout)

    def test_truncated_tail_FAILS_against_the_published_head_even_under_quiet(self):
        d = self.copy_chain("truncated", drop={"008_agentdojo.json"})
        r = run(d, "--expected-head", self.full_head, "--quiet")
        self.assertEqual(r.returncode, FAILED, r.stdout + r.stderr)
        self.assertNotIn("VERIFIED", r.stdout)
        self.assertIn("expected chain head", r.stdout)
        self.assertIn(self.full_head, r.stdout)
        self.assertIn("observed chain head", r.stdout)

    def test_expected_head_is_not_silently_ignored_when_no_chain_was_established(self):
        one = REPO / "vectors" / "valid" / "000_sb243.json"
        r = run(one, "--expected-head", self.full_head)
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("expected head could not be checked", r.stdout)

    def test_malformed_expected_head_is_INCOMPLETE(self):
        r = run(REPO / "vectors" / "valid", "--expected-head", "sha256:not-a-digest")
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("expected head is malformed", r.stdout)

    def test_missing_head_file_quiet_output_points_to_visible_diagnostics(self):
        missing = self.tmp / "does-not-exist.HEAD"
        r = run(REPO / "vectors" / "valid", "--expected-head-file", missing, "--quiet")
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertIn("one or more required checks could not be completed", r.stdout)
        self.assertIn("Diagnostic detail was suppressed by --quiet", r.stdout)
        self.assertIn("Re-run without --quiet", r.stdout)
        self.assertNotIn("see above", r.stdout)
        self.assertNotIn("receipt(s) verified", r.stdout)


class UnsignedContentMessaging(unittest.TestCase):
    """Hash consistency must be impossible to mistake for content validation."""

    def setUp(self):
        # Exact external-review case: alarming content plus a matching hash. The
        # receipt is internally consistent and therefore correctly exits 0 under
        # telos/0.1-unsigned. What matters here is what the output says that means.
        self.path = (REPO / "vectors" / "fabricated" /
                     "unsigned-content-claim.json")
        receipt = json.loads(self.path.read_text())
        self.assertEqual(receipt["payload"]["action_name"], "start_thermonuclear_war")
        self.assertEqual(receipt["payload"]["verdict"], "EXECUTE")
        self.assertEqual(receipt["integrity_hash"], integrity_hash(receipt["payload"]))

    def test_fabricated_unsigned_claim_exits_zero_but_says_content_not_validated(self):
        for extra in ((), ("--quiet",)):
            with self.subTest(extra=extra):
                r = run(self.path, *extra)
                self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
                self.assertIn("UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED", r.stdout)
                self.assertIn("Anyone can fabricate an unsigned receipt", r.stdout)
                self.assertIn("does not show that the described action", r.stdout)
                self.assertIn("verdict/score is correct", r.stdout)
                # The tool now checks structure (TRS-S3-030), and must say
                # that structure is all it checked.
                self.assertIn("SCHEMA CHECKED", r.stdout)
                self.assertIn("That is structure, not", r.stdout)
                self.assertIn("does not show that a recorded action, verdict, or score is correct",
                              r.stdout)
                self.assertNotIn("VERIFIED (UNSIGNED):", r.stdout)

    def test_fabricated_vector_meets_bundled_action_schema_constraints(self):
        schema = json.loads((REPO / "docs" / "receipt-spec.schema.json").read_text())
        receipt = json.loads(self.path.read_text())

        self.assertEqual(set(receipt), set(schema["properties"]))
        self.assertTrue(set(schema["required"]).issubset(receipt))
        self.assertEqual(receipt["receipt_version"],
                         schema["properties"]["receipt_version"]["const"])
        self.assertEqual(receipt["signing_status"],
                         schema["properties"]["signing_status"]["const"])
        self.assertIsNone(receipt["signature"])
        self.assertRegex(receipt["integrity_hash"],
                         re.compile(schema["properties"]["integrity_hash"]["pattern"]))

        payload_schema = schema["then"]["properties"]["payload"]
        payload = receipt["payload"]
        self.assertEqual(set(payload), set(payload_schema["properties"]))
        self.assertTrue(set(payload_schema["required"]).issubset(payload))
        self.assertRegex(payload["action_params_hash"],
                         re.compile(payload_schema["properties"]["action_params_hash"]["pattern"]))
        self.assertIn(payload["verdict"],
                      payload_schema["properties"]["verdict"]["enum"])
        self.assertIsInstance(payload["scores"], dict)
        self.assertTrue(all(type(value) in (int, float)
                            for value in payload["scores"].values()))

    def test_action_params_hash_contract_declares_its_missing_constructor_and_privacy_limit(self):
        for schema_name in ("receipt-spec.schema.json", "receipt-spec-signed.schema.json"):
            with self.subTest(schema=schema_name):
                schema = json.loads((REPO / "docs" / schema_name).read_text())
                description = schema["then"]["properties"]["payload"]["properties"][
                    "action_params_hash"
                ]["description"]
                self.assertIn("does not define which representation", description)
                self.assertIn("telos-verify does not recompute it", description)
                self.assertIn("not a confidentiality guarantee", description)
                self.assertNotIn("without leaking content", description)
                self.assertNotIn("commitment to the exact", description)

    def test_readme_scopes_hashes_to_canonical_json_and_signature_failure_to_nonverification(self):
        readme = (REPO / "README.md").read_text()
        normalized = re.sub(r"\s+", " ", readme)
        self.assertIn("canonical JSON encoding of each parsed payload", readme)
        self.assertIn("only that canonical JSON of the supplied payload agrees", normalized)
        self.assertIn("does not by itself identify who wrote the receipt", normalized)
        self.assertNotIn("recomputes the hash from\nthe payload bytes", readme)
        self.assertNotIn("The bytes are intact and the tool says so", readme)

        unsigned_schema = json.loads(
            (REPO / "docs" / "receipt-spec.schema.json").read_text()
        )
        integrity_claim = unsigned_schema["properties"]["integrity_hash"]["description"]
        self.assertIn("equality between that canonical encoding", integrity_claim)
        self.assertIn("source whitespace and object-key order are outside", integrity_claim)

        signed_schema = json.loads(
            (REPO / "docs" / "receipt-spec-signed.schema.json").read_text()
        )
        self.assertIn("verifies under a supplied public key", signed_schema["description"])
        self.assertIn("Binding that key to an identity or controller is outside",
                      signed_schema["description"])
        self.assertNotIn("holder of a particular key signed", signed_schema["description"])

        spec_note = (REPO / "docs" / "SPEC_NOTE.md").read_text()
        self.assertIn("Who controls that key requires an external identity binding", spec_note)
        self.assertNotIn('A signature narrows "who"', spec_note)

    def test_source_whitespace_is_not_misstated_as_covered_payload_bytes(self):
        source = self.path.read_text()
        receipt = json.loads(source)
        rewritten = json.dumps(receipt, separators=(",", ":")) + "\n"
        self.assertNotEqual(source.encode(), rewritten.encode())
        path = pathlib.Path(tempfile.mkdtemp(prefix="telos-canonical-json-")) / "spaced.json"
        path.write_text(rewritten)
        result = run(path, "--quiet")
        self.assertEqual(result.returncode, VERIFIED, result.stdout + result.stderr)
        self.assertIn("matches canonical JSON of its supplied payload", result.stdout)
        self.assertNotIn("payload bytes", result.stdout)


class PublishedSchemaConsistency(unittest.TestCase):
    """The two published contracts must say exactly where their shapes differ."""

    @staticmethod
    def without_descriptions(value):
        if isinstance(value, dict):
            return {
                key: PublishedSchemaConsistency.without_descriptions(item)
                for key, item in value.items() if key != "description"
            }
        if isinstance(value, list):
            return [PublishedSchemaConsistency.without_descriptions(item) for item in value]
        return value

    def setUp(self):
        docs = REPO / "docs"
        self.unsigned = json.loads((docs / "receipt-spec.schema.json").read_text())
        self.signed = json.loads((docs / "receipt-spec-signed.schema.json").read_text())

    def test_signed_and_unsigned_structural_constraints_differ_only_in_three_fields(self):
        self.assertEqual(self.signed["required"], self.unsigned["required"])
        self.assertEqual(self.signed["if"], self.unsigned["if"])
        self.assertEqual(self.signed["then"], self.unsigned["then"])

        unsigned_props = self.without_descriptions(self.unsigned["properties"])
        signed_props = self.without_descriptions(self.signed["properties"])
        self.assertEqual(set(signed_props), set(unsigned_props))
        differences = {
            name for name in signed_props if signed_props[name] != unsigned_props[name]
        }
        self.assertEqual(differences, {"receipt_version", "signing_status", "signature"})

    def test_signed_schema_rejects_non_base64_signature_material(self):
        sig_props = self.signed["properties"]["signature"]["properties"]
        self.assertIsNone(re.fullmatch(sig_props["value"]["pattern"], "not-even-base64"))
        self.assertIsNone(re.fullmatch(sig_props["public_key"]["pattern"], "not-even-base64"))
        self.assertIsNotNone(re.fullmatch(sig_props["value"]["pattern"], "A" * 86 + "=="))
        self.assertIsNotNone(re.fullmatch(sig_props["public_key"]["pattern"], "A" * 43 + "="))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class Ed25519Path(unittest.TestCase):
    """Ephemeral keys only. Nothing here touches production key material."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="telos-verify-ed25519-")
        cls.tmp = pathlib.Path(cls._tmp.name)

        cls.priv = Ed25519PrivateKey.generate()
        cls.other = Ed25519PrivateKey.generate()

        def write_key(priv, name):
            raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            path = cls.tmp / name
            path.write_text(base64.b64encode(raw).decode("ascii") + "\n")
            return path

        cls.key = write_key(cls.priv, "trusted.pub")
        cls.wrong_key = write_key(cls.other, "someone-else.pub")

        # A two-receipt signed chain, so directory mode exercises linkage too.
        cls.chain_dir = cls.tmp / "signed_chain"
        cls.chain_dir.mkdir()
        p0 = payload_at(0, None)
        r0 = mint_signed(p0, cls.priv)
        p1 = payload_at(1, r0["integrity_hash"])
        r1 = mint_signed(p1, cls.priv)
        for i, rec in enumerate((r0, r1)):
            (cls.chain_dir / f"{i:03d}.json").write_text(json.dumps(rec, indent=2))
        cls.one = cls.chain_dir / "000.json"
        cls.receipt = r0

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def write(self, name, receipt) -> pathlib.Path:
        path = self.tmp / name
        path.write_text(json.dumps(receipt, indent=2))
        return path

    # --- negative controls first ------------------------------------------

    def test_NEGATIVE_CONTROL_tampered_signature_fails(self):
        """A flipped signature byte must be FAILED and exit 1."""
        bad = json.loads(json.dumps(self.receipt))
        raw = bytearray(base64.b64decode(bad["signature"]["value"]))
        raw[0] ^= 0x01
        bad["signature"]["value"] = base64.b64encode(bytes(raw)).decode("ascii")
        path = self.write("tampered_signature.json", bad)

        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, FAILED, p.stdout + p.stderr)
        self.assertIn("signature does not verify", p.stdout)
        self.assertIn("the receipt names a key you supplied", p.stdout)
        self.assertIn("does not verify for that key and integrity hash", p.stdout)
        self.assertNotIn("VERIFIED", p.stdout)

    def test_NEGATIVE_CONTROL_signature_from_another_key_fails(self):
        forged = mint_signed(payload_at(0, None), self.other)
        path = self.write("forged.json", forged)

        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, FAILED, p.stdout + p.stderr)
        self.assertIn("not a key you trust", p.stdout)

    def test_NEGATIVE_CONTROL_tampered_payload_under_good_signature_fails(self):
        """Editing the payload breaks the hash before the signature is reached."""
        bad = json.loads(json.dumps(self.receipt))
        bad["payload"]["current"] = "99.99%"
        path = self.write("tampered_payload.json", bad)

        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, FAILED, p.stdout + p.stderr)
        self.assertIn("payload does not match recorded hash", p.stdout)

    def test_NEGATIVE_CONTROL_probe_can_distinguish_good_from_bad(self):
        """Guard against a checker that says FAILED unconditionally."""
        good = run(self.one, "--key", self.key)
        bad = run(self.one, "--key", self.wrong_key)
        self.assertEqual(good.returncode, VERIFIED, good.stdout)
        self.assertEqual(bad.returncode, FAILED, bad.stdout)

    # --- honesty invariants ------------------------------------------------

    def test_no_key_supplied_is_incomplete_never_a_pass(self):
        p = run(self.one)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("signature NOT checked", p.stdout)
        self.assertIn("not a trust anchor", p.stdout)

    def test_embedded_key_alone_cannot_produce_a_pass(self):
        """The receipt carries its own public key; that must not be enough."""
        self.assertIn("public_key", self.receipt["signature"])
        p = run(self.one)
        self.assertNotEqual(p.returncode, VERIFIED, p.stdout)

    def test_unusable_key_file_is_incomplete_not_silently_ignored(self):
        junk = self.tmp / "not-a-key.txt"
        junk.write_text("this is not a key\n")
        p = run(self.one, "--key", junk)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("not a PEM", p.stdout)

    def test_missing_key_file_is_incomplete(self):
        p = run(self.one, "--key", self.tmp / "does-not-exist.pub")
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        # A mutation review found the exit code alone is not evidence the key load
        # was attempted -- the later no-key path returns INCOMPLETE too, so this
        # stayed green when key-load errors were swallowed. Pin the REASON.
        self.assertIn("does-not-exist.pub", p.stdout)

    def test_wrong_covers_declaration_is_refused_not_verified(self):
        odd = json.loads(json.dumps(self.receipt))
        odd["signature"]["covers"] = "the whole envelope"
        path = self.write("odd_covers.json", odd)
        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("signature covers", p.stdout)

    def test_unknown_algorithm_is_refused(self):
        odd = json.loads(json.dumps(self.receipt))
        odd["signature"]["algorithm"] = "rsa-pss"
        path = self.write("odd_alg.json", odd)
        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("signature algorithm", p.stdout)

    def test_malformed_signature_value_fails(self):
        odd = json.loads(json.dumps(self.receipt))
        odd["signature"]["value"] = "not base64!!"
        path = self.write("bad_b64.json", odd)
        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, FAILED, p.stdout + p.stderr)

    def test_signature_on_unsigned_contract_version_is_refused(self):
        odd = json.loads(json.dumps(self.receipt))
        odd["receipt_version"] = "telos/0.1-unsigned"
        odd["signing_status"] = "unsigned_integrity_hash"
        path = self.write("wrong_version.json", odd)
        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("signature NOT checked", p.stdout)

    def test_signed_status_without_signature_object_is_refused(self):
        odd = json.loads(json.dumps(self.receipt))
        odd["signature"] = None
        path = self.write("no_sig_object.json", odd)
        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)

    # --- the pass, last ----------------------------------------------------

    def test_signed_receipt_with_trusted_key_verifies(self):
        p = run(self.one, "--key", self.key)
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)
        self.assertIn("VERIFIED (SIGNED — CONTENT NOT VALIDATED): 1 receipt(s).", p.stdout)
        self.assertIn("SIGNATURE CHECKED for 1 signed receipt(s)", p.stdout)
        self.assertIn("CHAIN LINKAGE NOT EVALUABLE", p.stdout)
        self.assertNotIn("CHAIN LINKAGE CHECKED", p.stdout)
        self.assertIn("NOT covered by it", p.stdout)

    def test_signed_chain_verifies_and_reports_linkage(self):
        p = run(self.chain_dir, "--key", self.key)
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)
        self.assertIn("VERIFIED (SIGNED — CONTENT NOT VALIDATED): 2 receipt(s).", p.stdout)
        self.assertIn("CHAIN LINKAGE CHECKED for all 2 receipt(s): 1 neighbouring link(s)",
                      p.stdout)

    def test_require_signature_distinguishes_all_signed_from_one_unsigned(self):
        """Exercise both outcomes so deleting the option logic turns this red."""
        signed = run(self.chain_dir, "--key", self.key, "--require-signature")
        self.assertEqual(signed.returncode, VERIFIED, signed.stdout + signed.stderr)

        mixed = self.tmp / "require_signature_mixed"
        mixed.mkdir()
        (mixed / "000.json").write_text((self.chain_dir / "000.json").read_text())
        unsigned = json.loads((REPO / "vectors" / "sample-receipt.json").read_text())
        (mixed / "001.json").write_text(json.dumps(unsigned, indent=2))
        refused = run(mixed, "--key", self.key, "--require-signature")
        self.assertEqual(refused.returncode, INCOMPLETE, refused.stdout + refused.stderr)
        self.assertIn("--require-signature", refused.stdout)

    def test_require_signature_REFUSES_an_unsigned_receipt(self):
        """The negative half. A mutation review found the positive control above
        stayed green with every --require-signature code path deleted, so it
        was never evidence the option was consulted. This is."""
        p = run(REPO / "vectors" / "valid", "--require-signature")
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertNotIn("VERIFIED", p.stdout)
        self.assertIn("--require-signature", p.stdout)

    def test_key_accepted_as_pem(self):
        pem = self.tmp / "trusted.pem"
        pem.write_bytes(self.priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        p = run(self.one, "--key", pem)
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)

    def test_key_accepted_as_hex(self):
        raw = self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        h = self.tmp / "trusted.hex"
        h.write_text(raw.hex() + "\n")
        p = run(self.one, "--key", h)
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)

    def test_pem_holding_a_non_ed25519_key_is_refused(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        pem = self.tmp / "rsa.pem"
        pem.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048)
                        .public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        p = run(self.one, "--key", pem)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("not an Ed25519 public key", p.stdout)

    def test_multiple_keys_one_of_which_matches(self):
        p = run(self.one, "--key", self.wrong_key, "--key", self.key)
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)

    # --- F1 on the signed path: the case that would have shipped ------------

    def test_NEGATIVE_CONTROL_duplicate_payload_cannot_win_a_SIGNED_pass(self):
        """The reported bypass, exactly: genuine signature, two payloads.

        The signature is real and verifies under the trusted key — over the
        SECOND payload. The first is what an auditor opening the file reads.
        Before the fix this printed VERIFIED (SIGNED) with exit 0.
        """
        members = list(self.receipt.items())
        i = [k for k, _ in members].index("payload")
        evil = {"claim": "MALICIOUS PAYLOAD", "result": "pass"}
        spliced = members[:i] + [("payload", evil)] + members[i:]
        text = render_with_members(spliced)
        path = self.tmp / "signed_dup_payload.json"
        path.write_text(text)

        # Probe integrity: valid JSON, two payloads, and the parser keeps the
        # signed one — so without the fix this file WOULD have verified.
        parsed = json.loads(text)
        self.assertEqual(text.count('"payload"'), 2)
        self.assertEqual(parsed["payload"], self.receipt["payload"])
        self.assertEqual(text.index('"MALICIOUS PAYLOAD"'),
                         min(text.index('"MALICIOUS PAYLOAD"'), text.index('"EPHEMERAL_TEST_0"')),
                         "the malicious payload must come first in the file")

        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("duplicate key 'payload'", p.stdout)
        self.assertNotIn("VERIFIED (SIGNED)", p.stdout)

    def test_probe_control_the_same_receipt_without_the_duplicate_verifies(self):
        """Proves the refusal above is the duplicate, not a broken parser."""
        path = self.tmp / "signed_no_dup.json"
        path.write_text(render_with_members(list(self.receipt.items())))
        p = run(path, "--key", self.key)
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)
        self.assertIn("VERIFIED (SIGNED — CONTENT NOT VALIDATED)", p.stdout)

    # --- the dependency claim, tested rather than asserted ------------------

    def test_without_cryptography_a_signed_receipt_is_INCOMPLETE_never_a_pass(self):
        env = crypto_blocked_env(self.tmp)
        p = run(self.one, "--key", self.key, env=env)
        self.assertEqual(p.returncode, INCOMPLETE, p.stdout + p.stderr)
        self.assertIn("`cryptography` package is not installed", p.stdout)
        self.assertIn("signature NOT checked", p.stdout)
        self.assertNotIn("VERIFIED (SIGNED)", p.stdout)

    def test_without_cryptography_the_unsigned_path_still_works(self):
        """The zero-dependency promise applies to the whole unsigned contract."""
        env = crypto_blocked_env(self.tmp)
        p = run(REPO / "vectors" / "valid", env=env)
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)
        self.assertIn("PAYLOAD-TO-HASH BINDING ESTABLISHED for 9 receipt(s)", p.stdout)

    def test_mixed_signed_and_unsigned_directory_is_reported_as_mixed(self):
        mixed = self.tmp / "mixed"
        mixed.mkdir()
        (mixed / "000.json").write_text((self.chain_dir / "000.json").read_text())
        unsigned = json.loads((REPO / "vectors" / "sample-receipt.json").read_text())
        (mixed / "001.json").write_text(json.dumps(unsigned, indent=2))
        p = run(mixed, "--key", self.key)
        self.assertIn("VERIFIED (MIXED AUTHENTICATION — CONTENT NOT VALIDATED)", p.stdout)
        self.assertEqual(p.returncode, VERIFIED, p.stdout + p.stderr)


# ---------------------------------------------------------------------------
# Independent review findings, 2026-08-31.
# Every test below was written against a REPRODUCED defect: each one was seen
# red on the unmodified tool before the fix existed, and each is mutation-tested:
# it goes red when the specific mechanism it names is broken.
# ---------------------------------------------------------------------------

def mint_unsigned(payload: dict) -> dict:
    """A telos/0.1-unsigned receipt over `payload`, correctly hashed."""
    return {
        "agent_id": "TELOS-Labs-AI/ephemeral-test",
        "covered_fields": COVERED,
        "engine": "ephemeral test fixture (no governance engine wired)",
        "integrity_hash": integrity_hash(payload),
        "issued_at": "2026-08-31T00:00:00.000000Z",
        "kind": "benchmark_reverification_projection",
        "payload": payload,
        "receipt_version": "telos/0.1-unsigned",
        "signature": None,
        "signing_status": "unsigned_integrity_hash",
    }


class Round3_H1_LinkageRequiresANeighbour(unittest.TestCase):
    """Round 3 HIGH — one participant cannot prove a linkage property.

    One sequenced receipt has zero neighbouring edges. Adding an unsequenced
    bystander must not promote it from NOT EVALUABLE to CHAIN LINKAGE CHECKED.
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="telos-verify-f1-"))
        gen = payload_at(0, None)
        (self.tmp / "0.json").write_text(json.dumps(mint_unsigned(gen), indent=2))
        loose = {"benchmark": "NO_SEQUENCE_FIELD", "disposition": "REPRODUCES"}
        (self.tmp / "1.json").write_text(json.dumps(mint_unsigned(loose), indent=2))

    def test_one_sequenced_receipt_plus_bystander_never_claims_linkage(self):
        for extra in ((), ("--quiet",)):
            with self.subTest(extra=extra):
                r = run(self.tmp, *extra)
                self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
                self.assertIn("PAYLOAD-TO-HASH BINDING ESTABLISHED for 2 receipt(s)",
                              r.stdout)
                self.assertIn("CHAIN LINKAGE NOT EVALUABLE from this set", r.stdout)
                self.assertIn("at least two sequenced receipts", r.stdout)
                self.assertNotIn("CHAIN LINKAGE CHECKED", r.stdout)
                self.assertNotIn("link cleanly", r.stdout)
                self.assertNotIn("chain of 1", r.stdout)

    def test_unsequenced_bystander_does_not_change_the_linkage_disposition(self):
        one = run(self.tmp / "0.json", "--quiet")
        with_bystander = run(self.tmp, "--quiet")
        self.assertEqual(one.returncode, VERIFIED, one.stdout + one.stderr)
        self.assertEqual(with_bystander.returncode, VERIFIED,
                         with_bystander.stdout + with_bystander.stderr)
        self.assertIn("CHAIN LINKAGE NOT EVALUABLE", one.stdout)
        self.assertIn("CHAIN LINKAGE NOT EVALUABLE", with_bystander.stdout)
        self.assertNotIn("CHAIN LINKAGE CHECKED", one.stdout + with_bystander.stdout)

    def test_a_fully_sequenced_set_still_makes_the_plain_claim(self):
        """Control: the narrowing must not fire when nothing was excluded."""
        d = self.tmp / "allseq"
        d.mkdir()
        prev = None
        for i in range(3):
            p = payload_at(i, prev)
            rec = mint_unsigned(p)
            (d / f"{i}.json").write_text(json.dumps(rec, indent=2))
            prev = rec["integrity_hash"]
        r = run(d, "--quiet")
        self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
        self.assertIn("CHAIN LINKAGE CHECKED for all 3 receipt(s): 2 neighbouring link(s)",
                      r.stdout)
        self.assertNotIn("CHAIN LINKAGE NOT EVALUABLE", r.stdout)


class Tier2_F2_SequenceTypeIsValidated(unittest.TestCase):
    """F2 MED — `sequence` had no type validation, wrong in both directions."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="telos-verify-f2-"))

    def chain_with_sequences(self, name, seqs):
        d = self.tmp / name
        d.mkdir()
        prev = None
        for i, seq in enumerate(seqs):
            p = payload_at(0, prev)
            p["sequence"] = seq
            rec = mint_unsigned(p)
            (d / f"{i}.json").write_text(json.dumps(rec, indent=2))
            prev = rec["integrity_hash"]
        return d

    def test_boolean_sequence_cannot_report_a_clean_chain(self):
        """bool subclasses int, so False/True compared equal to 0/1 and the
        tool reported a clean, contiguous chain over wrong-schema values."""
        r = run(self.chain_with_sequences("bools", [False, True]), "--quiet")
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)
        self.assertNotIn("VERIFIED", r.stdout)
        self.assertNotIn("CHAIN LINKAGE CHECKED", r.stdout)

    def test_string_sequence_is_INCOMPLETE_not_a_crash_and_not_FAILED(self):
        """This aborted with an uncaught TypeError and process exit 1 --
        reporting input the tool CANNOT evaluate as a proven failure, which
        inverts the tri-state."""
        r = run(self.chain_with_sequences("strs", [0, "1"]), "--quiet")
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(r.stderr, "")
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)

    def test_the_reason_names_the_offending_type(self):
        r = run(self.chain_with_sequences("named", [0, "1"]))
        self.assertIn("not an integer", r.stdout)

    def test_CONTROL_integer_sequences_still_link(self):
        """The guard must not refuse well-formed chains."""
        r = run(self.chain_with_sequences("ints", [0, 1]), "--quiet")
        self.assertEqual(r.returncode, VERIFIED, r.stdout + r.stderr)
        self.assertIn("CHAIN LINKAGE CHECKED", r.stdout)


class Tier2_F3_FailedOutranksIncomplete(unittest.TestCase):
    """F3 LOW — the priority worked but nothing tested it.

    A review mutated `Result.incomplete` to always overwrite FAILED and the whole
    suite stayed green. A proven break must never be downgraded to an unknown,
    in either file order.
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="telos-verify-f3-"))

    def mixed_dir(self, name, fail_first: bool):
        d = self.tmp / name
        d.mkdir()
        bad = mint_unsigned(payload_at(0, None))
        bad["integrity_hash"] = "sha256:" + "0" * 64          # proven break -> FAILED
        good = mint_unsigned(payload_at(1, None))
        dup = json.dumps(good, indent=2)
        i = dup.index('"payload"')
        dup = dup[:i] + '"payload": {"shadow": 1},\n  ' + dup[i:]  # unevaluable -> INCOMPLETE
        fail_name, inc_name = ("0_f.json", "1_i.json") if fail_first else ("1_f.json", "0_i.json")
        (d / fail_name).write_text(json.dumps(bad, indent=2))
        (d / inc_name).write_text(dup)
        return d

    def test_FAILED_outranks_INCOMPLETE_failed_first(self):
        r = run(self.mixed_dir("ff", True), "--quiet")
        self.assertEqual(r.returncode, FAILED, r.stdout + r.stderr)

    def test_FAILED_outranks_INCOMPLETE_incomplete_first(self):
        """Order must not decide the verdict."""
        r = run(self.mixed_dir("if", False), "--quiet")
        self.assertEqual(r.returncode, FAILED, r.stdout + r.stderr)

    def test_CONTROL_incomplete_alone_is_still_INCOMPLETE(self):
        """Without this, a tool that always returned FAILED would pass above."""
        d = self.tmp / "inconly"
        d.mkdir()
        good = mint_unsigned(payload_at(0, None))
        dup = json.dumps(good, indent=2)
        i = dup.index('"payload"')
        (d / "a.json").write_text(dup[:i] + '"payload": {"shadow": 1},\n  ' + dup[i:])
        r = run(d, "--quiet")
        self.assertEqual(r.returncode, INCOMPLETE, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
