#!/usr/bin/env python3
"""Conformance tests: TELOS Receipt Standard v0.1, section 3.

Each check id of S3 section 3.6 gets a test that drives the real CLI with an
input violating exactly that rule, BESIDE a valid input that must pass in the
same test. Every keypair is generated fresh inside the test; none is written
outside a temporary directory, and no real key is read.

Run:  python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = pathlib.Path(__file__).resolve().parent.parent
TOOL = REPO / "telos_verify.py"
VERIFIED, FAILED, INCOMPLETE = 0, 1, 2

COVERED = "payload (canonical JSON, sort_keys, compact separators)"
SIG_COVERS = "integrity_hash (ASCII bytes of the sha256: string)"
CERT_COVERS = "certificate_hash (ASCII bytes of the sha256: string)"
ENTRY_COVERS = "this_hash (ASCII bytes of the sha256: string)"
T0, T1 = "2026-09-30T12:00:00Z", "2026-10-01T12:00:00Z"
# The primary check id is the tag placed immediately
# after the keyword, separated by exactly one space.
TAG_LINE = re.compile(r"^(FAIL|INCOMPLETE) \[(TV-[A-Z0-9]+-[0-9]{3})\]( .*)?$")
# Output-contract ids are reported on NOTE lines, not as a diagnostic.
CONTRACT_IDS = {"TV-OUT-001"}

# The live ids of S3 section 3.6. All are implemented.
S36_IDS = {
    "TV-OFFLINE-001", "TV-PARSE-001", "TV-PARSE-002", "TV-VER-001",
    "TV-HASH-001", "TV-HASH-002", "TV-HASH-003", "TV-HASH-004", "TV-HASH-005",
    "TV-CANON-001", "TV-CANON-002",
    "TV-SIG-001", "TV-SIG-002", "TV-SIG-003", "TV-SIG-004", "TV-SIG-005",
    "TV-SIG-006", "TV-SIG-007", "TV-SIG-008", "TV-SIG-009",
    "TV-CHAIN-001", "TV-CHAIN-002", "TV-CHAIN-003", "TV-CHAIN-004", "TV-CHAIN-005",
    "TV-CHAIN-006", "TV-HEAD-001",
    "TV-TRUST-001", "TV-TRUST-002", "TV-TRUST-003", "TV-TRUST-004",
    "TV-ANCHOR-001", "TV-ANCHOR-002", "TV-ANCHOR-003",
    "TV-REGISTRY-001", "TV-REGISTRY-002", "TV-REGISTRY-003",
    "TV-EXIT-001", "TV-OUT-001", "TV-SCHEMA-001",
    "TV-S2-002", "TV-S2-003", "TV-S2-004", "TV-S2-005", "TV-S2-006",
}


# ------------------------------------------------------------------ builders

def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def h(obj) -> str:
    return "sha256:" + hashlib.sha256(canon(obj)).hexdigest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


class Key:
    def __init__(self):
        self.sk = Ed25519PrivateKey.generate()
        self.raw = self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pub = b64(self.raw)
        self.kid = "sha256:" + hashlib.sha256(self.raw).hexdigest()

    def sign(self, msg: bytes) -> str:
        return b64(self.sk.sign(msg))


def ag_payload(**over):
    p = {"action_name": "read_file",
         "action_params_hash": "sha256:" + hashlib.sha256(b"params").hexdigest(),
         "verdict": "EXECUTE", "composite_score": 0.5,
         "scores": {"dim_a": 0.5}, "pa_id": "pa-test"}
    p.update(over)
    return p


def unsigned(payload=None, **env):
    payload = ag_payload() if payload is None else payload
    r = {"receipt_version": "telos/0.1-unsigned", "kind": "action_governed",
         "agent_id": "test-agent", "payload": payload, "issued_at": T0,
         "integrity_hash": h(payload), "covered_fields": COVERED,
         "signing_status": "unsigned_integrity_hash", "signature": None,
         "engine": "test engine"}
    r.update(env)
    return r


def signed(key: Key, payload=None, *, with_kid=True, sign_key: Key | None = None, **env):
    r = unsigned(payload, **env)
    r["receipt_version"] = "telos/0.2-ed25519"
    r["signing_status"] = "ed25519_signed"
    sig = {"algorithm": "ed25519", "covers": SIG_COVERS, "public_key": key.pub,
           "value": (sign_key or key).sign(r["integrity_hash"].encode("ascii"))}
    if with_kid:
        sig["key_id"] = key.kid
    r["signature"] = sig
    return r


def chain(key: Key | None, n=3, **kw):
    out, prev = [], None
    for i in range(n):
        p = ag_payload(sequence=i, previous_receipt_integrity_hash=prev, action_name=f"step{i}")
        r = signed(key, p, **kw) if key else unsigned(p)
        out.append(r)
        prev = r["integrity_hash"]
    return out


# TRS-S4-023: the first projection entry's parent_hash is the head of the
# issuer's existing key-lineage record, never null. A test head stands in.
LINEAGE_HEAD = "sha256:" + hashlib.sha256(b"test key-lineage record head").hexdigest()


def cert_hash(c):
    return h({k: v for k, v in c.items() if k != "root_signature"})


def certificate(child: Key, root: Key, *, signer: Key | None = None, **over):
    c = {"cert_version": "trs-cert/0.1", "algorithm": "ed25519",
         "child_public_key": child.pub, "child_key_id": child.kid,
         "key_role": "deployment", "scope_id": "scope:test", "purpose": "receipt_signing",
         "valid_from": T0, "valid_until": None, "root_key_id": root.kid}
    c.update(over)
    c["root_signature"] = {"algorithm": "ed25519", "covers": CERT_COVERS,
                           "value": (signer or root).sign(cert_hash(c).encode("ascii"))}
    return c


def entry(seq, parent, cert, root: Key, event="child_key_issue", *, signer: Key | None = None,
          extra=None, **over):
    e = {"entry_version": "trs-lineage-projection/0.1", "sequence": seq, "event_type": event,
         "timestamp": T0, "effective_at": T0, "parent_hash": parent,
         "root_key_id": root.kid, "child_key_id": cert["child_key_id"],
         "key_role": cert["key_role"], "scope_id": cert["scope_id"],
         "valid_from": cert["valid_from"], "valid_until": cert["valid_until"],
         "certificate_hash": cert_hash(cert), "successor_key_id": None,
         "reason_digest": None, "withheld_digest": None}
    e.update(over)
    if extra:
        e.update(extra)
    e["this_hash"] = h(e)
    e["root_signature"] = {"algorithm": "ed25519", "covers": ENTRY_COVERS,
                           "value": (signer or root).sign(e["this_hash"].encode("ascii"))}
    return e


def bundle(root: Key, rcpts, certs, registry, expected_head=None):
    b = {"bundle_version": "trs-test-bundle/0.1", "trusted_root_public_key": root.pub,
         "certificates": certs, "registry": registry, "chain": rcpts}
    if expected_head:
        b["expected_head"] = expected_head
    return b


def anchored_world():
    root, dep = Key(), Key()
    c = certificate(dep, root)
    return root, dep, c, chain(dep), [c], [entry(0, LINEAGE_HEAD, c, root)]


# ------------------------------------------------------------------ harness

class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._td.name)
        self.n = 0

    def tearDown(self):
        self._td.cleanup()

    def put(self, obj=None, *, raw=None, name=None, suffix=".json"):
        self.n += 1
        p = self.tmp / (name or f"in{self.n}{suffix}")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(raw if raw is not None else json.dumps(obj, indent=1))
        return p

    def keyfile(self, key: Key):
        return self.put(raw=key.pub + "\n", suffix=".pub.b64")

    def jsonl(self, receipts, *, lines=None):
        text = lines if lines is not None else "".join(json.dumps(r) + "\n" for r in receipts)
        return self.put(raw=text, suffix=".jsonl")

    def run_tool(self, *args):
        p = subprocess.run([sys.executable, str(TOOL), *map(str, args)],
                           capture_output=True, text=True, timeout=60, check=False)
        return p.returncode, p.stdout + p.stderr

    def good(self, *args):
        rc, out = self.run_tool(*args)
        self.assertEqual(rc, VERIFIED, out)
        return out

    def bad(self, args, rc_expected, check, text):
        rc, out = self.run_tool(*args)
        self.assertEqual(rc, rc_expected, out)
        self.assertIn(f"[{check}]", out)
        self.assertIn(text, out)
        # Diagnostic lines start "FAIL " or "INCOMPLETE "; the verdict lines
        # "FAILED:" and "INCOMPLETE:" are not diagnostics.
        tagged = [l for l in out.splitlines() if re.match(r"^(FAIL|INCOMPLETE)\s", l)]
        self.assertTrue(tagged, out)
        for line in tagged:
            self.assertRegex(line, TAG_LINE, "FAIL/INCOMPLETE line outside the primary-tag grammar")
        if check not in CONTRACT_IDS:
            # Credit only a line whose PRIMARY tag is the check, with the text.
            primary = [l for l in tagged
                       if (m := TAG_LINE.match(l)) and m.group(2) == check and text in l]
            self.assertTrue(primary, f"no line with primary [{check}] and {text!r}:\n{out}")
        return out


# ------------------------------------------------------------------ interface

class ListChecks(Base):
    def test_list_checks_declares_every_s36_id(self):
        rc, out = self.run_tool("--list-checks")
        self.assertEqual(rc, 0, out)
        ids = {m.group(1) for l in out.splitlines() if (m := re.match(r"^CHECK\s+(\S+)", l))}
        self.assertTrue(S36_IDS <= ids, sorted(S36_IDS - ids))
        for i in ids:
            self.assertRegex(i, r"^TV-[A-Z0-9]+-\d{3}$")

    def test_out_001_trailer_and_tags(self):
        self.good(self.put(unsigned()))
        r = unsigned(); r["payload"]["action_name"] = "tampered"
        out = self.bad([self.put(r)], FAILED, "TV-HASH-004", "payload does not match recorded hash")
        self.assertIn("[TV-OUT-001]", out)

    def test_exit_001_failed_outranks_incomplete_is_tagged(self):
        d = self.tmp / "mix"; d.mkdir()
        (d / "a.json").write_text(json.dumps(unsigned()))
        self.good(d)
        r = unsigned(); r["payload"]["action_name"] = "x"
        (d / "b.json").write_text(json.dumps(r))
        (d / "c.json").write_text(json.dumps(unsigned(receipt_version="telos/9.9")))
        out = self.bad([d], FAILED, "TV-EXIT-001", "FAILED outranks INCOMPLETE")
        self.assertIn("FAILED:", out)

    def test_schema_note_no_longer_claims_non_validation(self):
        out = self.good(self.put(unsigned()))
        self.assertNotIn("RECEIPT SCHEMA NOT VALIDATED", out)
        self.assertIn("SCHEMA CHECKED", out)


# ------------------------------------------------------------------ section 1 / hash

class HashAndCanon(Base):
    def test_hash_002_uppercase_digest(self):
        self.good(self.put(unsigned()))
        r = unsigned(); r["integrity_hash"] = r["integrity_hash"].upper().replace("SHA256:", "sha256:")
        self.bad([self.put(r)], FAILED, "TV-HASH-002", "malformed integrity_hash")

    def test_canon_001_float_out_of_range(self):
        self.good(self.put(unsigned(ag_payload(composite_score=0.0001))))
        p = ag_payload(composite_score=1e16)
        self.bad([self.put(unsigned(p))], FAILED, "TV-CANON-001",
                 "number outside the canonical number domain")

    def test_canon_001_integer_beyond_2_53(self):
        self.good(self.put(unsigned(ag_payload(scores={"d": 2**53 - 1}))))
        p = ag_payload(scores={"d": 2**53})
        self.bad([self.put(unsigned(p))], FAILED, "TV-CANON-001",
                 "number outside the canonical number domain")

    def test_canon_001_negative_zero(self):
        self.good(self.put(unsigned(ag_payload(composite_score=0.0))))
        p = ag_payload(composite_score=-0.0)
        self.bad([self.put(unsigned(p))], FAILED, "TV-CANON-001",
                 "number outside the canonical number domain")

    def test_canon_002_unpaired_surrogate(self):
        self.good(self.put(unsigned(ag_payload(action_name="café \U0001F600"))))
        p = ag_payload(action_name="x\ud800y")
        raw = json.dumps(unsigned(p), ensure_ascii=True)
        self.bad([self.put(raw=raw)], FAILED, "TV-CANON-002", "unpaired surrogate")

    def test_hash_005_nan_still_incomplete(self):
        self.good(self.put(unsigned()))
        raw = json.dumps(unsigned()).replace('"composite_score": 0.5', '"composite_score": NaN')
        self.bad([self.put(raw=raw)], INCOMPLETE, "TV-HASH-005", "no canonical JSON form")


# ------------------------------------------------------------------ signatures

class Signatures(Base):
    def setUp(self):
        super().setUp()
        self.k = Key()
        self.kf = self.keyfile(self.k)

    def test_sig_005_non_canonical_base64(self):
        r = signed(self.k)
        self.good(self.put(r), "--key", self.kf)
        v = r["signature"]["value"]
        alt = {"A": "B", "Q": "R", "g": "h", "w": "x"}[v[-3]]
        r["signature"]["value"] = v[:-3] + alt + "=="
        self.bad([self.put(r), "--key", self.kf], FAILED, "TV-SIG-005",
                 "an Ed25519 signature is 64")

    def test_sig_006_embedded_key_not_trusted(self):
        self.good(self.put(signed(self.k)), "--key", self.kf)
        other = Key()
        self.bad([self.put(signed(other)), "--key", self.kf], FAILED, "TV-SIG-006",
                 "does not verify under any key you supplied")

    def test_sig_007_flipped_signature(self):
        r = signed(self.k)
        self.good(self.put(r), "--key", self.kf)
        raw = bytearray(base64.b64decode(r["signature"]["value"])); raw[0] ^= 1
        r["signature"]["value"] = b64(bytes(raw))
        self.bad([self.put(r), "--key", self.kf], FAILED, "TV-SIG-007",
                 "does not verify under any key you supplied")

    def test_sig_009_key_id_names_other_key(self):
        self.good(self.put(signed(self.k)), "--key", self.kf)
        r = signed(self.k); r["signature"]["key_id"] = Key().kid
        self.bad([self.put(r), "--key", self.kf], FAILED, "TV-SIG-009",
                 "key_id does not name the verifying key")

    def test_offline_001_no_trusted_key(self):
        self.good(self.put(signed(self.k)), "--key", self.kf)
        self.bad([self.put(signed(self.k))], INCOMPLETE, "TV-OFFLINE-001",
                 "supplied no trusted public key")

    def test_sig_008_require_signature(self):
        self.good(self.put(signed(self.k)), "--key", self.kf, "--require-signature")
        self.bad([self.put(unsigned()), "--require-signature"], INCOMPLETE, "TV-SIG-008",
                 "--require-signature was given")


# ------------------------------------------------------------------ schema (S1) and S2

class Schema(Base):
    def schema_bad(self, r):
        self.good(self.put(unsigned()))
        return self.bad([self.put(r)], FAILED, "TV-SCHEMA-001",
                        "does not conform to the receipt schema")

    def test_missing_member(self):
        r = unsigned(); del r["engine"]; self.schema_bad(r)

    def test_extra_member(self):
        r = unsigned(); r["note"] = "x"; self.schema_bad(r)

    def test_label_not_string(self):
        self.schema_bad(unsigned(agent_id=7))

    def test_issued_at_not_rfc3339(self):
        self.schema_bad(unsigned(issued_at="2026-09-30 12:00"))

    def test_payload_not_object(self):
        r = unsigned(); r["payload"] = [1]; r["integrity_hash"] = h([1]); self.schema_bad(r)

    def test_action_governed_member_missing(self):
        p = ag_payload(); del p["pa_id"]; self.schema_bad(unsigned(p))

    def test_action_governed_extra_member(self):
        self.schema_bad(unsigned(ag_payload(extra="x")))

    def test_action_params_hash_malformed(self):
        self.schema_bad(unsigned(ag_payload(action_params_hash="md5:1")))

    def test_signature_extra_member(self):
        k = Key(); kf = self.keyfile(k)
        self.good(self.put(signed(k)), "--key", kf)
        r = signed(k); r["signature"]["note"] = "x"
        self.bad([self.put(r), "--key", kf], FAILED, "TV-SCHEMA-001",
                 "does not conform to the receipt schema")

    def test_other_kind_payload_unconstrained(self):
        self.good(self.put(unsigned({"anything": [1, "x"]}, kind="other_kind")))

    def s2_bad(self, payload, check, text):
        self.good(self.put(unsigned()))
        self.bad([self.put(unsigned(payload))], FAILED, check, text)

    def test_s2_002_verdict(self):
        self.s2_bad(ag_payload(verdict="ALLOW"), "TV-S2-002", "verdict is not in the public vocabulary")

    def test_s2_003_composite_not_number(self):
        self.s2_bad(ag_payload(composite_score="0.5"), "TV-S2-003", "composite_score is not a number")

    def test_s2_003_composite_bool(self):
        self.s2_bad(ag_payload(composite_score=True), "TV-S2-003", "composite_score is not a number")

    def test_s2_004_scores_value(self):
        self.s2_bad(ag_payload(scores={"d": "high"}), "TV-S2-004", "scores value is not a number")

    def test_s2_005_scores_empty_label(self):
        self.s2_bad(ag_payload(scores={"": 0.5}), "TV-S2-005", "scores label is empty")

    def test_s2_006_pa_id_empty(self):
        self.s2_bad(ag_payload(pa_id=""), "TV-S2-006", "pa_id is empty")


# ------------------------------------------------------------------ chains (S4)

class Chains(Base):
    def test_jsonl_chain_file_valid(self):
        self.good(self.jsonl(chain(None)))

    def test_chain_004_member_without_partner(self):
        self.good(self.jsonl(chain(None)))
        c = chain(None)
        del c[0]["payload"]["previous_receipt_integrity_hash"]
        c[0]["integrity_hash"] = h(c[0]["payload"])
        c[1]["payload"]["previous_receipt_integrity_hash"] = c[0]["integrity_hash"]
        c[1]["integrity_hash"] = h(c[1]["payload"])
        c[2]["payload"]["previous_receipt_integrity_hash"] = c[1]["integrity_hash"]
        c[2]["integrity_hash"] = h(c[2]["payload"])
        self.bad([self.jsonl(c)], FAILED, "TV-CHAIN-004", "chain member without its partner")

    def test_chain_005_duplicate_sequence(self):
        self.good(self.jsonl(chain(None)))
        c = chain(None)
        self.bad([self.jsonl([c[0], c[1], c[1], c[2]])], FAILED, "TV-CHAIN-005",
                 "duplicate sequence")

    def test_chain_006_reordered_file(self):
        self.good(self.jsonl(chain(None)))
        c = chain(None)
        self.bad([self.jsonl([c[0], c[2], c[1]])], FAILED, "TV-CHAIN-006",
                 "chain file is not in sequence order")

    def test_chain_006_blank_line(self):
        self.good(self.jsonl(chain(None)))
        c = chain(None)
        text = json.dumps(c[0]) + "\n\n" + "".join(json.dumps(r) + "\n" for r in c[1:])
        self.bad([self.jsonl(None, lines=text)], FAILED, "TV-CHAIN-006", "chain file")

    def test_chain_003_genesis_predecessor_not_null(self):
        self.good(self.jsonl(chain(None)))
        c = chain(None)
        c[0]["payload"]["previous_receipt_integrity_hash"] = "sha256:" + "1" * 64
        c[0]["integrity_hash"] = h(c[0]["payload"])
        self.bad([self.jsonl(c)], FAILED, "TV-CHAIN-003", "broken link at sequence 0")

    def test_chain_break_fails_even_when_signature_unchecked(self):
        # Linkage needs only the payload-to-hash binding. Without a key the
        # signatures stay INCOMPLETE, but a proven break is FAILED (FAILED
        # outranks INCOMPLETE), and an intact chain stays INCOMPLETE, not 0.
        k = Key()
        c = chain(k)
        self.good(self.jsonl(c), "--key", self.keyfile(k))
        self.bad([self.jsonl(c)], INCOMPLETE, "TV-OFFLINE-001", "no trusted public key")
        broken = chain(k)
        p = broken[2]["payload"]
        p["previous_receipt_integrity_hash"] = "sha256:" + "2" * 64
        broken[2] = signed(k, p)
        self.bad([self.jsonl(broken)], FAILED, "TV-CHAIN-003", "broken link at sequence 2")

    def test_head_only_bundle_is_a_chain(self):
        # A test bundle with no certificates and an empty projection carries
        # no trust material; its chain and expected_head are still checked.
        k, root = Key(), Key()
        c = chain(k)
        self.good(self.put(bundle(root, c, [], [], c[-1]["integrity_hash"]),
                           suffix=".bundle.json"), "--key", self.keyfile(k))
        self.bad([self.put(bundle(root, c[:2], [], [], c[-1]["integrity_hash"]),
                           suffix=".bundle.json")],
                 FAILED, "TV-HEAD-001", "chain head does not match")


# ------------------------------------------------------------------ anchored mode (S4, S3 3.4)

class Anchored(Base):
    def run_bundle(self, b, *extra):
        return self.put(b, suffix=".bundle.json"), extra

    def check_bad(self, b, rc, check, text):
        root, _dep, _c, ch, certs, reg = anchored_world()
        self.good(self.put(bundle(root, ch, certs, reg), suffix=".bundle.json"))
        return self.bad([self.put(b, suffix=".bundle.json")], rc, check, text)

    def test_valid_bundle_and_warning(self):
        root, _dep, _c, ch, certs, reg = anchored_world()
        out = self.good(self.put(bundle(root, ch, certs, reg), suffix=".bundle.json"))
        self.assertIn("SELF-ROOTED", out)
        self.assertIn("TEST BUNDLE", out)

    def test_s3_036_self_rooted_bundle_never_reported_anchored(self):
        # TRS-S3-036: a root the bundle asserts for itself never yields a
        # certified pass. Control first: the same bundle with the caller's
        # --root-key IS anchored and carries no TEST BUNDLE warning.
        root, _dep, _c, ch, certs, reg = anchored_world()
        p = self.put(bundle(root, ch, certs, reg), suffix=".bundle.json")
        ctl = self.good(p, "--root-key", self.keyfile(root))
        self.assertRegex(ctl, r"(?<!NOT )\bANCHORED\b")
        self.assertNotIn("TEST BUNDLE", ctl)
        out = self.good(p)
        self.assertIn("TEST BUNDLE", out)
        self.assertIn("SELF-ROOTED", out)
        self.assertNotRegex(out, r"(?<!NOT )\bANCHORED\b",
                            "self-rooted bundle reported as anchored")
        self.assertNotRegex(out, r"(?i)\bcertified\b",
                            "self-rooted bundle reported as certified")

    def trust_dir(self, certs, reg, name="trust", *, projection=None):
        # S3 3.2 layout: one trs-cert/0.1 object per *.cert.json file, and the
        # projection as projection.jsonl, one entry per line in sequence order.
        d = self.tmp / name; d.mkdir()
        for i, c in enumerate(certs):
            (d / f"dep{i}.cert.json").write_text(json.dumps(c))
        (d / "projection.jsonl").write_text(
            projection if projection is not None else "".join(json.dumps(e) + "\n" for e in reg))
        return d

    def test_trust_dir_layout_s3_3_2(self):
        root, _dep, _c, ch, certs, reg = anchored_world()
        rf = self.keyfile(root)
        self.good(self.jsonl(ch), "--root-key", rf, "--trust-dir", self.trust_dir(certs, reg))
        # The older layout (certificates.json + projection.json) is not S3 3.2.
        old = self.tmp / "old"; old.mkdir()
        (old / "certificates.json").write_text(json.dumps(certs))
        (old / "projection.json").write_text(json.dumps(reg))
        self.bad([self.jsonl(ch), "--root-key", rf, "--trust-dir", old], INCOMPLETE,
                 "TV-LOAD-002", "projection.jsonl")
        # A projection with a blank line is refused whole, never skipped.
        text = "\n" + "".join(json.dumps(e) + "\n" for e in reg)
        self.bad([self.jsonl(ch), "--root-key", rf, "--trust-dir",
                  self.trust_dir(certs, reg, "blank", projection=text)], INCOMPLETE,
                 "TV-LOAD-002", "blank line")
        # A *.cert.json file holds one certificate object, not a list.
        lst = self.trust_dir([], reg, "list")
        (lst / "all.cert.json").write_text(json.dumps(certs))
        self.bad([self.jsonl(ch), "--root-key", rf, "--trust-dir", lst], INCOMPLETE,
                 "TV-LOAD-002", "one trs-cert/0.1 object")

    def test_trust_dir_mode(self):
        root, _dep, _c, ch, certs, reg = anchored_world()
        d = self.trust_dir(certs, reg)
        rf = self.keyfile(root)
        self.good(self.jsonl(ch), "--root-key", rf, "--trust-dir", d)
        other = self.keyfile(Key())
        self.bad([self.jsonl(ch), "--root-key", other, "--trust-dir", d], FAILED,
                 "TV-REGISTRY-002", "registry entry does not verify under the root key")

    def test_root_key_overrides_bundle_root(self):
        root, _dep, _c, ch, certs, reg = anchored_world()
        p = self.put(bundle(root, ch, certs, reg), suffix=".bundle.json")
        self.good(p, "--root-key", self.keyfile(root))
        self.bad([p, "--root-key", self.keyfile(Key())], FAILED, "TV-REGISTRY-002",
                 "registry entry does not verify under the root key")

    def test_trust_001_certificate_changed_after_signing(self):
        root, _dep, c, ch, _certs, _reg = anchored_world()
        c2 = dict(c, valid_from=T1)
        self.check_bad(bundle(root, ch, [c2], [entry(0, LINEAGE_HEAD, c2, root)]), FAILED,
                       "TV-TRUST-001", "deployment certificate does not verify under the root key")

    def test_trust_001_certificate_signed_by_other_root(self):
        root, dep, _c, ch, _certs, _reg = anchored_world()
        c2 = certificate(dep, root, signer=Key())
        self.check_bad(bundle(root, ch, [c2], [entry(0, LINEAGE_HEAD, c2, root)]), FAILED,
                       "TV-TRUST-001", "deployment certificate does not verify under the root key")

    def test_trust_002_no_certificate(self):
        root, _dep, _c, ch, _certs, reg = anchored_world()
        self.check_bad(bundle(root, ch, [], reg), INCOMPLETE, "TV-TRUST-002",
                       "no deployment certificate")

    def test_trust_003_receipt_signed_by_other_key(self):
        root, dep, _c, _ch, certs, reg = anchored_world()
        forged = chain(dep, sign_key=Key())
        self.check_bad(bundle(root, forged, certs, reg), FAILED, "TV-TRUST-003",
                       "receipt key is not the certified deployment key")

    def test_trust_003_certificate_key_id_mismatch(self):
        root, dep, _c, ch, _certs, _reg = anchored_world()
        c2 = certificate(dep, root, child_public_key=Key().pub)
        self.check_bad(bundle(root, ch, [c2], [entry(0, LINEAGE_HEAD, c2, root)]), FAILED,
                       "TV-TRUST-003", "receipt key is not the certified deployment key")

    def test_trust_004_unlogged_certificate(self):
        root, _dep, c, ch, _certs, _reg = anchored_world()
        other_c = certificate(Key(), root)
        self.check_bad(bundle(root, ch, [c, other_c], [entry(0, LINEAGE_HEAD, other_c, root)]), FAILED,
                       "TV-TRUST-004", "no issuance entry in the Lineage Chain registry")

    def test_anchor_001_no_key_id(self):
        root, dep, _c, _ch, certs, reg = anchored_world()
        self.check_bad(bundle(root, chain(dep, with_kid=False), certs, reg), FAILED,
                       "TV-ANCHOR-001", "anchored receipt has no key_id")

    def test_anchor_001_unsigned_receipt(self):
        root, _dep, _c, _ch, certs, reg = anchored_world()
        self.check_bad(bundle(root, chain(None), certs, reg), FAILED,
                       "TV-ANCHOR-001", "anchored receipt has no key_id")

    def test_anchor_002_purpose(self):
        root, dep, _c, ch, _certs, _reg = anchored_world()
        c2 = certificate(dep, root, purpose="code_signing")
        self.check_bad(bundle(root, ch, [c2], [entry(0, LINEAGE_HEAD, c2, root)]), FAILED,
                       "TV-ANCHOR-002", "certificate purpose is not receipt_signing")

    def test_anchor_003_revoked_is_incomplete(self):
        root, _dep, c, ch, certs, reg = anchored_world()
        e0 = reg[0]
        e1 = entry(1, e0["this_hash"], c, root, "child_key_revoke", effective_at=T1)
        self.check_bad(bundle(root, ch, certs, [e0, e1]), INCOMPLETE, "TV-ANCHOR-003",
                       "cannot be placed relative to the key's effective time")

    def test_anchor_003_valid_until_is_incomplete(self):
        root, dep, _c, ch, _certs, _reg = anchored_world()
        c2 = certificate(dep, root, valid_until=T1)
        self.check_bad(bundle(root, ch, [c2], [entry(0, LINEAGE_HEAD, c2, root)]), INCOMPLETE,
                       "TV-ANCHOR-003", "cannot be placed relative to the key's effective time")

    def test_registry_001_broken_link(self):
        root, _dep, _c, ch, certs, reg = anchored_world()
        c2 = certificate(Key(), root)
        e1 = entry(1, "sha256:" + "0" * 64, c2, root)
        self.check_bad(bundle(root, ch, certs, [reg[0], e1]), FAILED, "TV-REGISTRY-001",
                       "registry projection link is broken")

    def test_registry_001_this_hash_wrong(self):
        root, _dep, _c, ch, certs, reg = anchored_world()
        e0 = copy.deepcopy(reg[0]); e0["timestamp"] = T1  # changed after hashing and signing
        self.check_bad(bundle(root, ch, certs, [e0]), FAILED, "TV-REGISTRY-001",
                       "registry projection link is broken")

    def test_registry_002_entry_signed_by_other_root(self):
        root, _dep, c, ch, certs, _reg = anchored_world()
        self.check_bad(bundle(root, ch, certs, [entry(0, LINEAGE_HEAD, c, root, signer=Key())]), FAILED,
                       "TV-REGISTRY-002", "registry entry does not verify under the root key")

    def test_registry_003_extra_member(self):
        root, _dep, c, ch, certs, _reg = anchored_world()
        self.check_bad(bundle(root, ch, certs, [entry(0, LINEAGE_HEAD, c, root, extra={"note": "x"})]),
                       FAILED, "TV-REGISTRY-003", "registry entry has an undeclared member")

    def test_head_001_bundle_expected_head(self):
        root, _dep, _c, ch, certs, reg = anchored_world()
        self.good(self.put(bundle(root, ch, certs, reg, ch[-1]["integrity_hash"]),
                           suffix=".bundle.json"))
        self.bad([self.put(bundle(root, ch[:2], certs, reg, ch[-1]["integrity_hash"]),
                           suffix=".bundle.json")], FAILED, "TV-HEAD-001", "chain head does not match")


if __name__ == "__main__":
    unittest.main(verbosity=2)
