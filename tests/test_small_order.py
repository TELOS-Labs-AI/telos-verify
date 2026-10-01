#!/usr/bin/env python3
"""Refuse small-order and non-canonical Ed25519 public keys.

In an earlier version, with the identity point as public key
(01 followed by 31 zero bytes) and the signature R = identity, S = 0, a receipt
verified, and with that key as --root-key a forged bundle reported ANCHORED.
No private key exists for that construction; it is reproduced here byte for byte.

Outcomes:
  raw caller key refused (--key, --root-key)                       -> INCOMPLETE [TV-KEY-001]
  bundle root key, or any certificate child key refused           -> FAILED     [TV-KEY-002]
  (certificates from --trust-dir or a bundle, used by a receipt or not)
Every loaded certificate is checked when it is loaded.

Small-order table: the 8 canonical encodings of the Ed25519 torsion points.
The two order-8 y values are the ones libsodium blocks in
ge25519_has_small_order() (crypto_core/ed25519/ref10/ed25519_ref10.c); with
y = 0, 1, p-1 and both x signs where x != 0 they give exactly 8 points.
Non-canonical: y >= p (RFC 8032 section 5.1.3 step 1), and x = 0 with the sign
bit set (step 4). Every CLI case sits beside a valid key that must still pass;
KeyRefusalUnit drives the guard directly on fixed inputs for branch coverage.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_s3_conformance import (
    FAILED,
    INCOMPLETE,
    LINEAGE_HEAD,
    SIG_COVERS,
    VERIFIED,
    Base,
    Key,
    bundle,
    certificate,
    chain,
    entry,
    h,
    signed,
    unsigned,
)

P = 2 ** 255 - 19
IDENTITY = bytes([1]) + bytes(31)
FORGERY = IDENTITY + bytes(32)          # R = identity, S = 0: needs no private key


def enc(y: int, sign: int = 0) -> bytes:
    return (y | (sign << 255)).to_bytes(32, "little")


Y8_A = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
Y8_B = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")

SMALL_ORDER = {
    "order 1: identity (y=1)": enc(1),
    "order 2: y=p-1": enc(P - 1),
    "order 4: y=0, x sign 0": enc(0, 0),
    "order 4: y=0, x sign 1": enc(0, 1),
    "order 8: y8a, x sign 0": Y8_A,
    "order 8: y8a, x sign 1": Y8_A[:31] + bytes([Y8_A[31] | 0x80]),
    "order 8: y8b, x sign 0": Y8_B,
    "order 8: y8b, x sign 1": Y8_B[:31] + bytes([Y8_B[31] | 0x80]),
}
NON_CANONICAL = {
    "y = p (encodes 0, not reduced)": enc(P),
    "y = p+1 (encodes 1, not reduced)": enc(P + 1),
    "y = 2^255-1": enc(2 ** 255 - 1),
    "x = 0 with sign bit set (y=1)": enc(1, 1),
}


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def forged_receipt(pub: bytes = IDENTITY):
    r = unsigned()
    r["receipt_version"] = "telos/0.2-ed25519"
    r["signing_status"] = "ed25519_signed"
    r["signature"] = {"algorithm": "ed25519", "covers": SIG_COVERS, "value": b64(FORGERY),
                      "public_key": b64(pub), "key_id": "sha256:" + hashlib.sha256(pub).hexdigest()}
    return r


def forged_bundle():
    """An identity-point bundle: root, child, certificate, projection and receipts all forged."""
    troot, tdep = Key(), Key()
    kid = "sha256:" + hashlib.sha256(IDENTITY).hexdigest()
    cert = certificate(tdep, troot)
    cert.update(child_public_key=b64(IDENTITY), child_key_id=kid, root_key_id=kid)
    cert["root_signature"]["value"] = b64(FORGERY)
    e = entry(0, LINEAGE_HEAD, cert, troot)
    e.update(root_key_id=kid, child_key_id=kid)
    e["this_hash"] = h({k: v for k, v in e.items() if k not in ("this_hash", "root_signature")})
    e["root_signature"]["value"] = b64(FORGERY)
    ch = chain(tdep, n=3)
    for rec in ch:
        rec["signature"].update(public_key=b64(IDENTITY), key_id=kid, value=b64(FORGERY))
    b = bundle(troot, ch, [cert], [e])
    b["trusted_root_public_key"] = b64(IDENTITY)
    return b


def weak_child_bundle(root: Key):
    """A REAL root certifies a forgeable (identity) child key; receipts use the forgery."""
    tdep = Key()
    kid = "sha256:" + hashlib.sha256(IDENTITY).hexdigest()
    cert = certificate(tdep, root, child_public_key=b64(IDENTITY), child_key_id=kid)
    ch = chain(tdep, n=3)
    for rec in ch:
        rec["signature"].update(public_key=b64(IDENTITY), key_id=kid, value=b64(FORGERY))
    return bundle(root, ch, [cert], [entry(0, LINEAGE_HEAD, cert, root)])


def valid_bundle():
    root, dep = Key(), Key()
    c = certificate(dep, root)
    return root, bundle(root, chain(dep), [c], [entry(0, LINEAGE_HEAD, c, root)])


class SmallOrderKeys(Base):
    def rawkey(self, raw: bytes):
        return self.put(raw=b64(raw) + "\n", suffix=".test-public.b64")

    def baseline_signed(self):
        k = Key()
        self.good(self.put(signed(k)), "--key", self.keyfile(k))

    # -- identity-point reproducer, caller key
    def test_identity_forgery_with_key_is_refused(self):
        self.baseline_signed()
        out = self.bad([self.put(forged_receipt()), "--key", self.rawkey(IDENTITY)], INCOMPLETE,
                       "TV-KEY-001", "small-order")
        self.assertNotIn("SIGNATURE CHECKED", out)
        self.assertNotIn("VERIFIED", out)

    def test_identity_key_as_pem_is_refused(self):
        self.baseline_signed()
        pem = Ed25519PublicKey.from_public_bytes(IDENTITY).public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        self.bad([self.put(forged_receipt()), "--key", self.put(raw=pem, suffix=".pem")],
                 INCOMPLETE, "TV-KEY-001", "small-order")

    def test_forgery_under_real_key_still_fails_signature(self):
        k = Key()
        self.good(self.put(signed(k)), "--key", self.keyfile(k))
        self.bad([self.put(forged_receipt()), "--key", self.keyfile(k)], FAILED, "TV-SIG-006",
                 "does not verify under any key you supplied")

    # -- identity-point reproducer, root key
    def test_identity_root_key_bundle_never_anchored(self):
        root, vb = valid_bundle()
        ok = self.good(self.put(vb, suffix=".bundle.json"), "--root-key", self.keyfile(root))
        self.assertIn("ANCHORED", ok)
        # The raw --root-key is refused (INCOMPLETE) and the bundle's identity certificate is
        # refused at load (FAILED, which outranks it).
        out = self.bad([self.put(forged_bundle(), suffix=".bundle.json"),
                        "--root-key", self.rawkey(IDENTITY)], FAILED, "TV-KEY-002", "small-order")
        self.assertRegex(out, r"(?m)^INCOMPLETE \[TV-KEY-001\] --root-key .*small-order")
        self.assertNotRegex(out, r"(?<!NOT )\bANCHORED\b")
        self.assertNotIn("VERIFIED", out)

    # -- embedded keys: FAILED
    def test_identity_bundle_root_embedded_is_failed(self):
        _root, vb = valid_bundle()
        self.good(self.put(vb, suffix=".bundle.json"))
        out = self.bad([self.put(forged_bundle(), suffix=".bundle.json")], FAILED, "TV-KEY-002",
                       "small-order")
        self.assertNotIn("VERIFIED", out)
        # The refusal is the whole story: no secondary "anchored mode needs a root key" line.
        self.assertNotIn("TV-LOAD-002", out)

    def test_certified_small_order_child_key_is_failed(self):
        root, vb = valid_bundle()
        self.good(self.put(vb, suffix=".bundle.json"), "--root-key", self.keyfile(root))
        out = self.bad([self.put(weak_child_bundle(root), suffix=".bundle.json"),
                        "--root-key", self.keyfile(root)], FAILED, "TV-KEY-002", "small-order")
        self.assertNotRegex(out, r"(?<!NOT )\bANCHORED\b")

    def trust_dir(self, name, certs, registry):
        d = self.tmp / name; d.mkdir()
        for i, c in enumerate(certs):
            (d / f"c{i}.cert.json").write_text(json.dumps(c))
        (d / "projection.jsonl").write_text("".join(json.dumps(e) + "\n" for e in registry))
        return d

    def test_certified_small_order_child_key_via_trust_dir_is_failed(self):
        # The root-signed certificate bytes prove the defect: FAILED, and the load is refused.
        root, vb = valid_bundle()
        b = weak_child_bundle(root)
        good = self.trust_dir("goodtrust", vb["certificates"], vb["registry"])
        self.good(self.jsonl(vb["chain"]), "--root-key", self.keyfile(root), "--trust-dir", good)
        d = self.trust_dir("trust", b["certificates"], b["registry"])
        out = self.bad([self.jsonl(b["chain"]), "--root-key", self.keyfile(root), "--trust-dir", d],
                       FAILED, "TV-KEY-002", "small-order")
        self.assertNotRegex(out, r"(?<!NOT )\bANCHORED\b")

    # -- every loaded certificate, used or not
    def unused_weak_cert(self, root):
        kid = "sha256:" + hashlib.sha256(IDENTITY).hexdigest()
        return certificate(Key(), root, child_public_key=b64(IDENTITY), child_key_id=kid)

    def test_unused_small_order_certificate_in_trust_dir_is_failed(self):
        root, vb = valid_bundle()
        good = self.trust_dir("goodtrust", vb["certificates"], vb["registry"])
        self.good(self.jsonl(vb["chain"]), "--root-key", self.keyfile(root), "--trust-dir", good)
        d = self.trust_dir("trust", vb["certificates"] + [self.unused_weak_cert(root)],
                           vb["registry"])
        out = self.bad([self.jsonl(vb["chain"]), "--root-key", self.keyfile(root),
                        "--trust-dir", d], FAILED, "TV-KEY-002", "small-order")
        self.assertNotRegex(out, r"(?<!NOT )\bANCHORED\b")
        self.assertNotIn("VERIFIED", out)

    def test_unused_small_order_certificate_in_bundle_is_failed(self):
        root, vb = valid_bundle()
        self.good(self.put(vb, suffix=".bundle.json"), "--root-key", self.keyfile(root))
        b = copy.deepcopy(vb)
        b["certificates"].append(self.unused_weak_cert(root))
        out = self.bad([self.put(b, suffix=".bundle.json"), "--root-key", self.keyfile(root)],
                       FAILED, "TV-KEY-002", "small-order")
        self.assertNotRegex(out, r"(?<!NOT )\bANCHORED\b")
        self.assertNotIn("VERIFIED", out)

    # -- the table
    def test_all_eight_small_order_points_refused_as_key(self):
        self.assertEqual(len(set(SMALL_ORDER.values())), 8)
        for label, raw in SMALL_ORDER.items():
            with self.subTest(label):
                self.baseline_signed()
                self.bad([self.put(forged_receipt(raw)), "--key", self.rawkey(raw)], INCOMPLETE,
                         "TV-KEY-001", "small-order")

    def test_all_eight_small_order_points_refused_as_root_key(self):
        root, vb = valid_bundle()
        for label, raw in SMALL_ORDER.items():
            with self.subTest(label):
                self.good(self.put(vb, suffix=".bundle.json"), "--root-key", self.keyfile(root))
                self.bad([self.put(vb, suffix=".bundle.json"), "--root-key", self.rawkey(raw)],
                         INCOMPLETE, "TV-KEY-001", "small-order")

    def test_non_canonical_encodings_refused(self):
        for label, raw in NON_CANONICAL.items():
            with self.subTest(label):
                self.baseline_signed()
                self.bad([self.put(forged_receipt(raw)), "--key", self.rawkey(raw)], INCOMPLETE,
                         "TV-KEY-001", "not a canonical point encoding")

    def test_non_canonical_certificate_key_is_failed(self):
        root, vb = valid_bundle()
        self.good(self.put(vb, suffix=".bundle.json"), "--root-key", self.keyfile(root))
        b = copy.deepcopy(vb)
        raw = NON_CANONICAL["y = p (encodes 0, not reduced)"]
        kid = "sha256:" + hashlib.sha256(raw).hexdigest()
        cert = certificate(Key(), root, child_public_key=b64(raw), child_key_id=kid)
        for rec in b["chain"]:
            rec["signature"].update(public_key=b64(raw), key_id=kid)
        b["certificates"], b["registry"] = [cert], [entry(0, LINEAGE_HEAD, cert, root)]
        self.bad([self.put(b, suffix=".bundle.json"), "--root-key", self.keyfile(root)], FAILED,
                 "TV-KEY-002", "not a canonical point encoding")

    def test_ordinary_keys_accepted(self):
        for _ in range(5):
            self.baseline_signed()

    def test_list_checks_declares_key_ids(self):
        rc, out = self.run_tool("--list-checks")
        self.assertEqual(rc, VERIFIED, out)
        self.assertRegex(out, r"(?m)^CHECK TV-KEY-001\s+INCOMPLETE\s")
        self.assertRegex(out, r"(?m)^CHECK TV-KEY-002\s+FAILED\s")


def _tool_module():
    import importlib
    import sys
    repo = str(pathlib.Path(__file__).resolve().parent.parent)
    if repo not in sys.path:
        sys.path.insert(0, repo)
    return importlib.import_module("telos_verify_lib.keys")


# RFC 8032 section 7.1 TEST 1-3 public keys (published vectors; public data only).
RFC8032_PUBLIC = [bytes.fromhex(x) for x in (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
)]


class KeyRefusalUnit(unittest.TestCase):
    """The guard function itself, on fixed inputs (deterministic branch coverage)."""

    @classmethod
    def setUpClass(cls):
        cls.tv = _tool_module()

    def fixed_keys(self, n=64):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        # Fixed throwaway seeds generated here, never real key material.
        return [Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"g1b3-test-%d" % i).digest())
                .public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for i in range(n)]

    def test_table_is_exactly_the_refused_small_order_set(self):
        for label, raw in SMALL_ORDER.items():
            with self.subTest(label):
                self.assertRegex(self.tv.key_refusal(raw) or "", "^small-order point")

    def test_non_canonical_table_refused_as_non_canonical(self):
        for label, raw in NON_CANONICAL.items():
            with self.subTest(label):
                self.assertRegex(self.tv.key_refusal(raw) or "", "^not a canonical point encoding")

    def test_y_without_curve_point_refused(self):
        # y = 2 has no x on edwards25519 (checked by the guard's own square-root test).
        self.assertEqual(self.tv.key_refusal(enc(2)),
                         "not a canonical point encoding (no curve point has this y)")

    def test_rfc8032_public_keys_accepted_both_signs(self):
        for raw in RFC8032_PUBLIC:
            flipped = raw[:31] + bytes([raw[31] ^ 0x80])   # -P: also a full-order point
            self.assertIsNone(self.tv.key_refusal(raw), raw.hex())
            self.assertIsNone(self.tv.key_refusal(flipped), flipped.hex())

    def test_fixed_generated_keys_accepted_and_cover_both_root_branches(self):
        tv, sqrt_branch, plain_branch = self.tv, 0, 0
        for raw in self.fixed_keys():
            self.assertIsNone(tv.key_refusal(raw), raw.hex())
            y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
            u, v = (y * y - 1) % P, (tv._D * y * y + 1) % P
            x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
            if v * x * x % P == u:
                plain_branch += 1
            else:
                sqrt_branch += 1
        self.assertGreater(sqrt_branch, 0)
        self.assertGreater(plain_branch, 0)

    def test_order_eight_values_match_libsodium_listing(self):
        # Independent of the guard: y8 satisfies the curve equation with x != 0 and
        # the point has order exactly 8 ([4]P != identity, [8]P == identity).
        tv = self.tv
        for yb in (Y8_A, Y8_B):
            y = int.from_bytes(yb, "little")
            u, v = (y * y - 1) % P, (tv._D * y * y + 1) % P
            x = next(c for c in (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P,)
                     for c in (c, c * tv._SQRT_M1 % P) if v * c * c % P == u)
            pt = (x, y, 1, x * y % P)
            for _ in range(2):
                pt = tv._edwards_add(pt, pt)
            self.assertFalse(pt[0] == 0 and pt[1] == pt[2], "order divides 4")
            pt = tv._edwards_add(pt, pt)
            self.assertTrue(pt[0] == 0 and pt[1] == pt[2], "order does not divide 8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
