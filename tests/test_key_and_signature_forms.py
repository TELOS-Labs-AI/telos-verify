#!/usr/bin/env python3
"""Key and signature-block forms that the suite did not exercise (gaps found by mutation testing).

Each invalid input runs beside its valid baseline, and each must fail closed
with a tagged FAIL or INCOMPLETE line, never a traceback or an acceptance.
Every key is generated in the test.
"""
from __future__ import annotations

import base64
import copy
import unittest

from test_anchored03 import SCOPE, world03
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
    signed,
)

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def noncanonical(b64text: str) -> str:
    """The same bytes spelled with an unused trailing bit set: a second spelling."""
    body = b64text.rstrip("=")
    return body[:-1] + ALPHABET[ALPHABET.index(body[-1]) + 1] + b64text[len(body):]


# Malformed forms of a root_signature block whose signature bytes are otherwise valid.
BLOCK_FORMS = {
    "covers-wrong": lambda s: s.update(covers="something else"),
    "algorithm-wrong": lambda s: s.update(algorithm="ed448"),
    "value-not-string": lambda s: s.update(value=123),
    "value-not-base64": lambda s: s.update(value="!!!!"),
    "value-63-bytes": lambda s: s.update(value=base64.b64encode(bytes(63)).decode()),
    "value-noncanonical": lambda s: s.update(value=noncanonical(s["value"])),
}


class AnchoredBase(Base):
    def setUp(self):
        super().setUp()
        self.root, self.dep, self.c, self.ch, self.certs, self.reg = world03()

    def run_bundle(self, certs=None, reg=None, *, root_key=True, **over):
        b = bundle(self.root, self.ch, self.certs if certs is None else certs,
                   self.reg if reg is None else reg)
        b.update(over)
        args = [self.put(b, suffix=".bundle.json")]
        if root_key:
            args += ["--root-key", self.keyfile(self.root)]
        return self.run_tool(*args)

    def assert_valid_baseline(self):
        rc, out = self.run_bundle()
        self.assertEqual(rc, VERIFIED, out)
        self.assertIn("NOTE: ANCHORED for", out)

    def assert_outcome(self, rc_out, rc_expected, check):
        rc, out = rc_out
        self.assertNotIn("Traceback", out)
        self.assertEqual(rc, rc_expected, out)
        self.assertRegex(out, rf"(?m)^(FAIL|INCOMPLETE) \[{check}\] ")


class SignatureBlockForms(AnchoredBase):
    """ed25519_ok refuses every malformed block, not only a wrong signature."""

    def test_certificate_root_signature_forms_are_failed(self):
        for name, mutate in BLOCK_FORMS.items():
            with self.subTest(form=name):
                self.assert_valid_baseline()
                c = copy.deepcopy(self.c)
                mutate(c["root_signature"])
                self.assert_outcome(self.run_bundle([c], [entry(0, LINEAGE_HEAD, c, self.root)]),
                                    FAILED, "TV-TRUST-001")

    def test_certificate_root_signature_not_an_object_is_failed(self):
        self.assert_valid_baseline()
        c = copy.deepcopy(self.c)
        c["root_signature"] = "not-an-object"
        self.assert_outcome(self.run_bundle([c], [entry(0, LINEAGE_HEAD, c, self.root)]),
                            FAILED, "TV-TRUST-001")

    def test_projection_entry_root_signature_forms_are_failed(self):
        for name, mutate in BLOCK_FORMS.items():
            with self.subTest(form=name):
                self.assert_valid_baseline()
                reg = copy.deepcopy(self.reg)
                mutate(reg[0]["root_signature"])
                self.assert_outcome(self.run_bundle(reg=reg), FAILED, "TV-REGISTRY-002")


class EmbeddedKeyForms(AnchoredBase):
    """Keys carried in trust material must be canonical base64 of 32 bytes."""

    def test_noncanonical_certificate_child_key_is_failed(self):
        self.assert_valid_baseline()
        c = certificate(self.dep, self.root, scope_id=SCOPE,
                        child_public_key=noncanonical(self.dep.pub))
        self.assert_outcome(self.run_bundle([c], [entry(0, LINEAGE_HEAD, c, self.root)]),
                            FAILED, "TV-TRUST-003")

    def test_noncanonical_bundle_root_is_incomplete(self):
        rc, out = self.run_bundle(root_key=False)
        self.assertEqual(rc, VERIFIED, out)                  # self-rooted baseline
        self.assert_outcome(
            self.run_bundle(root_key=False, trusted_root_public_key=noncanonical(self.root.pub)),
            INCOMPLETE, "TV-LOAD-002")


class BundleCertificateShapes(AnchoredBase):
    """Certificate lists of the wrong shape are reported, never a crash."""

    def test_null_certificates_is_incomplete(self):
        self.assert_valid_baseline()
        b = bundle(self.root, self.ch, None, self.reg)
        self.assert_outcome(self.run_tool(self.put(b, suffix=".bundle.json"),
                                          "--root-key", self.keyfile(self.root)),
                            INCOMPLETE, "TV-LOAD-002")

    def test_non_object_certificate_element_is_reported(self):
        # Malformed trust material fails closed even beside a valid certificate,
        # as a non-object *.cert.json file does under --trust-dir.
        for certs in (["not-an-object", self.c], [self.c, 7], [self.c, None]):
            with self.subTest(certs=certs[0] if certs[0] is not self.c else certs[1]):
                self.assert_valid_baseline()
                rc, out = self.run_bundle(certs=certs)
                self.assert_outcome((rc, out), INCOMPLETE, "TV-LOAD-002")
                self.assertRegex(out, r"(?m)^INCOMPLETE \[TV-LOAD-002\] .*certificates\[[01]\]")
                self.assertRegex(out, r"(?m)^INCOMPLETE: 0 of 3 receipt\(s\) passed ")
                self.assertNotIn("ANCHORED:", out)


class CallerKeyFileForms(Base):
    """--key files: base64 or hex of 32 bytes; anything else is unusable, never a crash."""

    def setUp(self):
        super().setUp()
        self.k = Key()
        self.receipt = self.put(signed(self.k))

    def run_key(self, raw):
        path = self.tmp / f"key{self.n}.txt"
        self.n += 1
        path.write_bytes(raw)
        return self.run_tool(self.receipt, "--key", path)

    def test_baseline_base64_and_hex_verify(self):
        for raw in ((self.k.pub + "\n").encode(), (self.k.raw.hex() + "\n").encode()):
            rc, out = self.run_key(raw)
            self.assertEqual(rc, VERIFIED, out)

    def test_invalid_utf8_key_file_is_incomplete(self):
        rc, out = self.run_key((self.k.pub + "\n").encode())
        self.assertEqual(rc, VERIFIED, out)
        self.assert_unusable(self.run_key(b"\xff\xfe junk\n"))

    def test_base64_with_a_foreign_character_is_incomplete(self):
        rc, out = self.run_key((self.k.pub + "\n").encode())
        self.assertEqual(rc, VERIFIED, out)
        self.assert_unusable(self.run_key((self.k.pub[:10] + "*" + self.k.pub[10:] + "\n").encode()))

    def test_space_separated_hex_is_refused(self):
        # Only canonical encodings are keys: 64 contiguous hex characters,
        # canonical base64, or PEM. bytes.fromhex would accept spaced pairs.
        rc, out = self.run_key((self.k.raw.hex() + "\n").encode())
        self.assertEqual(rc, VERIFIED, out)
        self.assert_unusable(self.run_key((" ".join(f"{b:02x}" for b in self.k.raw) + "\n").encode()))

    def test_sixty_four_characters_that_are_not_contiguous_hex_are_refused(self):
        # The length of a hex key, but not its spelling: non-hex characters, and
        # 21 hex byte pairs padded with doubled separators to 64 characters.
        pairs = [f"{b:02x}" for b in self.k.raw[:21]]
        spaced = "  ".join(pairs[:3]) + " " + " ".join(pairs[3:])
        self.assertEqual(len(spaced), 64)
        for text in ("z" * 64, spaced):
            with self.subTest(text=text[:12]):
                rc, out = self.run_key((self.k.raw.hex() + "\n").encode())
                self.assertEqual(rc, VERIFIED, out)
                self.assert_unusable(self.run_key((text + "\n").encode()))

    def test_noncanonical_base64_key_file_is_refused(self):
        rc, out = self.run_key((self.k.pub + "\n").encode())
        self.assertEqual(rc, VERIFIED, out)
        self.assert_unusable(self.run_key((noncanonical(self.k.pub) + "\n").encode()))

    def assert_unusable(self, rc_out):
        rc, out = rc_out
        self.assertNotIn("Traceback", out)
        self.assertEqual(rc, INCOMPLETE, out)
        self.assertRegex(out, r"(?m)^INCOMPLETE \[TV-LOAD-002\] --key ")


if __name__ == "__main__":
    unittest.main()
