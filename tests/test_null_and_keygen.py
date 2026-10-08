"""Fail-closed input counts and keygen, using only temporary test material.

Each refusal runs beside a valid baseline. Fault injection exercises real
exclusive creates and cleanup; no production key or receipt is used.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch

from test_s3_conformance import Base, INCOMPLETE, Key, REPO, bundle, chain, unsigned
from test_anchored03 import world03

if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
import telos_sign
from telos_verify_lib import cli


NON_OBJECTS = (None, 7, 1.5, "receipt", True, False, [], [unsigned()])


class ReceiptRefusal(Base):
    def assert_refused(self, args, check="TV-PARSE-002"):
        rc, out = self.run_tool(*args)
        self.assertEqual(rc, INCOMPLETE, out)
        self.assertRegex(out, rf"(?m)^INCOMPLETE \[{check}\] ")
        self.assertNotRegex(out, r"(?m)^VERIFIED")
        self.assertNotIn("Traceback", out)
        return out

    def test_non_objects_alone(self):
        for obj in NON_OBJECTS:
            with self.subTest(obj=obj):
                self.good(self.put(unsigned()))
                out = self.assert_refused([self.put(obj)])
                self.assertIn("0 of 1 receipt(s) passed", out)

    def test_non_objects_beside_valid_in_directory(self):
        for obj in NON_OBJECTS:
            for bad_first in (True, False):
                with self.subTest(obj=obj, bad_first=bad_first):
                    directory = self.tmp / f"dir{self.n}"
                    self.put(unsigned(), name=f"{directory.name}/valid.json")
                    self.good(directory)
                    self.put(obj, name=f"{directory.name}/{'aaa' if bad_first else 'zzz'}.json")
                    out = self.assert_refused([directory])
                    self.assertIn("1 of 2 receipt(s) passed", out)

    def test_non_objects_beside_valid_in_jsonl(self):
        good = chain(None, n=2)
        for obj in NON_OBJECTS:
            for bad_first in (True, False):
                with self.subTest(obj=obj, bad_first=bad_first):
                    self.good(self.jsonl(good))
                    records = [obj, *good] if bad_first else [*good, obj]
                    self.assert_refused([self.jsonl(records)])

    def test_non_objects_beside_valid_in_bundle(self):
        root = Key()
        for obj in NON_OBJECTS:
            for bad_first in (True, False):
                with self.subTest(obj=obj, bad_first=bad_first):
                    good = [unsigned()]
                    self.good(self.put(bundle(root, good, [], [])))
                    records = [obj, *good] if bad_first else [*good, obj]
                    out = self.assert_refused([self.put(bundle(root, records, [], []))])
                    self.assertIn("1 of 2 receipt(s) passed", out)

    def test_empty_bundle_is_not_a_pass(self):
        root = Key()
        self.good(self.put(bundle(root, [unsigned()], [], [])))
        self.assert_refused([self.put(bundle(root, [], [], []))], "TV-LOAD-001")

    def test_zero_receipt_paths_are_nonzero(self):
        self.good(self.put(unsigned()))
        empty_dir = self.tmp / "empty"
        empty_dir.mkdir()
        for args in ([empty_dir], [self.put(raw="", suffix=".jsonl")],
                     [self.tmp / "missing.json"]):
            with self.subTest(args=args):
                self.good(self.put(unsigned()))
                rc, out = self.run_tool(*args)
                self.assertNotEqual(rc, 0, out)
                self.assertNotRegex(out, r"(?m)^VERIFIED")
                self.assertRegex(out, r"(?m)^(FAIL|INCOMPLETE) \[TV-[A-Z0-9]+-[0-9]{3}\] ")

    def test_quiet_partial_load_cannot_say_verified(self):
        directory = self.tmp / "quiet"
        self.put(unsigned(), name="quiet/valid.json")
        self.good(directory, "--quiet")
        self.put(None, name="quiet/null.json")
        rc, out = self.run_tool(directory, "--quiet")
        self.assertEqual(rc, INCOMPLETE, out)
        self.assertNotRegex(out, r"(?m)^VERIFIED")
        self.assertIn("1 of 2 receipt(s) passed", out)

    def test_silent_backend_skip_cannot_exit_zero(self):
        receipt = self.put(unsigned())
        self.good(receipt)
        args = cli.build_parser().parse_args([str(receipt)])
        output = io.StringIO()
        # A backend returning False without recording a diagnostic must still
        # refuse the overall run; this targets the final count guard directly.
        with patch.object(cli, "verify_one", return_value=False), contextlib.redirect_stdout(output):
            rc = cli.run(args)
        self.assertEqual(rc, INCOMPLETE, output.getvalue())
        self.assertIn("INCOMPLETE [TV-LOAD-001]", output.getvalue())
        self.assertNotRegex(output.getvalue(), r"(?m)^VERIFIED")


class ProjectionDisclosure(Base):
    def test_anchored_pass_discloses_unchecked_projection_tail(self):
        root, _, _, receipts, certs, registry = world03()
        for extra in ((), ("--quiet",)):
            with self.subTest(extra=extra):
                rc, out = self.run_tool(self.put(bundle(root, receipts, certs, registry)),
                                        "--root-key", self.keyfile(root), *extra)
                self.assertEqual(rc, 0, out)
                self.assertIn("NOTE: ANCHORED for", out)
                self.assertIn("projection currency and completeness were NOT checked", out)
                self.assertIn("--expected-projection-head", out)


class KeygenRefusal(Base):
    PRIVATE = "telos-signing-key.pem"
    PUBLIC = "telos-public-key.pem"

    def run_keygen(self, directory):
        process = subprocess.run([sys.executable, "-B", str(REPO / "telos_sign.py"),
                                  "keygen", "--out-dir", str(directory)],
                                 capture_output=True, text=True, timeout=60)
        return process.returncode, process.stdout + process.stderr

    def baseline(self):
        directory = self.tmp / f"baseline{self.n}"
        self.n += 1
        rc, out = self.run_keygen(directory)
        self.assertEqual(rc, 0, out)
        self.assertEqual({p.name for p in directory.iterdir()}, {self.PRIVATE, self.PUBLIC})
        self.assertEqual(stat.S_IMODE((directory / self.PRIVATE).stat().st_mode), 0o600)
        return directory

    def call_keygen(self, directory):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            rc = telos_sign.keygen(directory)
        return rc, output.getvalue()

    def test_existing_either_or_both_is_untouched(self):
        for names in ((self.PRIVATE,), (self.PUBLIC,), (self.PRIVATE, self.PUBLIC)):
            with self.subTest(names=names):
                self.baseline()
                directory = self.tmp / f"collision{self.n}"
                self.n += 1
                directory.mkdir()
                expected = {}
                for name in names:
                    expected[name] = b"dummy key canary: " + name.encode()
                    (directory / name).write_bytes(expected[name])
                rc, out = self.run_keygen(directory)
                actual = {p.name: p.read_bytes() for p in directory.iterdir()}
                self.assertEqual(actual, expected, out)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("refus", out.lower())
                self.assertIn("exist", out.lower())
                self.assertNotIn("Traceback", out)

    def test_dangling_symlinks_are_existing_targets(self):
        for name in (self.PRIVATE, self.PUBLIC):
            with self.subTest(name=name):
                self.baseline()
                directory = self.tmp / f"symlink{self.n}"
                self.n += 1
                directory.mkdir()
                missing = directory / "dummy-missing"
                (directory / name).symlink_to(missing)
                rc, out = self.run_keygen(directory)
                self.assertFalse(missing.exists(), out)
                self.assertEqual([p.name for p in directory.iterdir()], [name], out)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("refus", out.lower())

    def test_existing_target_refuses_before_any_create(self):
        for name in (self.PRIVATE, self.PUBLIC):
            with self.subTest(name=name):
                self.baseline()
                directory = self.tmp / f"preflight{self.n}"
                self.n += 1
                directory.mkdir()
                (directory / name).write_bytes(b"dummy existing key")
                # Even a transient private file is forbidden when the public
                # target already exists. Fail if keygen reaches any create.
                with patch.object(telos_sign.os, "open", side_effect=AssertionError("create attempted despite existing target")):
                    rc, out = self.call_keygen(directory)
                self.assertNotEqual(rc, 0, out)
                self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()},
                                 {name: b"dummy existing key"})

    def test_private_created_mode_0600_even_with_restrictive_umask(self):
        self.baseline()
        directory = self.tmp / "restrictive"
        directory.mkdir()
        old_umask = os.umask(0o777)
        try:
            rc, out = self.call_keygen(directory)
        finally:
            os.umask(old_umask)
        self.assertEqual(rc, 0, out)
        self.assertEqual(stat.S_IMODE((directory / self.PRIVATE).stat().st_mode), 0o600)

    def test_private_has_mode_0600_at_creation_before_bytes(self):
        self.baseline()
        directory = self.tmp / "initial-mode"
        directory.mkdir()
        real_open = os.open
        observed = []

        def observe_open(path, flags, mode=0o777):
            fd = real_open(path, flags, mode)
            if pathlib.Path(path).name == self.PRIVATE:
                observed.append(stat.S_IMODE(os.fstat(fd).st_mode))
            return fd

        old_umask = os.umask(0)
        try:
            with patch.object(telos_sign.os, "open", side_effect=observe_open):
                rc, out = self.call_keygen(directory)
        finally:
            os.umask(old_umask)
        self.assertEqual(rc, 0, out)
        self.assertEqual(observed, [0o600], out)

    def test_race_at_either_create_preserves_existing_dummy(self):
        real_open = os.open
        for name in (self.PRIVATE, self.PUBLIC):
            with self.subTest(name=name):
                self.baseline()
                directory = self.tmp / f"race{self.n}"
                self.n += 1
                directory.mkdir()
                raced = directory / name
                canary = b"dummy concurrent creator"

                def racing_open(path, flags, mode=0o777):
                    if pathlib.Path(path) == raced:
                        with os.fdopen(real_open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                            f.write(canary)
                    return real_open(path, flags, mode)

                with patch.object(telos_sign.os, "open", side_effect=racing_open):
                    rc, out = self.call_keygen(directory)
                self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()},
                                 {name: canary}, out)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("refus", out.lower())

    def test_open_failure_leaves_no_pair(self):
        real_open = os.open
        for name in (self.PRIVATE, self.PUBLIC):
            with self.subTest(name=name):
                self.baseline()
                directory = self.tmp / f"open-fail{self.n}"
                self.n += 1
                directory.mkdir()

                def failing_open(path, flags, mode=0o777):
                    if pathlib.Path(path).name == name:
                        raise OSError("dummy exclusive-create failure")
                    return real_open(path, flags, mode)

                with patch.object(telos_sign.os, "open", side_effect=failing_open):
                    rc, out = self.call_keygen(directory)
                self.assertEqual(list(directory.iterdir()), [], out)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("refus", out.lower())

    def test_write_failure_leaves_no_pair(self):
        real_fdopen = os.fdopen
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                self.baseline()
                directory = self.tmp / f"write-fail{self.n}"
                self.n += 1
                directory.mkdir()
                writes = 0

                @contextlib.contextmanager
                def failing_fdopen(fd, mode):
                    nonlocal writes
                    writes += 1
                    with real_fdopen(fd, mode) as f:
                        if writes == fail_at:
                            class BrokenWriter:
                                def write(self, data):
                                    f.write(data[:8])  # partial bytes really land
                                    raise OSError("dummy partial-write failure")
                            yield BrokenWriter()
                        else:
                            yield f

                with patch.object(telos_sign.os, "fdopen", side_effect=failing_fdopen):
                    rc, out = self.call_keygen(directory)
                self.assertEqual(list(directory.iterdir()), [], out)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("refus", out.lower())


if __name__ == "__main__":
    unittest.main()
