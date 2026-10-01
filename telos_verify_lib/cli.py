"""Argument parsing and the run itself."""
from __future__ import annotations

import argparse
import pathlib

from .anchored import verify_anchored, verify_projection
from .chain import check_expected_head, verify_chain
from .common import BUNDLE_VERSION, CHECKS, VERIFIED
from .inputs import as_receipt, load, load_chain_file, load_trust_dir
from .keys import (
    HAVE_CRYPTO,
    KeyRefused,
    load_public_key,
    raw_bytes,
    raw_public_key,
    refused_certificate,
)
from .receipt import verify_one
from .report import print_report
from .result import Result
from .schema import valid_sha256


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="telos-verify",
        description="Verify TELOS integrity-hash receipts offline. Makes no network calls.",
    )
    ap.add_argument("path", nargs="?",
                    help="a receipt .json file, a directory of them, a .jsonl chain file, "
                         "or a trs-test-bundle/0.1 .json file")
    ap.add_argument("--list-checks", action="store_true",
                    help="print every check id this tool implements, one `CHECK <id>` line "
                         "each, and exit 0")
    ap.add_argument("--root-key", metavar="FILE",
                    help="anchored mode: the root public key you already trust (PEM, or 32 "
                         "raw bytes as base64/hex). Requires --trust-dir, unless the input is "
                         "a test bundle, whose own root is then ignored.")
    ap.add_argument("--trust-dir", metavar="DIR",
                    help="anchored mode (S3 3.2): a directory holding one trs-cert/0.1 "
                         "certificate per *.cert.json file, and projection.jsonl (the Lineage "
                         "Chain public projection, one trs-lineage-projection/0.1 entry per "
                         "line in sequence order)")
    ap.add_argument(
        "--quiet", action="store_true",
        help="suppress per-receipt trace; keep the verdict and safety notes. On a "
             "nonzero result, re-run without --quiet for diagnostic reasons.",
    )
    ap.add_argument(
        "--key", action="append", default=[], metavar="FILE",
        help="a public key you already trust (PEM, or 32 raw bytes as base64/hex). "
             "Repeatable. Outside anchored mode, signatures are checked ONLY against "
             "keys given here; the key printed on a receipt is not a trust anchor.",
    )
    ap.add_argument(
        "--require-signature", action="store_true",
        help="treat an unsigned or unchecked receipt as INCOMPLETE rather than "
             "VERIFIED (UNSIGNED INTEGRITY ONLY). Off by default: unsigned receipts are a real "
             "contract, not an error.",
    )
    head = ap.add_mutually_exclusive_group()
    head.add_argument(
        "--expected-head", metavar="SHA256",
        help="an independently obtained expected chain head in sha256:<64 lowercase "
             "hex> form. A linked chain that ends elsewhere is FAILED.",
    )
    head.add_argument(
        "--expected-head-file", metavar="FILE",
        help="read the independently obtained expected chain head from FILE. The file "
             "must contain only sha256:<64 lowercase hex> plus optional whitespace.",
    )
    return ap


def main(argv: list[str]) -> int:
    ap = build_parser()
    args = ap.parse_args(argv[1:])

    if args.list_checks:
        for cid, (state, what) in CHECKS.items():
            print(f"CHECK {cid}  {state}  {what}")
        return VERIFIED
    if args.path is None:
        ap.error("the following arguments are required: path")
    return run(args)


class Run:
    """Everything one run gathers before the verdict: inputs, trust material, results."""

    def __init__(self, args):
        self.args = args
        self.r = Result()
        self.expected_head = None
        self.keys = []
        # Anchored-mode trust material: the caller's root, and certificates plus the
        # Lineage Chain projection from --trust-dir or a test bundle.
        self.root_raw = None
        self.anchor_error = False
        self.certs = self.entries = None
        self.items = []           # (label path, receipt) in input order
        self.files_count = 0
        self.loaded = []
        self.verified_inline = False
        self.anchored = False


def run(args) -> int:
    s = Run(args)
    r = s.r
    s.expected_head = expected_head_arg(args, r)
    s.keys = caller_keys(args.key, r)
    load_root_key(s)
    if args.trust_dir:
        s.certs, s.entries = load_trust_dir(pathlib.Path(args.trust_dir).expanduser(), r)
        if s.certs is None:
            s.anchor_error = True

    gather(s, pathlib.Path(args.path).expanduser())
    decide_anchored(s)
    if not s.verified_inline:
        for f, rec in s.items:
            if verify_one(f, rec, r, None if s.anchored else s.keys):
                s.loaded.append((f, rec))
    anchor_loaded(s)

    if args.require_signature and r.unsigned:
        r.incomplete(
            "TV-SIG-008",
            f"--require-signature was given, and {r.unsigned} receipt(s) carried no "
            "signature this tool could check."
        )

    files = [f for f, _ in s.items] if len(s.items) == s.files_count else [None] * s.files_count
    evaluate_chain(s, files)

    if s.expected_head is not None:
        check_expected_head(s.expected_head, r)

    if r.saw_failed and r.saw_incomplete:
        # Report the precedence decision only; the state is set by Result.incomplete
        # alone, so this line cannot mask a precedence bug.
        r.lines.append("FAIL [TV-EXIT-001] this run has both FAILED and INCOMPLETE results; "
                       "FAILED outranks INCOMPLETE, so the exit code is 1")

    print_report(r, args, s.loaded, files)
    return r.state


def expected_head_arg(args, r: Result):
    """The caller's expected head from --expected-head or --expected-head-file, or None."""
    expected_head = args.expected_head
    if args.expected_head_file:
        head_path = pathlib.Path(args.expected_head_file).expanduser()
        try:
            expected_head = head_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as e:
            r.incomplete("TV-LOAD-001", f"--expected-head-file {head_path}: unreadable: {e}")
            expected_head = None
    if expected_head is not None and not valid_sha256(expected_head):
        r.incomplete(
            "TV-LOAD-003",
            "expected head is malformed; expected sha256: followed by exactly "
            "64 lowercase hexadecimal characters"
        )
        expected_head = None
    return expected_head


def caller_keys(paths, r: Result) -> list:
    """(key_id, key) for every usable --key file."""
    keys = []
    for kpath in paths:
        p = pathlib.Path(kpath).expanduser()
        try:
            keys.append(load_public_key(p))
        except KeyRefused as e:
            r.incomplete("TV-KEY-001", f"--key {p}: {e}")
        except (ValueError, OSError) as e:
            # An unusable trust anchor must never degrade quietly into "no key
            # supplied", which would read as INCOMPLETE for the wrong reason.
            r.incomplete("TV-LOAD-002", f"--key {p}: {e}")
    return keys


def load_root_key(s: Run) -> None:
    """The caller's --root-key, if given."""
    root_key = s.args.root_key
    if not root_key:
        return
    try:
        _kid, root_pub = load_public_key(pathlib.Path(root_key).expanduser())
        s.root_raw = raw_bytes(root_pub)
    except KeyRefused as e:
        s.r.incomplete("TV-KEY-001", f"--root-key {root_key}: {e}")
        s.anchor_error = True
    except (ValueError, OSError) as e:
        s.r.incomplete("TV-LOAD-002", f"--root-key {root_key}: {e}")
        s.anchor_error = True


def gather(s: Run, target: pathlib.Path) -> None:
    """Load the input: a directory, a chain file, a receipt, or a test bundle."""
    r = s.r
    if target.is_dir():
        gather_dir(s, target)
    elif target.suffix == ".jsonl" and target.exists():
        chain_items = load_chain_file(target, r)
        s.items = chain_items or []
        s.files_count = max(len(s.items), 1)
    elif target.exists():
        s.files_count = 1
        rec = load(target, r)
        if rec is not None and "bundle_version" in rec:
            gather_bundle(s, target, rec)
        elif rec is not None:
            s.items.append((target, rec))
    else:
        r.incomplete("TV-LOAD-001", f"{target}: no such file or directory")


def gather_dir(s: Run, target: pathlib.Path) -> None:
    r = s.r
    # Whether anchored mode is on is known here for every input except a test
    # bundle (a single file, handled in gather_bundle).
    cli_anchored = s.root_raw is not None or s.certs is not None or s.anchor_error
    files = sorted(p for p in target.glob("*.json"))
    if not files:
        r.incomplete("TV-LOAD-001", f"{target}: directory contains no .json receipts")
    s.files_count = len(files)
    # Load and check one file at a time, in file order, so the tool's
    # verdict never depends on which kind of problem it met first.
    s.verified_inline = True
    for f in files:
        rec = load(f, r)
        if rec is not None:
            s.items.append((f, rec))
            if verify_one(f, rec, r, None if cli_anchored else s.keys):
                s.loaded.append((f, rec))


def gather_bundle(s: Run, target: pathlib.Path, rec: dict) -> None:
    """A trs-test-bundle/0.1 file: its root, trust material, expected head and chain."""
    r = s.r
    if rec.get("bundle_version") != BUNDLE_VERSION:
        r.incomplete("TV-LOAD-001", f"{target.name}: unknown bundle_version "
                     f"{rec.get('bundle_version')!r}")
        return
    r.test_bundle = True
    if s.root_raw is None and not s.anchor_error:
        bundle_root(s, target, rec)
    # A bundle anchors only if it carries trust material; a
    # head-only bundle (no certificates, empty projection) is a chain.
    s.certs, s.entries = rec.get("certificates"), rec.get("registry")
    if non_object_certificates(s.certs, target, r):
        s.anchor_error = True
    refused = refused_certificate(s.certs)
    if refused is not None:
        n, e = refused
        r.fail("TV-KEY-002", f"{target.name} certificates[{n}]: child_public_key is a {e}")
        s.anchor_error = True
    if not s.certs and not s.entries and not s.args.root_key:
        s.certs = s.entries = None
        s.root_raw = None
    if s.expected_head is None and rec.get("expected_head") is not None:
        s.expected_head = rec["expected_head"]
        if not valid_sha256(s.expected_head):
            r.incomplete("TV-LOAD-003", "bundle expected_head is malformed")
            s.expected_head = None
    bchain = rec.get("chain")
    if not isinstance(bchain, list):
        r.incomplete("TV-LOAD-001", f"{target.name}: bundle `chain` is not a list")
        bchain = []
    for n, obj in enumerate(bchain):
        where = f"{target.name} chain[{n}]"
        got = as_receipt(obj, where, r)
        if got is not None:
            s.items.append((pathlib.Path(where), got))
    s.files_count = max(len(bchain), 1)


def non_object_certificates(certs, target: pathlib.Path, r: Result) -> bool:
    """INCOMPLETE for every certificates element that is not an object; True if any."""
    # Malformed trust material fails closed even beside a valid certificate, as a
    # non-object *.cert.json file does under --trust-dir.
    bad = [n for n, c in enumerate(certs if isinstance(certs, list) else []) if not isinstance(c, dict)]
    for n in bad:
        r.incomplete("TV-LOAD-002", f"{target.name} certificates[{n}]: a certificate is one "
                     "trs-cert/0.1 object")
    return bool(bad)


def bundle_root(s: Run, target: pathlib.Path, rec: dict) -> None:
    """The root a test bundle asserts for itself, used only when the caller gave none."""
    try:
        s.root_raw = raw_public_key(rec.get("trusted_root_public_key"))
        if s.root_raw is None:
            s.r.incomplete("TV-LOAD-002", f"{target.name}: bundle root key is not "
                           "canonical base64 of 32 bytes")
    except KeyRefused as e:
        s.r.fail("TV-KEY-002", f"{target.name}: bundle trusted_root_public_key is a {e}")
    s.anchor_error = s.root_raw is None


def decide_anchored(s: Run) -> None:
    """Anchored mode is on if any trust material, or an attempt at it, was supplied."""
    r = s.r
    anchored = s.root_raw is not None or s.certs is not None or s.anchor_error
    if anchored and not s.anchor_error and (s.root_raw is None or s.certs is None):
        r.incomplete("TV-LOAD-002", "anchored mode needs both a root key (--root-key) and "
                     "trust material (--trust-dir or a test bundle)")
        s.anchor_error = True
    if anchored and not HAVE_CRYPTO:
        r.incomplete("TV-SIG-010", "anchored mode needs the `cryptography` package to check "
                     "Ed25519; install it with `pip install cryptography`")
        s.anchor_error = True
    s.anchored = anchored
    r.anchored = anchored
    r.self_rooted = anchored and r.test_bundle and not s.args.root_key


def anchor_loaded(s: Run) -> None:
    """Anchored mode: keep only the receipts whose key the trust material anchors."""
    if not s.anchored:
        return
    if s.anchor_error or not s.items or not verify_projection(s.entries, s.root_raw, s.r):
        s.loaded = []
        return
    # The chain a checkpoint may apply to. A receipt whose hash does not
    # bind its payload is already FAILED (TV-HASH-004), so it cannot
    # turn a FAILED run into a pass by matching a chain_head.
    chain_heads = frozenset(
        (rec["payload"]["sequence"], rec.get("integrity_hash")) for _, rec in s.items
        if isinstance(rec.get("payload"), dict)
        and type(rec["payload"].get("sequence")) is int)
    for f, rec in list(s.loaded):
        if verify_anchored(f.name, rec, s.certs, s.entries, s.root_raw, s.r, chain_heads):
            s.r.signed += 1
            s.r.anchored_ok += 1
        else:
            s.loaded.remove((f, rec))


def evaluate_chain(s: Run, files: list) -> None:
    """Check linkage over the loaded receipts, or over every hash-bound one."""
    r = s.r
    # Linkage evaluability depends on the number of SEQUENCED participants, not
    # total files. Always let verify_chain count them so an unsequenced bystander
    # cannot turn one sequenced receipt into a claimed chain.
    if s.loaded and len(files) == len(s.loaded):
        verify_chain(s.loaded, r)
    elif (s.items and len(s.items) == s.files_count and not s.anchored
          and all(id(rec) in r.bound for _, rec in s.items)
          and not r.saw_failed):
        # Every payload is hash-bound and nothing FAILED, but some signature
        # could not be checked (INCOMPLETE). Linkage is still decidable from the
        # bound payloads, and a broken link must not hide behind an unknown.
        verify_chain(s.items, r)
