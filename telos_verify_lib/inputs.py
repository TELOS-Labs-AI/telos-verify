"""Reading receipts, JSON Lines chain files and S3 trust directories."""
from __future__ import annotations

import json
import pathlib

from .common import AG_CHAIN
from .keys import refused_certificate
from .result import Result


# JSON null is data, not a parse-failure sentinel.
_UNUSABLE = object()


class DuplicateKey(ValueError):
    """A JSON object carried the same member name twice."""


def no_duplicate_keys(pairs):
    """Refuse a JSON object that repeats a member name.

    JSON does not forbid duplicate names, and parsers disagree about which one
    wins: Python keeps the LAST, while a human reading the file top to bottom
    takes the FIRST. That disagreement is a forgery primitive here. A receipt
    carrying `payload` twice shows an auditor one payload while the verifier
    hashes and signature-checks the other, and the tool would print VERIFIED
    over bytes nobody saw.

    Since this tool exists so that a person can be confident about what a file
    says, a file that says two things is refused rather than silently resolved.
    Applied recursively: json passes every object through this hook.
    """
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise DuplicateKey(f"duplicate key {k!r}")
        seen.add(k)
    return dict(pairs)


def parse_json_text(text: str, where: str, r: Result):
    """Parse one JSON document; return _UNUSABLE with a diagnostic on failure."""
    try:
        return json.loads(text, object_pairs_hook=no_duplicate_keys)
    except DuplicateKey as e:
        r.incomplete(
            "TV-PARSE-001",
            f"{where}: refused, {e}. A file that repeats a member name shows one "
            "thing to a reader and another to a parser, so nothing about it can "
            "be verified honestly."
        )
    except json.JSONDecodeError as e:
        r.incomplete("TV-LOAD-001", f"{where}: not valid JSON: {e}")
    except ValueError as e:
        # Belt and braces: any other parse-layer ValueError is an unknown, not a pass.
        r.incomplete("TV-LOAD-001", f"{where}: could not be parsed: {e}")
    return _UNUSABLE


def as_receipt(obj, where: str, r: Result):
    # A receipt is an object. Anything else is not a receipt, and asking it for
    # fields would raise. INCOMPLETE is the honest verdict, and returning None
    # here keeps one crafted file from aborting a whole directory run.
    if obj is _UNUSABLE:
        return None
    if not isinstance(obj, dict):
        r.incomplete(
            "TV-PARSE-002",
            f"{where}: top-level JSON is {type(obj).__name__}, not an object; "
            "this is not a receipt"
        )
        return None
    return obj


def read_text(path: pathlib.Path, r: Result):
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        r.incomplete("TV-LOAD-001", f"{path}: no such file")
    except (OSError, UnicodeError) as e:
        r.incomplete("TV-LOAD-001", f"{path}: unreadable: {e}")
    return None


def load(path: pathlib.Path, r: Result):
    text = read_text(path, r)
    if text is None:
        return None
    return as_receipt(parse_json_text(text, str(path), r), str(path), r)


def load_chain_file(path: pathlib.Path, r: Result):
    """Read a JSON Lines chain file (section 4.4). None if it cannot be used.

    Order is part of the format: lines must already be in ascending `sequence`
    order. The file is never sorted silently.
    """
    text = read_text(path, r)
    if text is None:
        return None
    if not text:
        r.fail("TV-CHAIN-006", f"{path.name}: chain file is empty")
        return None
    if not text.endswith("\n"):
        r.fail("TV-CHAIN-006", f"{path.name}: chain file's last line is not LF-terminated")
        return None
    out = _chain_lines(path, text, r)
    if out is None:
        return None
    seqs = [rec["payload"].get("sequence") for _, rec in out]
    if all(type(s) is int for s in seqs):
        for i in range(1, len(seqs)):
            if seqs[i] < seqs[i - 1]:
                r.fail("TV-CHAIN-006",
                       f"{out[i][0]}: chain file is not in sequence order "
                       f"(sequence {seqs[i]} follows {seqs[i - 1]}); it is not re-sorted")
                return None
    return out


def _chain_lines(path: pathlib.Path, text: str, r: Result):
    """Every line of a chain file as (label, receipt), or None if any line is unusable."""
    out, ok = [], True
    for n, line in enumerate(text[:-1].split("\n"), 1):
        where = f"{path.name} line {n}"
        if line.strip() == "":
            r.fail("TV-CHAIN-006", f"{where}: chain file contains a blank line")
            ok = False
            continue
        rec = as_receipt(parse_json_text(line, where, r), where, r)
        if rec is None:
            ok = False
            continue
        p = rec.get("payload")
        if not (isinstance(p, dict) and ("sequence" in p or AG_CHAIN[1] in p)):
            r.fail("TV-CHAIN-006", f"{where}: chain file line is not a chained receipt")
            ok = False
            continue
        out.append((pathlib.Path(where), rec))
    return out if ok else None


def load_trust_dir(tdir: pathlib.Path, r: Result):
    """Read an S3 3.2 trust directory: (certificates, projection entries), or (None, None).

    One trs-cert/0.1 object per `*.cert.json` file (read in name order), and the
    Lineage Chain public projection as `projection.jsonl`, one entry per line in
    sequence order. Any unusable file refuses the whole directory: trust material
    is never partially loaded.
    """
    if not tdir.is_dir():
        r.incomplete("TV-LOAD-002", f"--trust-dir {tdir}: not a directory")
        return None, None
    proj = tdir / "projection.jsonl"
    if not proj.is_file():
        r.incomplete("TV-LOAD-002", f"--trust-dir {tdir}: no projection.jsonl (S3 3.2 layout: "
                     "*.cert.json files plus projection.jsonl)")
        return None, None
    certs = _trust_certificates(tdir, r)
    if certs is None:
        return None, None
    entries = _trust_projection(proj, r)
    if entries is None:
        return None, None
    return certs, entries


def _trust_certificates(tdir: pathlib.Path, r: Result):
    """Every *.cert.json object, each child key admitted, or None."""
    certs, names = [], []
    for f in sorted(tdir.glob("*.cert.json")):
        text = read_text(f, r)
        if text is None:
            return None
        c = parse_json_text(text, f.name, r)
        if not isinstance(c, dict):
            r.incomplete("TV-LOAD-002", f"--trust-dir {f.name}: a *.cert.json file holds "
                         "one trs-cert/0.1 object")
            return None
        certs.append(c)
        names.append(f.name)
    refused = refused_certificate(certs)
    if refused is not None:
        n, e = refused
        r.fail("TV-KEY-002", f"--trust-dir {names[n]}: certificate child_public_key is a {e}")
        return None
    return certs


def _trust_projection(proj: pathlib.Path, r: Result):
    """The projection.jsonl entries in file order, or None."""
    text = read_text(proj, r)
    if text is None:
        return None
    if text and not text.endswith("\n"):
        r.incomplete("TV-LOAD-002", f"--trust-dir {proj.name}: last line is not LF-terminated")
        return None
    entries = []
    for n, line in enumerate(text[:-1].split("\n") if text else [], 1):
        where = f"{proj.name} line {n}"
        if line.strip() == "":
            r.incomplete("TV-LOAD-002", f"--trust-dir {where}: projection contains a blank line")
            return None
        e = parse_json_text(line, where, r)
        if not isinstance(e, dict):
            r.incomplete("TV-LOAD-002", f"--trust-dir {where}: a projection line holds one "
                         "trs-lineage-projection/0.1 object")
            return None
        entries.append(e)
    return entries
