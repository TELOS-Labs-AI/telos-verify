"""Anchored mode (section 4): projection, certificates, checkpoint ordering.

An offline root key certifies deployment keys, and every key lifecycle event is
a root-signed, hash-linked entry in the Lineage Chain public projection. The
root key comes from the caller (--root-key); it is never taken from the material
being verified, except from a section 4.11 TEST bundle, which the output then
labels as not a trust anchor.
"""
from __future__ import annotations

from .common import (
    CERT_COVERS,
    CERT_MEMBERS,
    CERT_VERSION,
    CHECKPOINT_EVENT,
    CHECKPOINT_MEMBERS,
    ENTRY_COVERS,
    ENTRY_MEMBERS,
    ENTRY_VERSION,
    KEY_EVENTS,
    SHA256_RE,
    SIG_ALGORITHM,
    SIG_COVERS,
    SIGNED_VERSION,
    SIGNED_VERSIONS,
    V03_VERSION,
)
from .keys import ed25519_ok, key_id, raw_public_key
from .result import Result
from .schema import compute_hash, without


def verify_projection(entries, root_raw: bytes, r: Result) -> bool:
    """TRS-S4-018/-021, -023, -014, -015, in that order (section 4.10 step 1).

    A projection entry is a key-event entry (Table 7) or a checkpoint entry
    (Table 8), told apart by event_type. A broken projection is never used.
    Checkpoints are parsed and member-checked here; the ordering they decide
    (TRS-S4-022) is applied per receipt in place_receipt.
    """
    root_kid = key_id(root_raw)
    if not isinstance(entries, list):
        r.fail("TV-REGISTRY-001", "registry projection link is broken: the projection is not a list")
        return False
    if not _projection_members(entries, r):
        return False

    # TRS-S4-023: sequence 0 continues the issuer's key-lineage record, so its
    # parent_hash is that record's head, never null. Only the form is checkable.
    anchor = entries[0]["parent_hash"] if entries else None
    if entries and not (isinstance(anchor, str) and SHA256_RE.fullmatch(anchor)):
        r.fail("TV-REGISTRY-004", f"projection entry 0: first projection entry has no lineage "
               f"anchor: parent_hash {anchor!r} is not sha256: plus 64 lowercase hex digits")
        return False

    if not _projection_links(entries, anchor, r):
        return False

    for i, e in enumerate(entries):
        if e["root_key_id"] != root_kid or not ed25519_ok(root_raw, e["root_signature"],
                                                          ENTRY_COVERS, e["this_hash"]):
            r.fail("TV-REGISTRY-002", f"projection entry {i}: registry entry does not verify "
                   f"under the root key {root_kid[:23]}...")
            return False
    r.note(f"ok    PROJECTION CHECKED: {len(entries)} Lineage Chain entr(ies), hash-linked from "
           "sequence 0, each root-signed")
    return True


def _projection_members(entries: list, r: Result) -> bool:
    """TRS-S4-018/-021: every entry is an object with exactly its table's members."""
    ok = True
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            r.fail("TV-REGISTRY-003", f"projection entry {i}: registry entry has an undeclared "
                   "member set: it is not an object")
            ok = False
            continue
        etype = e.get("event_type")
        if etype not in KEY_EVENTS and etype != CHECKPOINT_EVENT:
            r.fail("TV-REGISTRY-003", f"projection entry {i}: registry entry has an undeclared "
                   f"member set: event_type {etype!r} is not a key event or a checkpoint")
            ok = False
            continue
        if not _entry_members(i, e, etype, r):
            ok = False
    return ok


def _entry_members(i: int, e: dict, etype, r: Result) -> bool:
    table = CHECKPOINT_MEMBERS if etype == CHECKPOINT_EVENT else ENTRY_MEMBERS
    extra = sorted(set(e) - set(table))
    missing = [m for m in table if m not in e]
    ok = True
    if extra:
        r.fail("TV-REGISTRY-003", f"projection entry {i}: registry entry has an undeclared "
               "member: " + ", ".join(extra))
        ok = False
    if missing:
        r.fail("TV-REGISTRY-003", f"projection entry {i}: registry entry lacks member(s) "
               + ", ".join(missing))
        ok = False
    elif e.get("entry_version") != ENTRY_VERSION:
        r.fail("TV-REGISTRY-003", f"projection entry {i}: entry_version is "
               f"{e.get('entry_version')!r}, not {ENTRY_VERSION!r}")
        ok = False
    return ok


def _projection_links(entries: list, anchor, r: Result) -> bool:
    """TRS-S4-014: contiguous sequences, each entry linked to the one before it."""
    prev = anchor
    for i, e in enumerate(entries):
        why = _link_problem(i, e, prev)
        if why:
            r.fail("TV-REGISTRY-001", f"projection entry {i}: registry projection link is broken: {why}")
            return False
        prev = e["this_hash"]
    return True


def _link_problem(i: int, e: dict, prev):
    try:
        recomputed = compute_hash(without(e, "this_hash", "root_signature"))
    except (TypeError, ValueError):
        recomputed = None
    if type(e["sequence"]) is not int or e["sequence"] != i:
        return f"sequence {e['sequence']!r} where {i} is required"
    if e["parent_hash"] != prev:
        return f"parent_hash {e['parent_hash']!r} where {prev!r} is required"
    if e["this_hash"] != recomputed:
        return "this_hash does not match the entry's canonical bytes"
    return None


def place_receipt(rec: dict, kid: str, entries, chain_heads) -> tuple[str, dict | None]:
    """Section 4.9: place one receipt against every rotate/revoke entry for its key.

    Returns ("pass", None), ("after", E) or ("undecided", E). Only projection
    position is used: timestamp, effective_at and issued_at are never read.
    `chain_heads` holds (sequence, integrity_hash) of the hash-bound receipts of
    the chain under verification. FAILED ("after") outranks "undecided".
    """
    p = rec.get("payload")
    s = p.get("sequence") if isinstance(p, dict) else None
    verdict, where = "pass", None
    for ev in entries:
        if ev["event_type"] not in ("child_key_rotate", "child_key_revoke") or ev["child_key_id"] != kid:
            continue
        c = _last_checkpoint_before(entries, kid, ev)
        applies = (c is not None and type(s) is int
                   and (c["chain_sequence"], c["chain_head"]) in chain_heads)
        if applies and s <= c["chain_sequence"]:
            continue                                    # R precedes E
        if applies and c["sequence"] == ev["sequence"] - 1:
            return "after", ev                          # closing checkpoint: R follows E
        if verdict == "pass":
            verdict, where = "undecided", ev
    return verdict, where


def _last_checkpoint_before(entries, kid: str, ev: dict):
    """The highest-positioned checkpoint for `kid` below entry `ev`, or None."""
    below = [c for c in entries if c["event_type"] == CHECKPOINT_EVENT
             and c["child_key_id"] == kid and c["sequence"] < ev["sequence"]]
    return max(below, key=lambda e: e["sequence"]) if below else None


def verify_anchored(name: str, rec: dict, certs, entries, root_raw: bytes, r: Result,
                    chain_heads=frozenset()) -> bool:
    """TRS-S4-010, -011, -012, -016, -013, -017 for one receipt (section 4.10)."""
    root_kid = key_id(root_raw)
    sig = rec.get("signature")
    kid = sig.get("key_id") if isinstance(sig, dict) else None
    if rec.get("receipt_version") not in SIGNED_VERSIONS or not isinstance(kid, str):
        r.fail("TV-ANCHOR-001", f"{name}: anchored receipt has no key_id; anchored mode requires "
               f"{V03_VERSION!r} or {SIGNED_VERSION!r} with signature.key_id")
        return False

    certified = _certificate(name, kid, certs, root_raw, root_kid, r)
    if certified is None:
        return False
    cert, chash = certified
    if not _certified_use(name, rec, sig, cert, r):
        return False

    issued = [e for e in entries if e["event_type"] == "child_key_issue"
              and e["child_key_id"] == kid and e["certificate_hash"] == chash]
    if not issued:
        r.fail("TV-TRUST-004", f"{name}: no issuance entry in the Lineage Chain registry for this "
               "certificate; a valid root signature alone is not sufficient")
        return False

    if not _placed(name, rec, kid, cert, entries, chain_heads, r):
        return False

    if r.self_rooted:
        r.note(f"ok    {name}  SELF-ROOTED, NOT ANCHORED: signature verifies under key "
               f"{kid[:23]}... named by a bundle certificate; that certificate verifies under "
               f"the root the bundle asserts for itself ({root_kid[:23]}...); issuance logged "
               f"at projection entry {issued[0]['sequence']}; placed before every rotate/revoke entry")
        return True
    r.note(f"ok    {name}  ANCHORED: signature verifies under certified key {kid[:23]}...; "
           f"certificate verifies under root {root_kid[:23]}...; issuance logged at projection "
           f"entry {issued[0]['sequence']}; placed before every rotate/revoke entry")
    return True


def _placed(name: str, rec: dict, kid: str, cert: dict, entries, chain_heads, r: Result) -> bool:
    """Section 4.9: whether the signature is placed before every rotate/revoke entry."""
    # Section 4.9: placed by projection order only, through root-signed checkpoints.
    placed, ev = place_receipt(rec, kid, entries, chain_heads)
    if placed == "after":
        r.fail("TV-ANCHOR-006", f"{name}: a closing checkpoint places the receipt after the key's "
               f"{ev['event_type']} entry (projection entry {ev['sequence']})")
        return False
    if placed == "undecided" or cert.get("valid_until") is not None:
        what = (f"a {ev['event_type']} entry (projection entry {ev['sequence']}) that no "
                "applicable checkpoint orders it against" if placed == "undecided"
                else "a non-null valid_until, which no checkpoint can decide")
        r.incomplete("TV-ANCHOR-003", f"{name}: the signature cannot be placed relative to the "
                     f"key's effective time: the key has {what}; the receipt carries no covered "
                     "signing time, and timestamps are not used")
        return False

    return True


def _certificate(name: str, kid: str, certs, root_raw: bytes, root_kid: str, r: Result):
    """(certificate, certificate hash) for the first certificate naming `kid`, or None."""
    matches = [c for c in (certs if isinstance(certs, list) else [])
               if isinstance(c, dict) and c.get("child_key_id") == kid]
    if not matches:
        r.incomplete("TV-TRUST-002", f"{name}: no deployment certificate names key {kid[:23]}..., "
                     "so the key cannot be anchored")
        return None
    cert = matches[0]

    shape_ok = (sorted(cert) == sorted(CERT_MEMBERS) and cert.get("cert_version") == CERT_VERSION
                and cert.get("algorithm") == SIG_ALGORITHM)
    try:
        chash = compute_hash(without(cert, "root_signature"))
    except (TypeError, ValueError):
        chash = None
    if not (shape_ok and chash and cert.get("root_key_id") == root_kid
            and ed25519_ok(root_raw, cert.get("root_signature"), CERT_COVERS, chash)):
        r.fail("TV-TRUST-001", f"{name}: deployment certificate does not verify under the root key "
               f"{root_kid[:23]}...")
        return None
    return cert, chash


def _certified_use(name: str, rec: dict, sig, cert: dict, r: Result) -> bool:
    """TRS-S4-011, -012, -019/-020: certified key, receipt_signing purpose, matching scope."""
    # Every certificate key was admitted when the trust material was loaded.
    child_raw = raw_public_key(cert.get("child_public_key"))
    if (child_raw is None or key_id(child_raw) != cert["child_key_id"]
            or not ed25519_ok(child_raw, sig, SIG_COVERS, rec.get("integrity_hash"))):
        r.fail("TV-TRUST-003", f"{name}: receipt key is not the certified deployment key: the "
               "signature does not verify under the certified child_public_key, or that key "
               "does not match child_key_id")
        return False

    if cert.get("purpose") != "receipt_signing":
        r.fail("TV-ANCHOR-002", f"{name}: certificate purpose is not receipt_signing "
               f"({cert.get('purpose')!r})")
        return False

    # TRS-S4-019/-020: a 0.3 receipt names its scope, and it must be the scope
    # the selected certificate was issued for. 0.2 carries no covered scope.
    if rec.get("receipt_version") == V03_VERSION:
        payload = rec.get("payload")
        if not (isinstance(payload, dict) and "scope_id" in payload):
            r.fail("TV-ANCHOR-004", f"{name}: anchored telos/0.3 receipt has no scope_id")
            return False
        if payload["scope_id"] != cert.get("scope_id"):
            r.fail("TV-ANCHOR-005", f"{name}: receipt scope_id differs from the certificate's "
                   f"({payload['scope_id']!r} vs {cert.get('scope_id')!r})")
            return False
    return True
