"""One receipt: structure, hash, canonical domain, signature."""
from __future__ import annotations

import base64
import binascii
import pathlib

from .common import (
    COVERED,
    KNOWN_VERSION,
    KNOWN_VERSIONS,
    SIG_ALGORITHM,
    SIG_COVERS,
    SIGNED_STATUS,
    SIGNED_VERSION,
    UNSIGNED_STATUS,
)
from .keys import HAVE_CRYPTO, key_id, verifies
from .result import Result
from .schema import (
    canon_problems,
    compute_hash,
    schema_problems,
    scoring_problems,
    valid_sha256,
)


def check_signature(name: str, receipt: dict, sig: dict, keys, r: Result) -> bool:
    """Check an Ed25519 signature against keys the CALLER trusts. True if it verified.

    The key carried inside the receipt is used only to explain a mismatch. It is
    never treated as authority: whoever can forge a receipt can forge the key
    printed on it. `keys=None` means anchored mode: only the form of the block
    is checked here, and the anchored step verifies against the certified key.
    """
    raw_sig = _signature_form(name, sig, r)
    if raw_sig is None:
        return False
    if keys is None:
        return True
    if not _can_check(name, keys, r):
        return False

    message = receipt["integrity_hash"].encode("ascii")
    for kid, pub in keys:
        if verifies(pub, raw_sig, message):
            return _verified_under(name, sig, kid, r)
    _explain_mismatch(name, sig, keys, r)
    return False


def _signature_form(name: str, sig: dict, r: Result):
    """The 64 signature bytes if the block declares what this tool checks, else None."""
    alg = sig.get("algorithm")
    if alg != SIG_ALGORITHM:
        r.incomplete("TV-SIG-003", f"{name}: signature algorithm is {alg!r}; this tool only checks {SIG_ALGORITHM!r}")
        return None

    covers = sig.get("covers")
    if covers != SIG_COVERS:
        r.incomplete("TV-SIG-004", f"{name}: signature covers {covers!r}; this tool only verifies {SIG_COVERS!r}")
        return None

    return signature_bytes(name, sig, r)


def _can_check(name: str, keys, r: Result) -> bool:
    """Whether Ed25519 can be checked and the caller supplied a key to check it under."""
    if not HAVE_CRYPTO:
        r.incomplete(
            "TV-SIG-010",
            f"{name}: receipt is signed, but the `cryptography` package is not "
            "installed, so this tool cannot check Ed25519. PAYLOAD-TO-HASH "
            "BINDING established; signature NOT checked. Install it with "
            "`pip install cryptography` and run again."
        )
        return False

    if not keys:
        r.incomplete(
            "TV-OFFLINE-001",
            f"{name}: receipt carries a signature, but you supplied no trusted "
            "public key (--key). The key printed on a receipt is not a trust "
            "anchor, and this tool fetches nothing. PAYLOAD-TO-HASH BINDING "
            "established; signature NOT checked."
        )
        return False
    return True


def _verified_under(name: str, sig: dict, kid: str, r: Result) -> bool:
    """The signature verified under `kid`; True unless the receipt names another key."""
    claimed_kid = sig.get("key_id")
    if claimed_kid is not None and claimed_kid != kid:
        r.fail("TV-SIG-009", f"{name}: key_id does not name the verifying key: the signature "
               f"verifies under {kid[:23]}..., but the receipt names {str(claimed_kid)[:23]}...")
        return False
    r.note(f"ok    {name}  SIGNATURE CHECKED: Ed25519 signature verifies "
           f"under caller-supplied key {kid[:23]}...")
    return True


def _explain_mismatch(name: str, sig: dict, keys, r: Result) -> None:
    """FAIL a signature that verified under no supplied key, naming what the receipt claims."""
    claimed = None
    pk = sig.get("public_key")
    if isinstance(pk, str):
        try:
            claimed = key_id(base64.b64decode(pk, validate=True))
        except (binascii.Error, ValueError):
            claimed = None
    if claimed is None and isinstance(sig.get("key_id"), str):
        claimed = sig["key_id"]
    trusted = {k for k, _ in keys}
    if claimed is not None and claimed not in trusted:
        r.fail("TV-SIG-006", f"{name}: signature does not verify under any key you supplied; "
               f"the receipt names {claimed[:23]}..., which is not a key you trust")
    else:
        r.fail("TV-SIG-007", f"{name}: signature does not verify under any key you supplied")
    if isinstance(pk, str) and claimed is None:
        r.note("        the key printed on the receipt is not valid base64")
    elif claimed is not None and claimed in trusted:
        r.note("        the receipt names a key you supplied, but its signature value "
               "does not verify for that key and integrity hash")


def signature_bytes(name: str, sig: dict, r: Result):
    """The 64 signature bytes, or None after a TV-SIG-005 FAIL line.

    Canonical padded base64 only: a value whose unused trailing bits are set
    decodes to the same bytes but is a second spelling of one signature.
    """
    value = sig.get("value")
    if not isinstance(value, str):
        r.fail("TV-SIG-005", f"{name}: signature block has no `value`; an Ed25519 signature is 64 bytes")
        return None
    try:
        raw_sig = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        r.fail("TV-SIG-005", f"{name}: signature value is not valid base64; an Ed25519 signature is 64 bytes")
        return None
    if len(raw_sig) != 64:
        r.fail("TV-SIG-005", f"{name}: signature is {len(raw_sig)} bytes; an Ed25519 signature is 64")
        return None
    if base64.b64encode(raw_sig).decode("ascii") != value:
        r.fail("TV-SIG-005", f"{name}: signature value is not canonical base64; an Ed25519 "
               "signature is 64 bytes in canonical padded base64")
        return None
    return raw_sig


def verify_one(path: pathlib.Path, receipt: dict, r: Result, keys=()) -> bool:
    """Check a single receipt: structure, hash, canonical domain, signature.

    True if every check that applies to this receipt passed. `keys=None` means
    anchored mode (the signature is verified later against the certified key).
    """
    name = path.name

    version = receipt.get("receipt_version")
    if version not in KNOWN_VERSIONS:
        r.incomplete(
            "TV-VER-001",
            f"{name}: unknown receipt_version {version!r}; this tool knows "
            + " and ".join(repr(v) for v in KNOWN_VERSIONS)
        )
        return False

    ok = _structure_ok(name, receipt, r)
    if not _hash_binds(name, receipt, r):
        return False
    r.bound.add(id(receipt))

    # Signature posture, stated plainly and never skipped silently.
    status = receipt.get("signing_status")
    sig = receipt.get("signature")

    if version == KNOWN_VERSION:
        return _unsigned_posture(name, status, sig, ok, r)

    # Report only the relationship actually checked. A later signature
    # failure does not show that every envelope byte is intact or identify
    # who authored the record.
    r.note(f"ok    {name}  PAYLOAD-TO-HASH BINDING: recorded hash matches "
           "canonical JSON of supplied payload")
    if status != SIGNED_STATUS or not isinstance(sig, dict):
        r.incomplete(
            "TV-SIG-002",
            f"{name}: {version!r} requires signing_status {SIGNED_STATUS!r} and a "
            f"signature object; got signing_status={status!r}, signature={type(sig).__name__}"
        )
        return False
    if not check_signature(name, receipt, sig, keys, r):
        return False
    if keys is None:
        return ok  # anchored mode counts it once the certified key verifies
    if ok:
        r.signed += 1
    return ok


def _structure_ok(name: str, receipt: dict, r: Result) -> bool:
    """Section 1 structure and section 2 value forms; FAIL lines for each problem."""
    ok = True
    problems = schema_problems(receipt)
    if problems:
        r.fail("TV-SCHEMA-001", f"{name}: does not conform to the receipt schema: "
               + "; ".join(problems))
        ok = False
    for check, msg in scoring_problems(receipt):
        r.fail(check, f"{name}: {msg}")
        ok = False
    return ok


def _hash_binds(name: str, receipt: dict, r: Result) -> bool:
    """Whether the recorded integrity hash binds the supplied payload."""
    if "payload" not in receipt:
        r.fail("TV-HASH-001", f"{name}: no payload to hash")
        return False

    recorded = receipt.get("integrity_hash")
    if not valid_sha256(recorded):
        r.fail("TV-HASH-002", f"{name}: missing or malformed integrity_hash; expected sha256: "
               "followed by exactly 64 lowercase hexadecimal characters")
        return False

    covered = receipt.get("covered_fields")
    if covered != COVERED:
        # The receipt claims the hash covers something other than what this tool
        # recomputes. Refuse rather than compare the wrong bytes and call it a pass.
        r.incomplete("TV-HASH-003", f"{name}: covered_fields is {covered!r}; this tool only recomputes {COVERED!r}")
        return False

    try:
        actual = compute_hash(receipt["payload"])
    except (TypeError, ValueError) as e:
        r.incomplete("TV-HASH-005", f"{name}: payload has no canonical JSON form: {e}")
        return False

    domain = canon_problems(receipt["payload"])
    for check, msg in domain:
        r.fail(check, f"{name}: {msg}")
    if domain:
        return False

    if actual != recorded:
        r.fail("TV-HASH-004", f"{name}: payload does not match recorded hash")
        r.note(f"        recorded  {recorded}")
        r.note(f"        recomputed {actual}")
        return False
    return True


def _unsigned_posture(name: str, status, sig, ok: bool, r: Result) -> bool:
    """The telos/0.1-unsigned signing state, which defines `signature` as null."""
    # A signature on this version is a shape this tool does not know, so it
    # declines to judge it rather than verify bytes under a contract that does
    # not describe them.
    if status == UNSIGNED_STATUS and sig is None:
        if ok:
            r.unsigned += 1
    elif sig is not None:
        r.incomplete(
            "TV-SIG-001",
            f"{name}: receipt_version {KNOWN_VERSION!r} defines `signature` as null, "
            f"but this receipt carries one. PAYLOAD-TO-HASH BINDING established; signature NOT "
            f"checked. A signed receipt should declare {SIGNED_VERSION!r}."
        )
        return False
    else:
        r.incomplete("TV-SIG-001", f"{name}: inconsistent signing state (signing_status={status!r}, signature present={sig is not None})")
        return False

    if ok:
        r.note(f"ok    {name}  PAYLOAD-TO-HASH BINDING: recorded hash matches "
               "canonical JSON of supplied payload")
    return ok
