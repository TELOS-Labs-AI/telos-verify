"""Section 1 structure, section 2 value forms, and the canonical JSON encoding."""
from __future__ import annotations

import hashlib
import json
import math

from .common import (
    AG_03,
    AG_CHAIN,
    AG_REQUIRED,
    ENVELOPE,
    MAX_INT,
    PUBKEY_RE,
    RFC3339,
    SHA256_RE,
    SIG_MEMBERS,
    SIGNED_VERSIONS,
    V03_VERSION,
    VERDICTS,
    VERDICTS_03,
)


def schema_problems(receipt: dict) -> list[str]:
    """Section 1 structural rules not owned by another check (TV-SCHEMA-001)."""
    return (_envelope_problems(receipt) + _signature_block_problems(receipt)
            + _action_governed_problems(receipt))


def _envelope_problems(receipt: dict) -> list[str]:
    out = []
    missing = [m for m in ENVELOPE if m not in receipt]
    if missing:
        out.append("missing member(s) " + ", ".join(missing))
    extra = sorted(set(receipt) - set(ENVELOPE))
    if extra:
        out.append("undeclared member(s) " + ", ".join(extra))
    for m in ("kind", "agent_id", "engine"):
        if m in receipt and not isinstance(receipt[m], str):
            out.append(f"`{m}` is not a string")
    if "issued_at" in receipt and not (isinstance(receipt["issued_at"], str)
                                       and RFC3339.fullmatch(receipt["issued_at"])):
        out.append("`issued_at` is not an RFC 3339 date-time")
    if "payload" in receipt and not isinstance(receipt["payload"], dict):
        out.append("`payload` is not an object")
    return out


def _signature_block_problems(receipt: dict) -> list[str]:
    sig = receipt.get("signature")
    if not (receipt.get("receipt_version") in SIGNED_VERSIONS and isinstance(sig, dict)):
        return []
    out = []
    extra = sorted(set(sig) - set(SIG_MEMBERS))
    if extra:
        out.append("signature has undeclared member(s) " + ", ".join(extra))
    pk = sig.get("public_key")
    if "public_key" in sig and not (isinstance(pk, str) and PUBKEY_RE.fullmatch(pk)):
        out.append("signature.public_key is not canonical base64 of 32 bytes")
    kid = sig.get("key_id")
    if "key_id" in sig and not (isinstance(kid, str) and SHA256_RE.fullmatch(kid)):
        out.append("signature.key_id is not sha256: plus 64 lowercase hex digits")
    return out


def _action_governed_problems(receipt: dict) -> list[str]:
    p = receipt.get("payload")
    if not (receipt.get("kind") == "action_governed" and isinstance(p, dict)):
        return []
    admitted = set(AG_REQUIRED) | set(AG_CHAIN)
    if receipt.get("receipt_version") == V03_VERSION:
        admitted |= set(AG_03)
    return _ag_member_problems(p, admitted) + _ag_value_problems(p)


def _ag_member_problems(p: dict, admitted: set) -> list[str]:
    out = []
    missing = [m for m in AG_REQUIRED if m not in p]
    if missing:
        out.append("action_governed payload lacks " + ", ".join(missing))
    extra = sorted(set(p) - admitted)
    # TRS-S1-026: scope_id, when admitted and present, is a non-empty string.
    if "scope_id" in admitted and "scope_id" in p and not (
            isinstance(p["scope_id"], str) and p["scope_id"]):
        out.append("payload `scope_id` is not a non-empty string")
    if extra:
        out.append("action_governed payload has undeclared member(s) " + ", ".join(extra))
    return out


def _ag_value_problems(p: dict) -> list[str]:
    out = []
    for m in ("action_name", "pa_id"):
        if m in p and not isinstance(p[m], str):
            out.append(f"payload `{m}` is not a string")
    aph = p.get("action_params_hash")
    if "action_params_hash" in p and not (isinstance(aph, str) and SHA256_RE.fullmatch(aph)):
        out.append("payload `action_params_hash` is not sha256: plus 64 lowercase hex digits")
    return out


def is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def scoring_problems(receipt: dict) -> list[tuple[str, str]]:
    """Section 2 value forms of the scoring fields, when present."""
    p = receipt.get("payload")
    if receipt.get("kind") != "action_governed" or not isinstance(p, dict):
        return []
    out = []
    v03 = receipt.get("receipt_version") == V03_VERSION
    # The vocabulary is chosen by contract: a historical label is accepted only
    # as recorded on 0.1/0.2, and a 0.3 receipt carries the noun labels only.
    vocab = VERDICTS_03 if v03 else VERDICTS
    if "verdict" in p and p["verdict"] not in vocab:
        out.append(("TV-S2-002", (f"verdict is not in the public vocabulary of "
                                  f"{receipt.get('receipt_version')}: {p['verdict']!r}")))
    if "composite_score" in p and not is_number(p["composite_score"]):
        out.append(("TV-S2-003", ("composite_score is not a number: "
                                  f"{type(p['composite_score']).__name__}")))
    out += _scores_problems(p)
    if p.get("pa_id") == "":
        out.append(("TV-S2-006", "pa_id is empty"))
    if v03:
        out += scoring_problems_03(p)
    return out


def _scores_problems(p: dict) -> list[tuple[str, str]]:
    scores = p.get("scores")
    if "scores" in p and not isinstance(scores, dict):
        return [("TV-S2-004", "scores value is not a number: `scores` is not an object")]
    out = []
    if isinstance(scores, dict):
        if any(not is_number(v) for v in scores.values()):
            out.append(("TV-S2-004", "scores value is not a number"))
        if any(k == "" for k in scores):
            out.append(("TV-S2-005", "scores label is empty"))
    return out


def in_unit_range(v) -> bool:
    return 0 <= v <= 1


def scoring_problems_03(p: dict) -> list[tuple[str, str]]:
    """Section 2 rules that apply to telos/0.3-ed25519 only (TRS-S2-010..012).

    Historical contracts keep the type-only score rule, so this is never
    applied to them: an older receipt does not fail for its range.
    """
    out = []
    cs = p.get("composite_score")
    if is_number(cs) and not in_unit_range(cs):
        out.append(("TV-S2-010", f"composite_score is outside [0, 1]: {cs!r}"))
    scores = p.get("scores")
    if isinstance(scores, dict) and any(is_number(v) and not in_unit_range(v)
                                        for v in scores.values()):
        out.append(("TV-S2-010", "scores value is outside [0, 1]"))
    # One guard per member: absence and wrong form are the same defect.
    if not isinstance(p.get("boundary_flag"), bool):
        out.append(("TV-S2-011", "boundary_flag is absent or not a boolean"))
    if not isinstance(p.get("specification_version"), str):
        out.append(("TV-S2-012", "specification_version is absent or not a string"))
    och = p.get("observation_config_hash")
    if not (isinstance(och, str) and SHA256_RE.fullmatch(och)):
        out.append(("TV-S2-012", ("observation_config_hash is absent or not sha256: plus 64 "
                                  "lowercase hex digits")))
    if "profile_id" in p and not isinstance(p["profile_id"], str):
        out.append(("TV-S2-012", "profile_id is not a string"))
    return out


def canon_problems(v, where="payload") -> list[tuple[str, str]]:
    """Numbers and strings outside the canonical domain (TRS-S1-013, TRS-S1-014).

    Python parses a token with a fraction or exponent as float and any other
    number as int, which is exactly the integer-token / other-token split the
    standard draws, so the walk needs no access to the raw text.
    """
    if isinstance(v, bool) or v is None:
        return []
    if isinstance(v, int):
        return _canon_int(v, where)
    if isinstance(v, float):
        return _canon_float(v, where)
    if isinstance(v, str):
        return _canon_str(v, where)
    if isinstance(v, list):
        return [x for i, item in enumerate(v) for x in canon_problems(item, f"{where}[{i}]")]
    if isinstance(v, dict):
        return _canon_dict(v, where)
    return []


def _canon_int(v: int, where: str) -> list[tuple[str, str]]:
    if abs(v) > MAX_INT:
        return [("TV-CANON-001", (f"{where}: number outside the canonical number domain "
                                  f"(integer beyond 2^53-1)"))]
    return []


def _canon_float(v: float, where: str) -> list[tuple[str, str]]:
    if v == 0.0 and math.copysign(1.0, v) < 0:
        return [("TV-CANON-001", f"{where}: number outside the canonical number domain (-0)")]
    if v != 0.0 and not (1e-4 <= abs(v) < 1e16):
        return [("TV-CANON-001", (f"{where}: number outside the canonical number domain "
                                  f"({v!r})"))]
    return []


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _canon_str(v: str, where: str) -> list[tuple[str, str]]:
    if _has_surrogate(v):
        return [("TV-CANON-002", f"{where}: string contains an unpaired surrogate")]
    return []


def _canon_dict(v: dict, where: str) -> list[tuple[str, str]]:
    out = []
    for k, x in v.items():
        if _has_surrogate(k):
            out.append(("TV-CANON-002", f"{where}: key contains an unpaired surrogate"))
        out += canon_problems(x, f"{where}.{k}")
    return out


def canonical_bytes(payload) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def compute_hash(payload) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def valid_sha256(value) -> bool:
    """Whether value is the exact digest spelling this tool emits."""
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(c in "0123456789abcdef" for c in value[7:])
    )


def without(obj: dict, *names) -> dict:
    return {k: v for k, v in obj.items() if k not in names}
