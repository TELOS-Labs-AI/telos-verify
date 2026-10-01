"""Contract constants and the check registry (TELOS Receipt Standard v0.1)."""
from __future__ import annotations

import re

VERIFIED, FAILED, INCOMPLETE = 0, 1, 2

# The contract versions this tool understands. A receipt announcing anything
# else is INCOMPLETE rather than FAILED: we decline to judge what we do not know.
KNOWN_VERSION = "telos/0.1-unsigned"
SIGNED_VERSION = "telos/0.2-ed25519"
# telos/0.3-ed25519 keeps the envelope, canonical bytes and signature block of
# 0.2 and adds covered observation members to action_governed (Section 2).
V03_VERSION = "telos/0.3-ed25519"
SIGNED_VERSIONS = (SIGNED_VERSION, V03_VERSION)
KNOWN_VERSIONS = (KNOWN_VERSION, SIGNED_VERSION, V03_VERSION)
UNSIGNED_STATUS = "unsigned_integrity_hash"
SIGNED_STATUS = "ed25519_signed"

# What the signature block must declare about itself, checked strictly for the
# same reason `covered_fields` is: if the receipt says the signature covers
# something other than what this tool verifies, we refuse rather than compare
# the wrong bytes and call it a pass.
SIG_ALGORITHM = "ed25519"
SIG_COVERS = "integrity_hash (ASCII bytes of the sha256: string)"

# Exactly what the receipt's own `covered_fields` declares, and what the
# published schema documents. Canonical JSON over `payload`: sorted keys,
# compact separators, ensure_ascii escaping, UTF-8 bytes.
COVERED = "payload (canonical JSON, sort_keys, compact separators)"

# Check registry: TELOS Receipt Standard v0.1, section 3.6. Every FAIL and
# INCOMPLETE line carries one of these ids in brackets, and `--list-checks`
# prints them, so a traceability tool can tie each requirement of the standard
# to the check that enforces it. Ids are stable: never renumbered or reused.
# TV-LOAD-001..003, TV-SIG-010 and TV-HEAD-002 name input and environment
# failures; section 3.6 lists them with the other checks.
CHECKS = {
    "TV-OFFLINE-001": ("INCOMPLETE", "signed receipt and no caller-supplied trusted key; nothing is fetched"),
    "TV-PARSE-001": ("INCOMPLETE", "a JSON object repeats a member name"),
    "TV-PARSE-002": ("INCOMPLETE", "top-level JSON value is not an object"),
    "TV-VER-001": ("INCOMPLETE", "receipt_version not implemented by this tool"),
    "TV-HASH-001": ("FAILED", "receipt has no payload"),
    "TV-HASH-002": ("FAILED", "integrity_hash is not sha256: plus 64 lowercase hex digits"),
    "TV-HASH-003": ("INCOMPLETE", "covered_fields declares bytes this tool does not recompute"),
    "TV-HASH-004": ("FAILED", "recomputed integrity hash differs from the recorded one"),
    "TV-HASH-005": ("INCOMPLETE", "payload has no canonical JSON form (NaN or infinity)"),
    "TV-CANON-001": ("FAILED", "payload number outside the canonical number domain"),
    "TV-CANON-002": ("FAILED", "payload string contains an unpaired surrogate"),
    "TV-SIG-001": ("INCOMPLETE", "telos/0.1-unsigned signing state is not the defined one"),
    "TV-SIG-002": ("INCOMPLETE", "telos/0.2-ed25519 signing state is not the defined one"),
    "TV-SIG-003": ("INCOMPLETE", "signature algorithm is not ed25519"),
    "TV-SIG-004": ("INCOMPLETE", "signature covers something other than the integrity hash"),
    "TV-SIG-005": ("FAILED", "signature value is not canonical base64 of 64 bytes"),
    "TV-SIG-006": ("FAILED", "signature does not verify; the receipt names a key the caller does not trust"),
    "TV-SIG-007": ("FAILED", "signature does not verify under any caller-supplied key"),
    "TV-SIG-008": ("INCOMPLETE", "--require-signature and a receipt carries no checked signature"),
    "TV-SIG-009": ("FAILED", "key_id does not name the key the signature verifies under"),
    "TV-SIG-010": ("INCOMPLETE", "the cryptography package is absent, so Ed25519 cannot be checked"),
    "TV-CHAIN-001": ("INCOMPLETE", "sequence is not a JSON integer"),
    "TV-CHAIN-002": ("FAILED", "sequences are not contiguous from genesis 0"),
    "TV-CHAIN-003": ("FAILED", "previous_receipt_integrity_hash does not link"),
    "TV-CHAIN-004": ("FAILED", "a chain member without its partner"),
    "TV-CHAIN-005": ("FAILED", "two receipts share a sequence"),
    "TV-CHAIN-006": ("FAILED", "chain file malformed or not in sequence order"),
    "TV-HEAD-001": ("FAILED", "observed chain head differs from the expected head"),
    "TV-HEAD-002": ("INCOMPLETE", "expected head given, but no linked chain head was established"),
    "TV-TRUST-001": ("FAILED", "deployment certificate does not verify under the root key"),
    "TV-TRUST-002": ("INCOMPLETE", "no certificate names the receipt's key"),
    "TV-TRUST-003": ("FAILED", "receipt is not signed by the certified deployment key"),
    "TV-TRUST-004": ("FAILED", "certificate has no issuance entry in the Lineage Chain projection"),
    "TV-ANCHOR-001": ("FAILED", "anchored receipt is not telos/0.3-ed25519 or telos/0.2-ed25519 with a key_id"),
    "TV-ANCHOR-002": ("FAILED", "certificate purpose is not receipt_signing"),
    "TV-ANCHOR-003": ("INCOMPLETE", "key has a rotate/revoke entry or a valid_until; no covered time places the signature"),
    "TV-REGISTRY-001": ("FAILED", "Lineage Chain projection is not a contiguous hash-linked chain"),
    "TV-REGISTRY-002": ("FAILED", "projection entry does not verify under the root key"),
    "TV-REGISTRY-003": ("FAILED", "projection entry has members outside the published set"),
    "TV-EXIT-001": ("FAILED", "FAILED and INCOMPLETE in one run: FAILED wins, exit 1"),
    "TV-OUT-001": ("ANY", "every FAIL and INCOMPLETE line carries its check id"),
    "TV-TRUST-006": ("ANY", "a self-rooted test bundle run carries the TEST BUNDLE warning and no anchored claim"),
    "TV-SCHEMA-001": ("FAILED", "receipt does not conform to the section 1 receipt schema"),
    "TV-S2-002": ("FAILED", "verdict is not in the public vocabulary"),
    "TV-S2-003": ("FAILED", "composite_score is not a JSON number"),
    "TV-S2-004": ("FAILED", "a scores value is not a JSON number"),
    "TV-S2-005": ("FAILED", "a scores label is empty"),
    "TV-S2-006": ("FAILED", "pa_id is empty"),
    "TV-ANCHOR-004": ("FAILED", "anchored telos/0.3 receipt has no scope_id"),
    "TV-ANCHOR-006": ("FAILED", ("a closing checkpoint places the receipt after its key's "
                                 "rotate or revoke entry")),
    "TV-ANCHOR-005": ("FAILED", "receipt scope_id differs from the certificate's"),
    "TV-REGISTRY-004": ("FAILED", "first projection entry has no lineage anchor"),
    "TV-S2-010": ("FAILED", "telos/0.3 composite_score or a scores value is outside [0, 1]"),
    "TV-S2-011": ("FAILED", "telos/0.3 boundary_flag is absent or not a boolean"),
    "TV-S2-012": ("FAILED", ("telos/0.3 specification_version, observation_config_hash or "
                             "profile_id is absent or malformed")),
    "TV-LOAD-001": ("INCOMPLETE", "input missing, unreadable, or not JSON"),
    "TV-LOAD-002": ("INCOMPLETE", "a supplied key or trust file is unusable"),
    "TV-LOAD-003": ("INCOMPLETE", "the supplied expected head is malformed"),
    "TV-KEY-001": ("INCOMPLETE", "a caller-supplied public key is small-order or not a canonical point encoding"),
    "TV-KEY-002": ("FAILED", "a certificate or bundle public key is small-order or not a canonical point encoding"),
}

# Section 1 structure (schema/S1.schema.json of the standard), checked with the
# standard library so the unsigned path keeps needing nothing installed. Rules
# that have their own check id (version, covered_fields, hash form, signing
# state, algorithm, covers, signature value) are left to that check, so one
# defect is reported once, under the id that names it.
ENVELOPE = ("receipt_version", "kind", "agent_id", "payload", "issued_at",
            "integrity_hash", "covered_fields", "signing_status", "signature", "engine")
AG_REQUIRED = ("action_name", "action_params_hash", "verdict", "composite_score", "scores", "pa_id")
AG_CHAIN = ("sequence", "previous_receipt_integrity_hash")
SIG_MEMBERS = ("algorithm", "covers", "value", "public_key", "key_id")
VERDICTS = ("EXECUTE", "CLARIFY", "SUGGEST", "ESCALATE", "INERT")  # historical 0.1/0.2
VERDICTS_03 = ("ALIGNMENT", "UNCERTAINTY", "ADVISORY", "DIVERGENCE", "INERT")
# Covered members 0.3 adds to action_governed. Their presence and form are
# Section 2 rules (TV-S2-011, TV-S2-012); Section 1 here only admits them.
AG_03 = ("boundary_flag", "specification_version", "observation_config_hash", "profile_id",
         "scope_id")
RFC3339 = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                     r"(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
PUBKEY_RE = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")
MAX_INT = 2 ** 53 - 1

# ---------------------------------------------------------------- anchored mode
#
# Section 4 of the standard: an offline root key certifies deployment keys, and
# every key lifecycle event is a root-signed, hash-linked entry in the Lineage
# Chain public projection. The root key comes from the caller (--root-key); it
# is never taken from the material being verified, except from a section 4.11
# TEST bundle, which the output then labels as not a trust anchor.

CERT_VERSION = "trs-cert/0.1"
CERT_COVERS = "certificate_hash (ASCII bytes of the sha256: string)"
CERT_MEMBERS = ("cert_version", "algorithm", "child_public_key", "child_key_id", "key_role",
                "scope_id", "purpose", "valid_from", "valid_until", "root_key_id",
                "root_signature")
ENTRY_VERSION = "trs-lineage-projection/0.1"
ENTRY_COVERS = "this_hash (ASCII bytes of the sha256: string)"
ENTRY_MEMBERS = ("entry_version", "sequence", "event_type", "timestamp", "effective_at",
                 "parent_hash", "root_key_id", "child_key_id", "key_role", "scope_id",
                 "valid_from", "valid_until", "certificate_hash", "successor_key_id",
                 "reason_digest", "withheld_digest", "this_hash", "root_signature")
KEY_EVENTS = ("child_key_issue", "child_key_rotate", "child_key_revoke")
CHECKPOINT_EVENT = "receipt_chain_checkpoint"
CHECKPOINT_MEMBERS = ("entry_version", "sequence", "event_type", "timestamp", "parent_hash",
                      "root_key_id", "child_key_id", "scope_id", "chain_head", "chain_sequence",
                      "withheld_digest", "this_hash", "root_signature")
BUNDLE_VERSION = "trs-test-bundle/0.1"
