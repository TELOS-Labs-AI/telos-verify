# Spec note: what the published schema covers, and what it does not

`receipt-spec.schema.json` describes the `telos/0.1-unsigned` envelope: the
outer record shape, the required fields, and the form of the integrity hash. It
lets a Draft 2020-12 validator check that structure. A schema does not recompute
the payload hash, verify chain links, or authenticate a signature; those are
separate executable checks.

## Deliberately outside this schema

Being explicit is better than letting a reader assume the published surface is
the whole system.

- **Key custody and key distribution.** `receipt-spec-signed.schema.json` now
  describes the signed envelope `telos/0.2-ed25519`: the signature block, the
  algorithm, and exactly what is signed. What it deliberately does not describe
  is how signing keys are generated, stored, rotated, or published, or how a
  verifier should decide which key to trust. That decision is the whole of the
  trust model and it cannot be delegated to a schema. `telos-verify` reflects
  this by refusing to treat the key printed on a receipt as authority: it checks
  signatures only against a key the operator supplies out of band, or, in
  anchored mode, against a deployment key certified by a root key the operator
  supplies.
- **Scoring internals.** `composite_score` and the per-dimension `scores` appear
  in the envelope as numbers. How they are computed, what weights combine them,
  and what thresholds map a score to a verdict are not part of this schema.
- **Purpose anchor construction.** `pa_id` names a purpose anchor. How an anchor
  is built or represented is not described here.
- **Action-parameter digest construction and confidentiality.**
  `action_params_hash` is constrained only to `sha256:<64 lowercase hex>` form.
  This public contract does not define a serialization, producer, recomputation,
  or opening procedure for it, and `telos-verify` checks only that form; it does
  not recompute the value. It is therefore not a publicly reproducible
  commitment. Omitting raw arguments avoids echoing them, but a deterministic
  digest can still reveal equality and permit offline guessing of low-entropy
  parameter values, so the field does not keep those values secret.
- **Payload shapes other than `action_governed`.** The envelope carries a `kind`
  field and other kinds reuse the same outer shape, but only `action_governed`
  has its payload constrained here.

## What this means for a verifier

A Draft 2020-12 JSON Schema validator can check a receipt against the bundled
schema files. `telos-verify` does **not** load or run those files. Instead it has
its own structure and field checks, written in Python with the standard library,
that follow the TELOS Receipt Standard v0.1:

- **Section 1 structure (`TV-SCHEMA-001`):** exactly the ten envelope members;
  string `kind`, `agent_id` and `engine`; an RFC 3339 `issued_at`; an object
  `payload`; no undeclared members in a signed receipt's signature block, and
  well-formed `public_key` and `key_id` when present; and, for `action_governed`
  payloads, the six required members, no undeclared members, and well-formed
  `action_name`, `pa_id`, `action_params_hash` and (on 0.3) `scope_id`.
- **Section 2 field forms (`TV-S2-*`),** for `action_governed` payloads: the
  version's verdict vocabulary, numeric `composite_score` and `scores` values,
  non-empty `scores` labels and `pa_id`; and on `telos/0.3-ed25519` only, scores
  in [0, 1], a boolean `boundary_flag`, a string `specification_version`, a
  well-formed `observation_config_hash`, and a string `profile_id` when present.
- **Canonical domain (`TV-CANON-001`, `TV-CANON-002`):** payload numbers inside
  the standard's canonical number domain, and strings and keys without unpaired
  surrogates.

Rules that have their own check id (version, `covered_fields`, hash form, signing
state, signature algorithm, `covers` and value) are reported under that id. A
failure of any of these checks is FAILED (exit `1`). Its exit `0` means these
checks passed along with the hash, linkage, head-pin, signature and anchored
checks that applied. That is close to, but not the same as, a JSON Schema
validator's verdict on the bundled files, and there is no bundled schema file for
`telos/0.3-ed25519`. Run a schema validator separately if you need that verdict.
`telos-verify --list-checks` prints every check id.

Those executable checks still cannot, and should not claim to, evaluate whether
a verdict was correct. Schema conformance, hash integrity, chain linkage,
signature verification, and content truth are separate questions.

For `telos/0.1-unsigned`, integrity means only that the supplied payload and its
recorded hash agree. Anyone can fabricate both together. It does not show that a
described action occurred, that its parameters are genuine, or that a verdict or
score is correct. Implementations should put that limit in their runtime output,
including reduced-output modes, rather than relying on documentation the operator
may never have read.

A successful signature check establishes verification under a supplied public
key. Who controls that key requires an external identity binding. It leaves
"when" open: `issued_at` sits outside the hash so that the same logical payload
always produces the same hash, which means it is outside the signature too. A
signed receipt does not date itself.

## Versioning

`receipt_version` is the contract identifier. A verifier should refuse a version
it does not know rather than guess, which is why `telos-verify` reports
INCOMPLETE rather than FAILED when it meets an unfamiliar version.

`telos-verify` knows three versions:

- `telos/0.1-unsigned`: `signature` is null. Described by
  `receipt-spec.schema.json`.
- `telos/0.2-ed25519`: the same required outer fields and `action_governed`
  payload constraints as 0.1. Three version-specific fields differ:
  `receipt_version`, `signing_status`, and `signature`. The signed schema
  (`receipt-spec-signed.schema.json`) requires an Ed25519 signature object and
  constrains its public-key and signature values to the base64 lengths of 32 and
  64 raw bytes.
- `telos/0.3-ed25519`: the 0.2 envelope, canonical bytes and signature block,
  plus covered `action_governed` payload members (`boundary_flag`,
  `specification_version`, `observation_config_hash`, and optionally `profile_id`
  and `scope_id`) and a different verdict vocabulary (`ALIGNMENT`,
  `UNCERTAINTY`, `ADVISORY`, `DIVERGENCE`, `INERT`). No schema file for 0.3 is
  bundled here.

`telos-verify` refuses a receipt declaring 0.1 while carrying a signature,
because that shape contradicts its declared version, and reports INCOMPLETE for
a signed version whose signing state is not the defined one.
