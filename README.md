# telos-verify

An offline command-line verifier for TELOS receipts.

Point it at a receipt, a directory of receipts, a JSON Lines chain file, or a test
bundle. It checks each receipt's structure, recomputes the integrity hash from
the canonical JSON encoding of each parsed payload, checks signatures against keys
you supply, and, when at least two receipts carry sequence fields, checks their
neighbouring links. It works after the fact, on records that already exist. The implementation
contains no network client. For unsigned receipts it needs **no third-party Python
package** and uses only the standard library. You still trust the Python runtime and
the channel that supplied these files; zero additional dependencies is not zero
supply-chain trust. The verifier is intentionally small enough to inspect.

It knows three receipt versions:

| `receipt_version` | Signature | Notes |
|---|---|---|
| `telos/0.1-unsigned` | none (`signature` is `null`) | integrity hash only |
| `telos/0.2-ed25519` | Ed25519 over the integrity hash | same envelope and payload rules as 0.1 |
| `telos/0.3-ed25519` | Ed25519 over the integrity hash | adds covered observation fields to `action_governed` payloads and uses a different verdict vocabulary |

Any other version is reported INCOMPLETE (`TV-VER-001`), not judged. Checking a
signature needs one optional dependency; see [Signed receipts](#signed-receipts).

## What a passing check shows

Exit `0` means every check that applied to the input passed. Depending on the input,
that covers up to five things:

1. **Receipt structure and field forms.** Every receipt is checked against the
   structural rules of section 1 of the TELOS Receipt Standard v0.1 (check id
   `TV-SCHEMA-001`) and, for `action_governed` payloads, the field rules of
   section 2 (check ids `TV-S2-*`). Payload numbers and strings must also lie in
   the canonical JSON domain (`TV-CANON-001`, `TV-CANON-002`). These checks are
   written in Python in `telos_verify_lib/schema.py`. See
   [Structure and field checks](#structure-and-field-checks) for exactly what they
   cover.
2. **The recorded hash matches the canonical JSON encoding of the payload value
   supplied to this run.** If the parsed payload value changes in a way that changes
   that canonical encoding, without also changing the recorded hash, the recomputed
   hash will not match and the tool fails. Whitespace and object-key order in the
   source file are intentionally not covered. For an unsigned receipt,
   anyone can fabricate both the payload and a matching hash; this check does not
   establish that any claim inside the payload is true.
3. **When at least two sequenced receipts are present, the sequenced subset starts
   at genesis and its neighbouring links have no gap.** Each sequenced receipt
   points at the previous receipt's hash and the sequence is contiguous from `0`.
   Removing a sequenced record from the beginning or middle, or reordering it
   without coherently rewriting the linked payloads, breaks this check. Receipts
   without sequence fields are outside it. **A record removed from the newest end
   breaks nothing**, and no check inside the set can detect it; see "The two ends
   of a chain are not the same". One sequenced receipt has zero neighbouring links,
   even when unsequenced bystanders are present, so linkage is NOT EVALUABLE then.
4. **When you pin a head** with `--expected-head` or `--expected-head-file`, the
   linked chain ends at that head.
5. **When a receipt is signed and you supply a key**, its Ed25519 signature over the
   integrity hash verifies under a key you supplied (or, in anchored mode, under a
   deployment key that your root key certified).

The output names which of these were checked on each run. A check the output does
not name was not performed.

## What a passing check does NOT show

**It does not establish who issued an unsigned receipt, when it was issued, whether
the described action happened, whether its parameters are genuine, or whether its
verdict or score is correct.** The structure and field checks look at the shape of
a record, not at whether what it says is true.

The bundled JSON Schema files (`docs/receipt-spec.schema.json` and
`docs/receipt-spec-signed.schema.json`) are not read or run by the verifier. Its
structure checks are a separate implementation of the standard's rules, so a pass
here is not the same thing as a pass from a JSON Schema validator run against
those files. The bundled schema files describe `telos/0.1-unsigned` and
`telos/0.2-ed25519` only; there is no bundled schema file for `telos/0.3-ed25519`.

The public contract does not define how `action_params_hash` is produced: it
specifies neither a parameter serialization nor a recomputation/opening procedure,
and this verifier checks only that the field has the `sha256:` plus 64 lowercase
hex form. It is not a publicly reproducible commitment. Omitting raw arguments
avoids echoing them, but a deterministic digest can reveal equality and support
offline guessing of low-entropy values, so it does not keep those values secret.

The `telos/0.1-unsigned` contract carries no digital signature. The `signature`
field is `null` and the receipt declares this about itself in `signing_status`.
An integrity hash is key-free: anyone can compute one, so a matching hash shows
only that canonical JSON of the supplied payload agrees with the recorded hash,
and nothing about authorship or truth. Whoever can write the receipt can write
any payload and its matching hash. The CLI therefore labels an unsigned success `UNSIGNED INTEGRITY
ONLY — CONTENT NOT VALIDATED` and repeats the warning even under `--quiet`.

This is stated in the TELOS whitepaper and it is repeated here because the tool
should not be more confident than the artifact deserves.

The signed versions change `receipt_version`, fill `signature`, and change
`signing_status`. A checked signature establishes only that the signature verifies
under a key you supplied. Identifying **who** controls that key requires an
independent key-to-identity binding outside this tool. It still does not answer
**when**: `issued_at` sits outside the hash, so it
is covered by neither the hash nor the signature. Without a key you supply
yourself, the tool does not treat a signed receipt as verified and reports
INCOMPLETE instead. An unavailable or absent required signature check is not a
pass.

`issued_at` is deliberately outside the hash, so the same logical payload always
produces the same hash. That means the timestamp is metadata and is **not**
covered by the integrity check. The structure check looks only at its form (an
RFC 3339 date-time).

## Install

For unsigned receipts there is no third-party package to install. The code has a
Python 3.9 runtime floor. This release was exercised only on the exact
interpreters named in [Tests](#tests); versions not named there remain unverified.

```bash
git clone https://github.com/TELOS-Labs-AI/telos-verify.git
cd telos-verify
python3 telos_verify.py --help
```

To check Ed25519 signatures, or to use anchored mode, you also need
[`cryptography`](https://pypi.org/project/cryptography/):

```bash
pip install cryptography
```

### Why a dependency, and why only this one

Python's standard library has no Ed25519. This repository uses `cryptography`
instead of shipping its own RFC 8032 implementation. Installing it adds another
supply-chain component that you must obtain and trust; the unsigned path does not
load it when it is absent.

The dependency is **optional and confined to the signature path**. Without it the
unsigned contract verifies exactly as before, and a signed receipt reports
INCOMPLETE (`TV-SIG-010`) with an instruction to install it. It is never treated as
a pass. Two tests run the tool with `import cryptography` made to fail and check both
behaviours.

## Usage

```bash
python3 telos_verify.py <path-to-receipt.json>     # one receipt
python3 telos_verify.py <path-to-directory>        # every *.json receipt in a directory
python3 telos_verify.py <chain.jsonl>              # a JSON Lines chain file
python3 telos_verify.py <path> --quiet             # suppress trace, keep verdict + warnings
python3 telos_verify.py <path> --key trusted.pub   # also check the signature
python3 telos_verify.py <path> --require-signature # unsigned is not good enough
python3 telos_verify.py <directory> --expected-head sha256:... # reject another head
python3 telos_verify.py <directory> --expected-head-file HEAD.sha256
python3 telos_verify.py <path> --root-key root.pub --trust-dir trust/  # anchored mode
python3 telos_verify.py --list-checks              # print every check id
```

| Flag | Effect |
|---|---|
| `--quiet` | Suppress per-receipt trace while retaining the verdict and safety notes. On a nonzero result, re-run without `--quiet` for the diagnostic reason. |
| `--key FILE` | A public key **you already trust**, as PEM or as the 32 raw key bytes in canonical base64 or hex. Repeatable. Signatures are checked only against keys given here. A small-order or non-canonical key is refused (`TV-KEY-001`). |
| `--require-signature` | Report INCOMPLETE rather than VERIFIED (UNSIGNED INTEGRITY ONLY) when a receipt carries no signature this tool could check. Off by default because the integrity-only profile is supported. |
| `--expected-head SHA256` | Compare the linked chain's observed head with an independently obtained `sha256:<64 lowercase hex>` value. A mismatch is FAILED (exit 1). |
| `--expected-head-file FILE` | Read that expected digest from a file. Mutually exclusive with `--expected-head`. |
| `--root-key FILE` | Anchored mode: the root public key you already trust. Needs `--trust-dir`, unless the input is a test bundle. See [Anchored mode](#anchored-mode). |
| `--trust-dir DIR` | Anchored mode: a directory of `*.cert.json` certificates plus `projection.jsonl`. |
| `--list-checks` | Print every check id, the state it produces, and a one-line description, then exit `0`. |

### Exit codes, three states

| Code | State | Meaning |
|---|---|---|
| `0` | VERIFIED | Every implemented check that applied passed: structure and field checks, the payload-to-hash check, and any linkage, head-pin, signature or anchored check explicitly named in the output. For unsigned input it does not validate payload claims. |
| `1` | FAILED | At least one named check was contradicted: for example a structure or field check, a hash mismatch, a payload value outside the canonical domain, a broken chain link, a head-pin mismatch, or a signature that does not verify under a key you supplied. The tool does not identify authorship or decide which conflicting input is authoritative. |
| `2` | INCOMPLETE | Verification could not be completed: for example unreadable input, a file that is not a receipt object, a file that repeats a JSON member name, an unknown contract version, a refused `--key`, or a receipt claiming a signature while the material needed to check it is absent. |

`INCOMPLETE` is never reported as a pass. When one run has both FAILED and
INCOMPLETE results, FAILED wins and the exit code is `1` (`TV-EXIT-001`). This
matters if you are wiring the tool into CI: `python3 telos_verify.py receipts/ &&
echo VERIFIED` prints nothing unless the exit code is `0`.

### Check ids

Every FAIL and INCOMPLETE line names one check id in brackets, such as
`[TV-HASH-004]`, and any run with a FAIL or INCOMPLETE line ends with a note
saying so (`TV-OUT-001`). `--list-checks` prints all 60 check ids:

```
$ python3 telos_verify.py --list-checks | head -n 3
CHECK TV-OFFLINE-001  INCOMPLETE  signed receipt and no caller-supplied trusted key; nothing is fetched
CHECK TV-PARSE-001  INCOMPLETE  a JSON object repeats a member name
CHECK TV-PARSE-002  INCOMPLETE  top-level JSON value is not an object
```

### One receipt versus a chain

The two modes prove different things, and the tool is explicit about which one
you got.

- **At least two individually valid, sequenced receipts** let the tool check each
  hash and one or more neighbouring links. Receipts without a sequence are
  explicitly excluded from that check.
- **Fewer than two sequenced receipts** checks each receipt only. One sequenced
  receipt cannot demonstrate linkage, because linkage lives in a neighbouring
  pair. Adding any number of unsequenced bystanders does not change that. The tool
  reports chain linkage as NOT EVALUABLE in normal and quiet output. Exit `0`
  reflects the applicable per-receipt checks alone.

So a valid receipt exits `0` whatever its sequence number, and the run tells you
plainly that chain linkage was not evaluable:

```
$ python3 telos_verify.py vectors/valid/004_harmbench.json
ok    004_harmbench.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
chain  NOT EVALUABLE from this set: only one receipt carries a `sequence` field, so there is no neighbouring link to check.

VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED): PAYLOAD-TO-HASH BINDING ESTABLISHED for 1 receipt(s): each recorded hash matches canonical JSON of its supplied payload.
NOTE: CHAIN LINKAGE NOT EVALUABLE from this set. Only 1 of 1 receipt(s) carries a `sequence` field; at least two sequenced receipts are needed to evaluate a neighbouring link.
NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and
      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not
      content: it does not show that a recorded action, verdict, or score is correct.
WARNING: CONTENT NOT VALIDATED. Anyone can fabricate an unsigned receipt and
         compute a matching hash. This result does not show that the described action
         happened, that its parameters are genuine, or that its verdict/score is correct.
NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.

$ echo $?
0
```

Absence of linkage evidence is not evidence of tampering, so this is neither a
pass nor a failure on that question. If you want linkage checked, supply at least
two neighbouring sequenced receipts.

### Chain files

A path ending in `.jsonl` is read as a chain file: one receipt per line, every line
ending in LF, and lines already in ascending `sequence` order. Every line must be a
chained receipt, carrying `sequence` or `previous_receipt_integrity_hash` in its
payload. The file is never re-sorted. A chain file that is empty, lacks a final LF,
contains a blank line or a line that is not a chained receipt, or is out of
sequence order is FAILED (`TV-CHAIN-006`).

## Structure and field checks

These run on every receipt, before the hash check, and are reported as FAIL lines.

**Section 1 structure (`TV-SCHEMA-001`).** One FAIL line lists every problem found
in the receipt:

- The envelope has exactly these ten members, no more and no fewer:
  `receipt_version`, `kind`, `agent_id`, `payload`, `issued_at`, `integrity_hash`,
  `covered_fields`, `signing_status`, `signature`, `engine`.
- `kind`, `agent_id` and `engine` are strings; `issued_at` is an RFC 3339
  date-time; `payload` is an object.
- On the signed versions, the signature block has no members other than
  `algorithm`, `covers`, `value`, `public_key` and `key_id`; `public_key`, when
  present, is canonical base64 of 32 bytes; `key_id`, when present, is `sha256:`
  plus 64 lowercase hex digits.
- For `kind: action_governed`, the payload has `action_name`,
  `action_params_hash`, `verdict`, `composite_score`, `scores` and `pa_id`, and no
  other members except `sequence` and `previous_receipt_integrity_hash`. On
  `telos/0.3-ed25519` it may also carry `boundary_flag`, `specification_version`,
  `observation_config_hash`, `profile_id` and `scope_id`; `scope_id`, when
  present, is a non-empty string. `action_name` and `pa_id` are strings, and
  `action_params_hash` is `sha256:` plus 64 lowercase hex digits.

Rules that have their own check id are reported under that id instead, so one
defect is reported once: the version (`TV-VER-001`), `covered_fields`
(`TV-HASH-003`), the integrity-hash form (`TV-HASH-002`), the signing state
(`TV-SIG-001`, `TV-SIG-002`), the signature algorithm and `covers` statement
(`TV-SIG-003`, `TV-SIG-004`) and the signature value (`TV-SIG-005`).

**Section 2 field forms (`TV-S2-*`),** for `action_governed` payloads only:

| Check | Rule |
|---|---|
| `TV-S2-002` | `verdict` is in the vocabulary of the receipt's version: `EXECUTE`, `CLARIFY`, `SUGGEST`, `ESCALATE`, `INERT` on 0.1 and 0.2; `ALIGNMENT`, `UNCERTAINTY`, `ADVISORY`, `DIVERGENCE`, `INERT` on 0.3 |
| `TV-S2-003` | `composite_score` is a JSON number |
| `TV-S2-004` | `scores` is an object whose values are JSON numbers |
| `TV-S2-005` | no `scores` label is empty |
| `TV-S2-006` | `pa_id` is not empty |
| `TV-S2-010` | 0.3 only: `composite_score` and every `scores` value lie in [0, 1] |
| `TV-S2-011` | 0.3 only: `boundary_flag` is present and is a boolean |
| `TV-S2-012` | 0.3 only: `specification_version` is present and is a string; `observation_config_hash` is present and is `sha256:` plus 64 lowercase hex digits; `profile_id`, when present, is a string |

Payloads of other kinds get the envelope checks only.

**Canonical domain (`TV-CANON-001`, `TV-CANON-002`).** A payload number written
without a fraction or exponent must lie within ±(2^53 − 1). A number written with
one must not be −0 and, unless it is zero, must have an absolute value of at least
0.0001 and below 10^16. Strings and object keys must not contain an unpaired
surrogate.

Here is a receipt from the valid set with its `engine` member removed. `engine` is
outside the hash, so the hash still matches, but the structure check fails:

```
$ python3 telos_verify.py missing-engine.json
FAIL [TV-SCHEMA-001] missing-engine.json: does not conform to the receipt schema: missing member(s) engine

FAILED: 0 of 1 receipt(s) passed the implemented per-receipt checks; one or more required checks failed.
NOTE: [TV-OUT-001] every FAIL and INCOMPLETE line names its check id in brackets; --list-checks lists them.

$ echo $?
1
```

## Test vectors, with real output

The repository ships passing, altered, and coherently fabricated cases. The
outputs below were produced by running the commands shown and are pasted
verbatim. Inputs that are not in `vectors/` (such as `missing-engine.json` above
and the signed examples below) were built from the valid vectors in a scratch
directory; signed ones use a throwaway key generated for the run.

### 1. A chain that verifies

Nine unsigned receipts supplied as this repository's reference valid set. The
verifier checks their structure, internal hashes and linkage; it does not establish
their provenance or byte-identity to any separately published copy.

```
$ python3 telos_verify.py vectors/valid
ok    000_sb243.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    001_xstest_generic.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    002_xstest_healthcare_hipaa.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    003_ailuminate.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    004_harmbench.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    005_medsafetybench.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    006_agentharm.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    007_propensitybench.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    008_agentdojo.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    CHAIN LINKAGE CHECKED: 9 sequenced receipt(s), 8 neighbouring link(s), contiguous from genesis (sequence 0) through sequence 8
      head sha256:0f7a0cf9c137739aa0afa37e376e600d7bed49bdbc2e458ea874d1f9a608e3b3
      NOT CHECKED: whether any receipt newer than sequence 8 exists. A missing tail
      cannot be detected from the receipts alone. Pin the head hash above against a head
      you hold independently.

VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED): PAYLOAD-TO-HASH BINDING ESTABLISHED for 9 receipt(s): each recorded hash matches canonical JSON of its supplied payload.
NOTE: CHAIN LINKAGE CHECKED for all 9 receipt(s): 8 neighbouring link(s) validated; sequences are contiguous from genesis 0 through 8.
NOTE: chain COMPLETENESS was NOT assessed. Receipts newer than sequence 8 could be
      missing and nothing in this set would show it. Pin this observed head against a head you
      hold independently:  sha256:0f7a0cf9c137739aa0afa37e376e600d7bed49bdbc2e458ea874d1f9a608e3b3
NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and
      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not
      content: it does not show that a recorded action, verdict, or score is correct.
WARNING: CONTENT NOT VALIDATED. Anyone can fabricate an unsigned receipt and
         compute a matching hash. This result does not show that the described action
         happened, that its parameters are genuine, or that its verdict/score is correct.
NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.

$ echo $?
0
```

`vectors/valid/HEAD.sha256` publishes the expected head for this exact vector
set, so the consumer path can be run rather than described:

```
$ python3 telos_verify.py vectors/valid --expected-head-file vectors/valid/HEAD.sha256 --quiet
VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED): PAYLOAD-TO-HASH BINDING ESTABLISHED for 9 receipt(s): each recorded hash matches canonical JSON of its supplied payload.
NOTE: CHAIN LINKAGE CHECKED for all 9 receipt(s): 8 neighbouring link(s) validated; sequences are contiguous from genesis 0 through 8.
NOTE: HEAD PIN CHECKED: the observed chain head matches the expected head supplied by the caller: sha256:0f7a0cf9c137739aa0afa37e376e600d7bed49bdbc2e458ea874d1f9a608e3b3
      The verifier cannot determine whether that external pin is authoritative or current.
NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and
      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not
      content: it does not show that a recorded action, verdict, or score is correct.
WARNING: CONTENT NOT VALIDATED. Anyone can fabricate an unsigned receipt and
         compute a matching hash. This result does not show that the described action
         happened, that its parameters are genuine, or that its verdict/score is correct.
NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.

$ echo $?
0
```

The bundled head demonstrates the mechanism but is not independent merely
because it is a separate file. For real use, obtain or retain the expected head
through a channel you trust independently of the receipts being checked.

### 2. A chain with one altered receipt

The same nine receipts, with exactly one change: in `004_harmbench.json` the
payload's `current` field was edited from `0.00%` to `99.99%`, and the recorded
`integrity_hash` was left untouched. This is the shape of change the receipt
exists to reveal: someone restating a result after the fact.

```
$ python3 telos_verify.py vectors/tampered
ok    000_sb243.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    001_xstest_generic.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    002_xstest_healthcare_hipaa.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    003_ailuminate.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
FAIL [TV-HASH-004] 004_harmbench.json: payload does not match recorded hash
        recorded  sha256:f0549f563add4bbfaf14b3bc172c0d5c305619030e090d2498f8c99319565d68
        recomputed sha256:ef47a8caf12b610d39a7b9ea15a8ed62adf4c46a0e0ff6053f748efa7925cf1d
ok    005_medsafetybench.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    006_agentharm.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    007_propensitybench.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    008_agentdojo.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload

FAILED: 8 of 9 receipt(s) passed the implemented per-receipt checks; one or more required checks failed.
NOTE: [TV-OUT-001] every FAIL and INCOMPLETE line names its check id in brackets; --list-checks lists them.

$ echo $?
1
```

Note what the tool does not do: it does not guess which version was the true one.
It reports that the record no longer matches its own hash. Because one receipt
failed, linkage was not evaluated on this run.

**Why eight lines say `ok` under a directory named `tampered`.** Only one file in
`vectors/tampered/` is altered. The other eight are byte-identical to the valid
set on purpose, so the vector shows the tool finding the single bad record inside
an otherwise intact set, which is the realistic case. A directory where every
receipt failed would prove much less.

### 3. Fabricated content with a matching hash

`vectors/fabricated/unsigned-content-claim.json` contains `action_name:
start_thermonuclear_war`, a fabricated parameters hash, `verdict: EXECUTE`, and
`composite_score: 1.0`. It has every field required for an `action_governed`
payload, so it passes the structure and field checks, and its recorded integrity
hash was calculated over exactly that payload, so the hash check passes too. The
run exits `0`, and the output states plainly that none of this says the content is
true:

```
$ python3 telos_verify.py vectors/fabricated/unsigned-content-claim.json --quiet
VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED): PAYLOAD-TO-HASH BINDING ESTABLISHED for 1 receipt(s): each recorded hash matches canonical JSON of its supplied payload.
NOTE: CHAIN LINKAGE NOT EVALUABLE from this set. No receipt carries a `sequence` field, so no neighbouring link exists to check.
NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and
      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not
      content: it does not show that a recorded action, verdict, or score is correct.
WARNING: CONTENT NOT VALIDATED. Anyone can fabricate an unsigned receipt and
         compute a matching hash. This result does not show that the described action
         happened, that its parameters are genuine, or that its verdict/score is correct.
NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.

$ echo $?
0
```

## Signed receipts

`telos/0.2-ed25519` and `telos/0.3-ed25519` are the signed contracts. Compared with
`telos/0.1-unsigned`, three envelope fields differ: `receipt_version` names the
signed version, `signing_status` becomes `ed25519_signed`, and `signature` holds
an object instead of `null`. `telos/0.2-ed25519` keeps the 0.1 payload rules;
`telos/0.3-ed25519` adds the payload fields and verdict vocabulary listed under
[Structure and field checks](#structure-and-field-checks).

```json
"signature": {
  "algorithm": "ed25519",
  "covers": "integrity_hash (ASCII bytes of the sha256: string)",
  "public_key": "1caSqSsicjdC4D+v5wUszfmbYU64uuDhpPRGEv5xT/0=",
  "value": "daYWzhPAladHtfU62XN0JCnHglX0IccPdZzFJh+0dDKKYR9ocTV5OcWFhk31HbrNG9ldcyZsq9PdqflUij5IDg=="
}
```

The block may also carry `key_id` (`sha256:` plus 64 lowercase hex digits). When it
does, it must name the key the signature verifies under, or the receipt is FAILED
(`TV-SIG-009`). Anchored mode requires it.

The signature is over the **ASCII bytes of the `integrity_hash` string**, which
is itself the hash of the canonical payload. So the signature commits to the
payload transitively, and you can check the two links separately: recompute the
hash yourself, then check the signature over that hash. The signature value must be
canonical padded base64 of exactly 64 bytes (`TV-SIG-005`).

### The key on the receipt is not the key you trust

`public_key` is printed on the receipt for diagnosis only. **It is not a trust
anchor**, because anyone who can forge a receipt can print a key on it and sign
with the matching secret. The tool never uses it to reach a verdict. It checks
signatures only against keys you pass with `--key`, which you must obtain the
same way you would obtain any root of trust: out of band, from a source you have
independent reason to believe.

Run without `--key`, a signed receipt is INCOMPLETE, not a pass. The hashes still
bind their payloads, so linkage is still checked and reported in the trace:

```
$ python3 telos_verify.py signed/
ok    000.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
INCOMPLETE [TV-OFFLINE-001] 000.json: receipt carries a signature, but you supplied no trusted public key (--key). The key printed on a receipt is not a trust anchor, and this tool fetches nothing. PAYLOAD-TO-HASH BINDING established; signature NOT checked.
ok    001.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
INCOMPLETE [TV-OFFLINE-001] 001.json: receipt carries a signature, but you supplied no trusted public key (--key). The key printed on a receipt is not a trust anchor, and this tool fetches nothing. PAYLOAD-TO-HASH BINDING established; signature NOT checked.
ok    CHAIN LINKAGE CHECKED: 2 sequenced receipt(s), 1 neighbouring link(s), contiguous from genesis (sequence 0) through sequence 1
      head sha256:edb166fb23ff0ebc3e2dfcd8fe1943a30d0577a712e0b32b2011c6697f98cb11
      NOT CHECKED: whether any receipt newer than sequence 1 exists. A missing tail
      cannot be detected from the receipts alone. Pin the head hash above against a head
      you hold independently.

INCOMPLETE: 0 of 2 receipt(s) passed the implemented per-receipt checks; one or more required checks could not be completed.
NOTE: INCOMPLETE is not a pass. The reason(s) are listed above.
NOTE: [TV-OUT-001] every FAIL and INCOMPLETE line names its check id in brackets; --list-checks lists them.

$ echo $?
2
```

With the key, the check runs and says so:

```
$ python3 telos_verify.py signed/ --key trusted.pub
ok    000.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    000.json  SIGNATURE CHECKED: Ed25519 signature verifies under caller-supplied key sha256:0a8ab0f29291afc0...
ok    001.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    001.json  SIGNATURE CHECKED: Ed25519 signature verifies under caller-supplied key sha256:0a8ab0f29291afc0...
ok    CHAIN LINKAGE CHECKED: 2 sequenced receipt(s), 1 neighbouring link(s), contiguous from genesis (sequence 0) through sequence 1
      head sha256:edb166fb23ff0ebc3e2dfcd8fe1943a30d0577a712e0b32b2011c6697f98cb11
      NOT CHECKED: whether any receipt newer than sequence 1 exists. A missing tail
      cannot be detected from the receipts alone. Pin the head hash above against a head
      you hold independently.

VERIFIED (SIGNED — CONTENT NOT VALIDATED): 2 receipt(s). The PAYLOAD-TO-HASH BINDING is established for 2 receipt(s).
NOTE: SIGNATURE CHECKED for 2 signed receipt(s): each Ed25519 signature verifies under a caller-supplied key.
NOTE: CHAIN LINKAGE CHECKED for all 2 receipt(s): 1 neighbouring link(s) validated; sequences are contiguous from genesis 0 through 1.
NOTE: chain COMPLETENESS was NOT assessed. Receipts newer than sequence 1 could be
      missing and nothing in this set would show it. Pin this observed head against a head you
      hold independently:  sha256:edb166fb23ff0ebc3e2dfcd8fe1943a30d0577a712e0b32b2011c6697f98cb11
NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and
      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not
      content: it does not show that a recorded action, verdict, or score is correct.
NOTE: the signature covers the integrity hash, so after the payload-to-hash check it binds
      the key to the canonical JSON payload. Fields outside the hash
      (issued_at, agent_id, kind, engine) are NOT covered by it. This is tamper-evident, not tamper-proof.
WARNING: CONTENT NOT VALIDATED. A valid signature does not show that the described
         action happened or that its parameters, verdict, or score are correct.

$ echo $?
0
```

### The negative control

A verifier that cannot be made to say FAILED has not been shown to check
anything. Flipping a single bit of the signature leaves the canonical
payload-to-hash relationship unchanged but alters the signature envelope:

```
$ python3 telos_verify.py tampered_sig.json --key trusted.pub
ok    tampered_sig.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
FAIL [TV-SIG-007] tampered_sig.json: signature does not verify under any key you supplied
        the receipt names a key you supplied, but its signature value does not verify for that key and integrity hash

FAILED: 0 of 1 receipt(s) passed the implemented per-receipt checks; one or more required checks failed.
NOTE: [TV-OUT-001] every FAIL and INCOMPLETE line names its check id in brackets; --list-checks lists them.

$ echo $?
1
```

The first line establishes only the canonical payload-to-hash relationship; it
does not say every envelope byte is intact. The signature failure establishes
only that the signature does not verify under a supplied key. It does not by
itself identify who wrote the receipt or decide whether the signature, key,
hash, or claimed issuer is authoritative. A receipt signed by some other key
fails the same way under `TV-SIG-006`, with the reason stated as `the receipt
names <key>, which is not a key you trust`.

The signed inputs above were made with a **throwaway keypair generated for the
run**. No key material is committed to this repository, so the key fingerprints
and signed heads you get will differ from the ones shown. The test suite builds
its own signed receipts the same way:

```bash
pip install cryptography
python3 -m unittest discover -s tests -v
```

### What a signed pass still does not show

- **Not "when".** `issued_at` is outside the hash, so it is outside the
  signature. A signed receipt does not date itself.
- **Not the envelope metadata.** `agent_id`, `kind` and `engine` are outside the
  hash for the same reason and are equally uncovered by the signature. The
  structure check looks only at their form.
- **Not that the verdict inside the payload was correct.** That is a question
  about judgement, not arithmetic, and no verifier can answer it.
- **Not tamper-proof.** Anyone holding the signing key can mint a receipt saying
  anything. Signing makes alteration by anyone else *evident*; it does not make
  the record true.

## Anchored mode

Anchored mode checks a signing key against a root key you trust, instead of
trusting the signing key directly. It needs `cryptography`, a root public key you
obtained independently (`--root-key`), and trust material: either `--trust-dir`,
holding one `trs-cert/0.1` certificate per `*.cert.json` file and the Lineage Chain
public projection as `projection.jsonl` (one `trs-lineage-projection/0.1` entry per
line, in sequence order), or a `trs-test-bundle/0.1` file given as the input path.

For each receipt it checks that:

- the receipt is `telos/0.2-ed25519` or `telos/0.3-ed25519` and its signature block
  carries `key_id` (`TV-ANCHOR-001`);
- the projection is a contiguous, hash-linked list of entries with exactly their
  published members, starting from a lineage anchor, each signed by the root key
  (`TV-REGISTRY-001` to `TV-REGISTRY-004`);
- a certificate names the receipt's key (`TV-TRUST-002`), verifies under the root
  key (`TV-TRUST-001`), and the receipt's signature verifies under the certified key
  (`TV-TRUST-003`);
- the certificate's purpose is `receipt_signing` (`TV-ANCHOR-002`), and on 0.3 the
  receipt's `scope_id` is present and matches the certificate's (`TV-ANCHOR-004`,
  `TV-ANCHOR-005`);
- the certificate has an issuance entry in the projection (`TV-TRUST-004`);
- the receipt can be placed before every rotate or revoke entry for its key, using
  root-signed checkpoint entries and projection order only. Timestamps are never
  used. A closing checkpoint that places the receipt after such an entry is FAILED
  (`TV-ANCHOR-006`); a receipt that cannot be placed, or whose certificate has a
  `valid_until`, is INCOMPLETE (`TV-ANCHOR-003`).

All certificate keys and a bundle's root key are checked for small-order and
non-canonical encodings when loaded (`TV-KEY-002`), whether or not a receipt uses
them. Trust material is never partly loaded: any unusable file refuses the whole
directory.

A test bundle run without `--root-key` uses the root key the bundle asserts for
itself. That root is not a trust anchor, so the verdict says `SELF-ROOTED TEST
BUNDLE — NOT ANCHORED` and a `WARNING: TEST BUNDLE` follows it (`TV-TRUST-006`).
Pass `--root-key` with a root you obtained independently to anchor it.

An anchored pass shows that the signatures trace back to the root key you supplied
through the certificates and projection you supplied. It does not show who controls
that root key, and it shows nothing more about the receipts' content than a signed
pass does.

## A file that says two things is refused

JSON does not forbid an object from carrying the same member name twice, and
parsers disagree about which one wins. Python keeps the **last**. A person
reading the file top to bottom takes the **first**.

That gap would be a forgery primitive for a tool like this one. A receipt carrying
`payload` twice shows an auditor one payload while the verifier hashes and
signature-checks the other, and the signature over the second payload is
perfectly genuine. Without this refusal the tool would print `VERIFIED (SIGNED)`,
exit `0`, over bytes nobody saw. No key access is needed to build one.

So a duplicate member name is refused at parse time, before any check runs:

```
$ python3 telos_verify.py dup_payload.json --key trusted.pub
INCOMPLETE [TV-PARSE-001] dup_payload.json: refused, duplicate key 'payload'. A file that repeats a member name shows one thing to a reader and another to a parser, so nothing about it can be verified honestly.

INCOMPLETE: 0 of 1 receipt(s) passed the implemented per-receipt checks; one or more required checks could not be completed.
NOTE: INCOMPLETE is not a pass. The reason(s) are listed above.
NOTE: [TV-OUT-001] every FAIL and INCOMPLETE line names its check id in brackets; --list-checks lists them.

$ echo $?
2
```

The refusal is recursive: a duplicate nested anywhere inside the payload is
caught the same way. This tool exists so a person can be confident about what a
file says, and a file that says two things cannot support that.

## What the verdict sentence is allowed to claim

The verdict reports linkage checked only when at least one neighbouring edge was
actually validated. Linkage is checked through `payload.sequence`, so a set with
zero sequenced receipts, and a set with exactly one, has no neighbouring link to
check. In those cases the tool says so rather than reporting a linked chain:

```
$ python3 telos_verify.py receipts-without-sequence/
ok    000.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    001.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
ok    002.json  PAYLOAD-TO-HASH BINDING: recorded hash matches canonical JSON of supplied payload
chain  NOT EVALUABLE: no receipt carries a `sequence` field, so there is no linkage to check.

VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED): PAYLOAD-TO-HASH BINDING ESTABLISHED for 3 receipt(s): each recorded hash matches canonical JSON of its supplied payload.
NOTE: CHAIN LINKAGE NOT EVALUABLE from this set. No receipt carries a `sequence` field, so no neighbouring link exists to check.
NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and
      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not
      content: it does not show that a recorded action, verdict, or score is correct.
WARNING: CONTENT NOT VALIDATED. Anyone can fabricate an unsigned receipt and
         compute a matching hash. This result does not show that the described action
         happened, that its parameters are genuine, or that its verdict/score is correct.
NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.

$ echo $?
0
```

The receipts passed their checks, so this is a pass on the questions that were
asked. What the tool declines to do is answer a question it never asked.

A payload that carries only one of `sequence` and `previous_receipt_integrity_hash`
is FAILED (`TV-CHAIN-004`), and two receipts with the same sequence are FAILED
without either being chosen (`TV-CHAIN-005`).

### The two ends of a chain are not the same

**The genesis end is anchored. The newest end is not.** This asymmetry is a real
property of the check, and the tool states it rather than averaging it into a
vague disclaimer.

Linkage requires the lowest sequence to be `0`, so **removing the genesis receipt
FAILS**, and so does removing anything in the middle, because the gap breaks
contiguity:

```
$ python3 telos_verify.py chain-missing-genesis/ --quiet
FAILED: 8 of 8 receipt(s) passed the implemented per-receipt checks; one or more required checks failed.
NOTE: Re-run without --quiet to see the failure or incomplete reason(s).
NOTE: [TV-OUT-001] every FAIL and INCOMPLETE line names its check id in brackets; --list-checks lists them.

$ echo $?
1
```

Nothing anchors the newest end. Delete the three most recent receipts and the six
that remain still start at genesis and still link without a gap, because that is
the truth about them:

```
$ python3 telos_verify.py chain-truncated/ --quiet
VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED): PAYLOAD-TO-HASH BINDING ESTABLISHED for 6 receipt(s): each recorded hash matches canonical JSON of its supplied payload.
NOTE: CHAIN LINKAGE CHECKED for all 6 receipt(s): 5 neighbouring link(s) validated; sequences are contiguous from genesis 0 through 5.
NOTE: chain COMPLETENESS was NOT assessed. Receipts newer than sequence 5 could be
      missing and nothing in this set would show it. Pin this observed head against a head you
      hold independently:  sha256:8652ac3735cd4fb78970550eb421cf9152e95fb62ebe70ae74902d14db5fb88e
NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and
      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not
      content: it does not show that a recorded action, verdict, or score is correct.
WARNING: CONTENT NOT VALIDATED. Anyone can fabricate an unsigned receipt and
         compute a matching hash. This result does not show that the described action
         happened, that its parameters are genuine, or that its verdict/score is correct.
NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.

$ echo $?
0
```

This is inherent without an external anchor: from inside a set of receipts, a
missing tail and a complete chain look identical. **What closes it is a head
obtained independently of the set.** Passing the full vector head above turns
a missing newest receipt into a reported failure, including under `--quiet`:

```
$ python3 telos_verify.py chain-missing-newest/ --expected-head-file vectors/valid/HEAD.sha256 --quiet
FAILED: 8 of 8 individual receipt check(s) passed; the chain-head check failed.
NOTE: Re-run without --quiet to see the failure or incomplete reason(s).
NOTE: expected chain head: sha256:0f7a0cf9c137739aa0afa37e376e600d7bed49bdbc2e458ea874d1f9a608e3b3
      observed chain head: sha256:7c5d3f2dd6a67e0341d2997eedb3b2ed56fe461280f4a82775400342fc8c39b5
NOTE: [TV-OUT-001] every FAIL and INCOMPLETE line names its check id in brackets; --list-checks lists them.

$ echo $?
1
```

The tool prints the observed head in the unpinned verdict too, so an operator can
retain it before moving the receipts. Supplying that independently held value on
a later run is what turns a changed newest end from an invisible omission into
a failure.

So: when the output explicitly says `CHAIN LINKAGE CHECKED`, the sequenced
receipts you were given start at genesis and their neighbouring links have no
gap. Exit `0` without that line is only a pass on the other checks named in the
output. Neither case means you were given every receipt.

## How the hash is computed

The receipt states its own covered fields:

```
"covered_fields": "payload (canonical JSON, sort_keys, compact separators)"
```

So the computation is:

1. Take the `payload` object.
2. Serialize as canonical JSON: sorted keys, compact separators, ASCII escaping.
3. Encode UTF-8, take SHA-256, prefix `sha256:`.

You can reproduce it in three lines without this tool as an independent
cross-check of the hash calculation:

```python
import json, hashlib
payload = json.load(open("vectors/valid/000_sb243.json"))["payload"]
print("sha256:" + hashlib.sha256(
    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
```

Chain linkage is checked through `payload.sequence` and
`payload.previous_receipt_integrity_hash`, which must equal the preceding
receipt's `integrity_hash`.

## Receipt schema

`docs/receipt-spec.schema.json` is the bundled JSON Schema for the
`telos/0.1-unsigned` envelope, and `docs/receipt-spec-signed.schema.json` is the
bundled schema for the `telos/0.2-ed25519` envelope. There is no bundled schema
file for `telos/0.3-ed25519`. The verifier does not load either file; its own
structure checks are described in
[Structure and field checks](#structure-and-field-checks). If you want a JSON
Schema validator's opinion as well, run a Draft 2020-12 validator against these
files separately. If a copy is hosted elsewhere, compare it independently; the
verifier does not fetch or establish the identity or currency of a remote copy.
See `docs/SPEC_NOTE.md` for scope.

## Repository contents

```
telos_verify.py                     the verifier's entry point
telos_verify_lib/                   the implementation; stdlib only except the signature path
telos_sign.py                       operator-invoked keygen/signer for telos/0.2-ed25519; requires cryptography
tests/                              executable tests; keys are generated inside the tests
tests/sabotage_harness.py           copy-only mutations that check named tests can fail
vectors/valid/                      nine receipts that verify
vectors/valid/HEAD.sha256           expected head for the bundled valid vector set
vectors/tampered/                   the same nine, one deliberately altered
vectors/fabricated/                 coherent but untrusted content; exercises output warnings
vectors/sample-receipt.json         a single action receipt, for the one-file case
docs/receipt-spec.schema.json       JSON Schema for the unsigned envelope
docs/receipt-spec-signed.schema.json  JSON Schema for the Ed25519-signed (0.2) envelope
docs/SPEC_NOTE.md                   scope and boundaries of the published spec
LICENSE                             Apache 2.0
NOTICE                              copyright and attribution
```

No key material of any kind is committed here. The signed test vectors are
generated in a temporary directory when the tests run, and deleted with it.

## Tests

```bash
pip install cryptography
python3 -m unittest discover -s tests -v
```

264 tests. Most drive the command-line tool in a subprocess and assert on exit
codes, because the exit code is what you would wire into CI; some call library
functions directly. They include
the signature negative controls above, the duplicate-key refusal on both the signed
and unsigned paths, the structure and field checks for all three versions, checks
that the verdict never claims linkage or completeness it did not establish, the
chain asymmetry in both directions (a removed genesis or middle receipt FAILS; a
removed tail passes unpinned but FAILS against the bundled expected head), anchored
mode and its checkpoint ordering, refusal of small-order and non-canonical keys,
the check id on every FAIL and INCOMPLETE line, controls showing the tool can
still tell good from bad, and two tests that run with `import cryptography` made
to fail, to show that the unsigned path needs no dependency and that the signed
path degrades to INCOMPLETE rather than to a pass.

The suite itself needs `cryptography`: most test modules import it to generate
keys.

Runs for this release, each `Ran 264 tests` and `OK`:

- Python 3.9.6 with cryptography 50.0.0
- Python 3.11.14 with cryptography 46.0.5
- Python 3.14.5 with cryptography 49.0.0, and again with cryptography 50.0.1

On Python 3.12.13 without `cryptography`, 11 of the test modules could not be
imported and the run failed, so that run says nothing about Python 3.12. Python 3.10 and 3.13 were not
available and are unverified.

`tests/sabotage_harness.py` breaks one named mechanism at a time in a disposable
copy of the repository and reruns the tests meant to catch that break. It runs
every child with Python bytecode caching off and clears cached bytecode after each
change, so one mutant does not run another mutant's compiled code; a control
(S0b) forces that collision and must still go red. For this release it reported
all 27 of its named mutations and the S0b control as caught, and exited `0`. The
harness speaks only about the mechanisms it names, not about every assertion in
the suite.

## License

Apache License 2.0. See `LICENSE`.
