# telos-verify

An offline command-line verifier for TELOS integrity-hash receipts.

Point it at a receipt, or at a directory of them, and it recomputes the hash from
the payload bytes and checks that the chain links. It makes **no network calls**,
needs **no installation**, and uses **only the Python standard library**, so there
is nothing to trust in the supply chain and nothing to configure. You can read the
whole thing in a few minutes, which is the point.

## What a passing check proves

Exactly two things:

1. **The payload matches the hash recorded on the receipt.** If a single character
   of the payload changed after the receipt was written, the recomputed hash will
   not match and the tool fails.
2. **The chain is intact.** Each receipt points at the previous receipt's hash and
   the sequence is contiguous from genesis to head, so records cannot be removed,
   reordered, or inserted without breaking a link. This second check applies only
   when you pass a directory. A single receipt cannot show its own chain position,
   and the tool says so rather than implying otherwise. See "One receipt versus a
   chain" below.

## What a passing check does NOT prove

**It does not establish who issued a receipt, or when.**

The `telos/0.1-unsigned` contract carries no digital signature. The `signature`
field is `null` and the receipt declares this about itself in `signing_status`.
An integrity hash is key-free: anyone can compute one, so a matching hash shows
the payload is unchanged relative to the recorded hash, and nothing about
authorship. Whoever can write the receipt can write a matching hash.

This is stated in the TELOS whitepaper and it is repeated here because the tool
should not be more confident than the artifact deserves. A future signed contract
version fills `signature` and changes `signing_status` without changing the
envelope shape; this tool already refuses to treat a signed receipt as verified
while it has no published root key to check against, and reports INCOMPLETE
instead. It never silently skips a check.

`issued_at` is deliberately outside the hash, so the same logical payload always
produces the same hash. That means the timestamp is metadata and is **not**
covered by the integrity check.

## Install

There is nothing to install. You need Python 3.9 or newer.

```bash
git clone https://github.com/TELOS-Labs-AI/telos-verify.git
cd telos-verify
python3 telos_verify.py --help
```

## Usage

```bash
python3 telos_verify.py <path-to-receipt.json>     # one receipt
python3 telos_verify.py <path-to-directory>        # a chain
python3 telos_verify.py <path> --quiet             # verdict line only
```

### Exit codes, three states

| Code | State | Meaning |
|---|---|---|
| `0` | VERIFIED | Every check that could be run, passed. |
| `1` | FAILED | A hash mismatch or a broken chain link. The record is not intact. |
| `2` | INCOMPLETE | Verification could not be completed: unreadable input, an unknown contract version, or a receipt claiming a signature while the material needed to check it is absent. |

`INCOMPLETE` is never reported as a pass. This matters if you are wiring the tool
into CI: `python3 telos_verify.py receipts/ && echo VERIFIED` prints nothing
unless the exit code is `0`.

### One receipt versus a chain

The two modes prove different things, and the tool is explicit about which one
you got.

- **A directory** checks every hash **and** the chain linkage, so a pass means
  both the payloads and their ordering are intact.
- **A single receipt** checks the hash only. A single receipt cannot demonstrate
  its own chain position, because the linkage lives in its neighbours. The tool
  reports chain linkage as NOT EVALUABLE, and says so in the output rather than
  quietly leaving it out. The exit code reflects the hash check alone.

So a valid receipt exits `0` whatever its sequence number, and the run tells you
plainly that chain integrity was not assessed:

```
$ python3 telos_verify.py vectors/valid/004_harmbench.json
ok    004_harmbench.json  hash matches
chain  NOT EVALUABLE from a single receipt. Chain linkage needs the neighbouring receipts,
       so this run neither confirms nor denies chain integrity. Pass the directory to check the chain.

VERIFIED (UNSIGNED): 1 receipt. The payload matches the recorded hash.
NOTE: chain integrity was NOT assessed. A single receipt cannot show its own chain position.
NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.

$ echo $?
0
```

Absence of chain evidence is not evidence of tampering, so this is neither a pass
nor a failure on that question. If you hold one receipt and want the chain
checked too, you need the neighbouring receipts and should pass the directory.

## Test vectors, with real output

Two vectors ship with the repository. Both outputs below were produced by running
the commands shown, and are pasted verbatim.

### 1. A chain that verifies

Nine receipts from a real published benchmark re-verification. They are unsigned,
and they are the same records published alongside the corresponding Zenodo DOIs.

```
$ python3 telos_verify.py vectors/valid
ok    000_sb243.json  hash matches
ok    001_xstest_generic.json  hash matches
ok    002_xstest_healthcare_hipaa.json  hash matches
ok    003_ailuminate.json  hash matches
ok    004_harmbench.json  hash matches
ok    005_medsafetybench.json  hash matches
ok    006_agentharm.json  hash matches
ok    007_propensitybench.json  hash matches
ok    008_agentdojo.json  hash matches
ok    chain of 9 receipts links cleanly from genesis to head
      head sha256:0f7a0cf9c137739aa0afa37e376e600d7bed49bdbc2e458ea874d1f9a608e3b3

VERIFIED (UNSIGNED): 9 receipt(s). The payload matches the recorded hash and the chain is intact.
NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.

$ echo $?
0
```

### 2. A chain with one altered receipt

The same nine receipts, with exactly one change: in `004_harmbench.json` the
payload's `current` field was edited from `0.00%` to `99.99%`, and the recorded
`integrity_hash` was left untouched. This is the shape of the attack the receipt
exists to catch, someone restating a result after the fact.

```
$ python3 telos_verify.py vectors/tampered
ok    000_sb243.json  hash matches
ok    001_xstest_generic.json  hash matches
ok    002_xstest_healthcare_hipaa.json  hash matches
ok    003_ailuminate.json  hash matches
FAIL  004_harmbench.json: payload does not match recorded hash
        recorded  sha256:f0549f563add4bbfaf14b3bc172c0d5c305619030e090d2498f8c99319565d68
        recomputed sha256:ef47a8caf12b610d39a7b9ea15a8ed62adf4c46a0e0ff6053f748efa7925cf1d
ok    005_medsafetybench.json  hash matches
ok    006_agentharm.json  hash matches
ok    007_propensitybench.json  hash matches
ok    008_agentdojo.json  hash matches

FAILED: 8 of 9 receipt(s) verified.

$ echo $?
1
```

Note what the tool does not do: it does not guess which version was the true one.
It reports that the record no longer matches its own hash and stops.

**Why eight lines say `ok` under a directory named `tampered`.** Only one file in
`vectors/tampered/` is altered. The other eight are byte-identical to the valid
set on purpose, so the vector shows the tool finding the single bad record inside
an otherwise intact set, which is the realistic case. A directory where every
receipt failed would prove much less.

## How the hash is computed

The receipt states its own covered fields:

```
"covered_fields": "payload (canonical JSON, sort_keys, compact separators)"
```

So the computation is:

1. Take the `payload` object.
2. Serialize as canonical JSON: sorted keys, compact separators, ASCII escaping.
3. Encode UTF-8, take SHA-256, prefix `sha256:`.

You can reproduce it in three lines without this tool at all, which is the
strongest form of verification because it does not require trusting our code:

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

`docs/receipt-spec.schema.json` is the JSON Schema for the unsigned envelope. It
is the same document published at `https://telos-labs.ai/docs/receipt-spec.schema.json`.
See `docs/SPEC_NOTE.md` for what the schema deliberately does not cover.

## Repository contents

```
telos_verify.py                     the verifier, standard library only
vectors/valid/                      nine receipts that verify
vectors/tampered/                   the same nine, one deliberately altered
vectors/sample-receipt.json         a single action receipt, for the one-file case
docs/receipt-spec.schema.json       JSON Schema for the unsigned envelope
docs/SPEC_NOTE.md                   scope and boundaries of the published spec
LICENSE                             Apache 2.0
NOTICE                              copyright and attribution
```

## License

Apache License 2.0. See `LICENSE`.
