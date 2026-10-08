# Review this verifier in about 10 minutes

This repository contains the open, offline verifier for TELOS receipts. The
scoring engine is not here. This review checks the verifier's behavior and the
claims its documentation makes about that behavior.

## 1. Clone at a pinned commit

You need Git and Python 3.9 or later. The commands below were exercised with
Python 3.14.5; that does not establish behavior on every supported version.
The bundled unsigned examples need no third-party Python packages.

Run these commands one at a time:

```sh
git clone https://github.com/TELOS-Labs-AI/telos-verify.git telos-verify-review
cd telos-verify-review
git checkout --detach 7bfa4970d4e3a3cb042634ebe79bc890486cb720
git rev-parse HEAD
python3 --version
```

The clone is the only network step; everything after it runs offline.
The printed commit must be exactly
`7bfa4970d4e3a3cb042634ebe79bc890486cb720`. Stop if checkout fails or the
commit differs.

### Fully offline alternative

Start with a local checkout or Git mirror named `telos-verify-source` that
contains the pinned commit. From its parent directory, run:

```sh
git clone --no-hardlinks ./telos-verify-source ./telos-verify-review
cd telos-verify-review
git checkout --detach 7bfa4970d4e3a3cb042634ebe79bc890486cb720
git rev-parse HEAD
python3 --version
```

These commands clone locally and make no network requests. Apply the same
commit check above.

## 2. Check the bundled examples

Run the valid baseline first:

```sh
python3 telos_verify.py vectors/valid
```

Expect exit `0`, with `VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED)`.
The output should report nine receipts and eight neighboring chain links checked.
It also says chain completeness was not assessed.

Then run the altered set:

```sh
python3 telos_verify.py vectors/tampered
```

Expect exit `1`, with `FAILED` and a `FAIL [TV-HASH-004]` line for
`004_harmbench.json`. Its payload was changed while its recorded hash was kept.
The other eight receipts match the valid set, so eight `ok` lines are expected.
They do not make the whole run a pass.

List the implemented checks:

```sh
python3 telos_verify.py --list-checks
```

Expect exit `0` and one `CHECK` line per check id. This lists the checks; it does
not run them. Match diagnostic ids to this list when investigating a result.

## 3. Interpret the exit code

| Exit | Meaning |
|---|---|
| `0` — VERIFIED | Every implemented check that applied to the supplied input passed. Read the output to see which checks ran and their limits. An unsigned pass does not validate content. |
| `1` — FAILED | At least one check found a contradiction, such as a mismatched hash, invalid field, or broken link. |
| `2` — INCOMPLETE | Verification could not finish, for example because input was unreadable, the receipt version was unknown, or required signature material was missing. This is not a pass. Invalid command-line arguments also exit `2`, with a usage error. |

If FAILED and INCOMPLETE occur together, FAILED takes precedence: exit `1`.
Record the actual exit status as well as stdout and stderr; an `ok` line alone
does not establish success.

## What counts as a finding

- A tampered input that passes a check meant to detect that change, such as an
  edited payload with its original hash. State which contract rule it violates.
- A valid input that fails an applicable check.
- `VERIFIED` on input for which a required check cannot be completed.
- Documentation that overstates what the verifier checks or what a pass proves.

Compare a failing example with a valid baseline from the same commit. Work on
copies of the inputs and describe every edit so someone else can reproduce it.
An unsigned payload rewritten together with its hash can pass by design; that
alone is not a verifier defect.

## Scope limits

The verifier reports a receipt whose payload no longer matches its recorded
hash; it cannot prevent the change. With unsigned receipts, whoever writes the
receipt can also rewrite the hash. The unsigned
`telos/0.1-unsigned` contract checks payload structure, the hash of canonical JSON,
and neighboring links when at least two sequenced receipts are supplied. It
carries no signature. Anyone can rewrite an unsigned payload, its hash, and its
chain links together.

A hash match does not validate content or identify an issuer. It does not prove
that an action happened or that a recorded score or verdict is correct. JSON
whitespace and object-key order are not covered; envelope metadata such as
`issued_at` is outside the payload hash. Signed receipts require additional key
material and the optional `cryptography` package; the unsigned examples above
do not exercise signature or anchored verification.

Chain linkage does not detect receipts omitted from the newest end. The
`--expected-head` and `--expected-head-file` options can compare a receipt-chain
head with an independently held value; the verifier cannot establish whether
that external value is authoritative or current.

This version does not check whether a supplied key projection is current or
complete; later key rotations or revocations may be absent. Receipt-chain head
options do not check the projection head.

This repository is the open verifier only. It does not contain or rerun the
scoring engine, and a verifier result is not an assessment of that engine.

## How to report

For a reproducible behavior or documentation finding, open a
[GitHub issue using the finding template](https://github.com/TELOS-Labs-AI/telos-verify/issues/new?template=finding.md).
Include the commit, OS and Python version, exact command, input or construction
steps, expected and observed exit status and output, and the relevant check id.

Use [GitHub private vulnerability reporting](https://github.com/TELOS-Labs-AI/telos-verify/security/advisories/new)
for security-sensitive reports; see [SECURITY.md](SECURITY.md).
