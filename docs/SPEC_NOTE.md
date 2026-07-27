# Spec note: what the published schema covers, and what it does not

`receipt-spec.schema.json` describes the `telos/0.1-unsigned` envelope: the
outer record shape, the required fields, and the form of the integrity hash. It
is enough to write an independent verifier, which is the point of publishing it.

## Deliberately outside this schema

Being explicit is better than letting a reader assume the published surface is
the whole system.

- **The signing implementation.** This contract version is unsigned. How a future
  signed version produces and checks signatures is not described here.
- **Scoring internals.** `composite_score` and the per-dimension `scores` appear
  in the envelope as numbers. How they are computed, what weights combine them,
  and what thresholds map a score to a verdict are not part of this schema.
- **Purpose anchor construction.** `pa_id` names a purpose anchor. How an anchor
  is built or represented is not described here.
- **Payload shapes other than `action_governed`.** The envelope carries a `kind`
  field and other kinds reuse the same outer shape, but only `action_governed`
  has its payload constrained here.

## What this means for a verifier

A verifier built from this schema can check integrity and chain linkage. It
cannot, and should not claim to, evaluate whether a verdict was correct. Those
are different questions, and only the first one is a matter of arithmetic.

## Versioning

`receipt_version` is the contract identifier. A verifier should refuse a version
it does not know rather than guess, which is why `telos-verify` reports
INCOMPLETE rather than FAILED when it meets an unfamiliar version.
