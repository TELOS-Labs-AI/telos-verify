"""Implementation of telos-verify. Run it as `python3 telos_verify.py`.

Modules, in the order a run uses them:
  common    contract constants and the check registry (section 3.6)
  result    the tri-state result every check reports into
  inputs    reading receipts, chain files and trust directories
  keys      Ed25519 key loading and key acceptance (small-order, canonical)
  schema    section 1 structure, section 2 value forms, canonical JSON
  receipt   one receipt: structure, hash, canonical domain, signature
  chain     sequence contiguity, links, and the head pin
  anchored  section 4: projection, certificates, checkpoint ordering
  cli       argument parsing and the run itself
  report    the verdict block
"""
