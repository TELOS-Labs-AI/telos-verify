"""The tri-state result every check reports into (section 3.6)."""
from __future__ import annotations

from .common import CHECKS, FAILED, INCOMPLETE, VERIFIED


class Result:
    def __init__(self):
        self.state = VERIFIED
        self.lines: list[str] = []
        self.unsigned = 0
        self.signed = 0
        # Set ONLY by verify_chain, and only when linkage was actually validated.
        # The verdict sentence reads this instead of inferring from the file
        # count, so the tool can never claim a chain it did not check.
        self.chain_checked = False
        # The head this run saw, and the highest sequence it reached. Carried to
        # the verdict because the head hash is the one thing an outside record
        # can be pinned against, and it must survive --quiet.
        self.chain_head: str | None = None
        self.chain_top_seq: int | None = None
        # How many receipts linkage actually COVERED, and how many it excluded.
        # The verdict sentence is built from these, never from the file count:
        # a set can contain receipts that carry no `sequence` and are therefore
        # outside linkage entirely, and saying "these receipts link" over such a
        # set is a pass plus a claim about work not performed.
        self.chain_linked = 0
        self.chain_excluded = 0
        # Human-facing reason used whenever fewer than two sequenced receipts
        # leave no neighbouring link to evaluate. A successful hash check must
        # not be promoted into a successful linkage claim.
        self.chain_not_evaluable_reason: str | None = None
        # A chain head becomes a completeness boundary only when the caller
        # supplies it independently. Keep both values so a mismatch remains
        # visible even under --quiet.
        self.expected_head: str | None = None
        self.head_pin_checked = False
        self.head_pin_matched = False

        self.saw_failed = False
        self.saw_incomplete = False
        # Anchored mode (section 4): set once trust material is loaded.
        self.anchored = False
        self.anchored_ok = 0
        self.test_bundle = False
        # TRS-S3-036: a test bundle checked under its own root (no --root-key).
        # The one guard: while set, nothing is reported as anchored.
        self.self_rooted = False
        # Receipts whose payload-to-hash binding was established. Linkage needs
        # only that binding, so a chain is still evaluated when a signature
        # could not be checked; a broken link is a proven break either way.
        self.bound: set[int] = set()

    def note(self, s): self.lines.append(s)

    def fail(self, check, s):
        assert check in CHECKS, check
        self.lines.append(f"FAIL [{check}] {s}")
        self.saw_failed = True
        self.state = FAILED

    def incomplete(self, check, s):
        assert check in CHECKS, check
        self.lines.append(f"INCOMPLETE [{check}] {s}")
        self.saw_incomplete = True
        # FAILED outranks INCOMPLETE: a proven break is worse than an unknown.
        if self.state != FAILED:
            self.state = INCOMPLETE
