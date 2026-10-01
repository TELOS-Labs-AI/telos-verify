"""Sequence contiguity, neighbouring links, and the caller's head pin."""
from __future__ import annotations

import pathlib

from .common import AG_CHAIN
from .result import Result


def verify_chain(receipts: list[tuple[pathlib.Path, dict]], r: Result) -> None:
    """Check sequence contiguity and neighbouring links where evaluable."""
    # A chained payload carries both chain members or neither (TRS-S4-001). One
    # without the other is neither a chain position nor an unchained receipt.
    if _half_chain_members(receipts, r):
        r.note("chain  NOT EVALUABLE: a chain member lacks its partner, so linkage was NOT checked.")
        return
    linked = _sequenced(receipts)
    if not linked:
        # Not an error and not a pass: there is simply nothing to link. Say so,
        # and leave r.chain_checked False so the verdict does not claim a chain.
        r.chain_linked = 0
        r.chain_excluded = len(receipts)
        r.chain_not_evaluable_reason = (
            "No receipt carries a `sequence` field, so no neighbouring link exists to check."
        )
        r.note("chain  NOT EVALUABLE: no receipt carries a `sequence` field, so there is "
               "no linkage to check.")
        return
    if len(linked) < len(receipts):
        r.note(f"chain  {len(receipts) - len(linked)} receipt(s) carry no `sequence` field and "
               "are outside the linkage check.")

    # Validate the TYPE of every `sequence` before sorting. Two different wrongs
    # live here and they fail in opposite directions.
    #
    #   bool is a subclass of int, so `True`/`False` compare equal to 1/0 and a
    #   boolean sequence sailed through as a clean, contiguous chain.
    #
    #   A str sequence raised TypeError inside sort(), which aborted the whole
    #   directory with process exit 1 -- reporting input the tool CANNOT evaluate
    #   as a proven failure. That inverts the tri-state: unevaluable input is
    #   INCOMPLETE, never FAILED.
    #
    # `type(x) is int` rather than isinstance(), precisely because bool would pass
    # isinstance and that is the defect.
    bad = _non_integer_sequences(linked)
    if bad:
        for path, seq in bad:
            r.incomplete("TV-CHAIN-001", f"{path.name}: `sequence` is {type(seq).__name__} ({seq!r}), "
                         "not an integer, so its chain position cannot be evaluated")
        r.note("chain  NOT EVALUABLE: a `sequence` value is not an integer, so linkage "
               "was NOT checked.")
        return

    # One sequenced receipt has no neighbour. Genesis-shaped fields can be
    # present, but zero edges means no linkage property was evaluated. This
    # guard is based on linkage participants, never total JSON-file count: an
    # unrelated unsequenced bystander cannot manufacture a chain pass.
    if len(linked) < 2:
        r.chain_linked = len(linked)
        r.chain_excluded = len(receipts) - len(linked)
        r.chain_not_evaluable_reason = (
            f"Only {len(linked)} of {len(receipts)} receipt(s) carries a `sequence` field; "
            "at least two sequenced receipts are needed to evaluate a neighbouring link."
        )
        r.note("chain  NOT EVALUABLE from this set: only one receipt carries a `sequence` "
               "field, so there is no neighbouring link to check.")
        return

    if _duplicate_sequences(linked, r):
        r.note("chain  NOT EVALUABLE: duplicate sequences, so linkage was NOT checked.")
        return

    linked.sort(key=lambda t: t[2].get("sequence", 0))
    linked_ok, head = _links(linked, r)
    if linked_ok:
        _record_chain(linked, len(receipts), head, r)


def _half_chain_members(receipts, r: Result) -> bool:
    """FAIL every payload carrying one chain member without the other; True if any did."""
    half = []
    for path, rec in receipts:
        p = rec.get("payload")
        if isinstance(p, dict) and (("sequence" in p) != (AG_CHAIN[1] in p)):
            has, lacks = (("sequence", AG_CHAIN[1]) if "sequence" in p
                          else (AG_CHAIN[1], "sequence"))
            half.append(path)
            r.fail("TV-CHAIN-004", f"{path.name}: chain member without its partner: payload "
                   f"has `{has}` but lacks `{lacks}`")
    return bool(half)


def _sequenced(receipts):
    """(path, receipt, payload) for each receipt whose payload carries `sequence`."""
    linked = []
    for path, rec in receipts:
        p = rec.get("payload", {})
        if isinstance(p, dict) and "sequence" in p:
            linked.append((path, rec, p))
    return linked


def _non_integer_sequences(linked):
    return [(path, p.get("sequence")) for path, _rec, p in linked
            if type(p.get("sequence")) is not int]


def _duplicate_sequences(linked, r: Result) -> bool:
    """FAIL every repeated sequence; True if any was repeated."""
    # Two receipts at one position are a copy or a fork (TRS-S4-007). Either way
    # the tool names it and keeps neither, rather than let a sort pick one.
    seen: dict[int, pathlib.Path] = {}
    dups = False
    for path, _rec, p in linked:
        seq = p["sequence"]
        if seq in seen:
            r.fail("TV-CHAIN-005", f"{path.name}: duplicate sequence {seq} (also {seen[seq].name}); "
                   "neither receipt is chosen")
            dups = True
        else:
            seen[seq] = path
    return dups


def _links(linked, r: Result):
    """(True, head hash) if the sorted receipts are contiguous and linked; else (False, None)."""
    expected_prev = None
    for i, (path, rec, p) in enumerate(linked):
        seq = p.get("sequence")
        if seq != i:
            r.fail("TV-CHAIN-002", f"{path.name}: sequence {seq} is not contiguous, expected {i}")
            return False, None
        prev = p.get("previous_receipt_integrity_hash")
        if prev != expected_prev:
            r.fail("TV-CHAIN-003", f"{path.name}: broken link at sequence {seq}")
            r.note(f"        points at {prev}")
            r.note(f"        expected  {expected_prev}")
            return False, None
        expected_prev = rec.get("integrity_hash")
    return True, expected_prev


def _record_chain(linked, total: int, head, r: Result) -> None:
    """Record a chain whose every link was validated."""
    # Only here — after every link was actually validated — may the verdict
    # sentence speak about the chain.
    #
    # Note precisely WHAT was established. The two ends of a chain are not
    # symmetric. The genesis end is anchored: the contiguity check requires the
    # lowest sequence to be 0, so a removed genesis receipt FAILS. The newest
    # end is not anchored by anything: receipts beyond the highest sequence
    # would simply be absent, and absence looks the same as completeness from
    # inside the set. So this run can prove where the chain STARTS and that the
    # neighbouring links it was given are consistent. It cannot prove it was given all of
    # them, and it must not say otherwise.
    r.chain_checked = True
    r.chain_linked = len(linked)
    r.chain_excluded = total - len(linked)
    r.chain_head = head
    r.chain_top_seq = linked[-1][2].get("sequence")
    r.note(f"ok    CHAIN LINKAGE CHECKED: {len(linked)} sequenced receipt(s), "
           f"{len(linked) - 1} neighbouring link(s), contiguous from genesis "
           f"(sequence 0) through sequence {r.chain_top_seq}")
    r.note(f"      head {head}")
    r.note(f"      NOT CHECKED: whether any receipt newer than sequence {r.chain_top_seq} "
           "exists. A missing tail")
    r.note("      cannot be detected from the receipts alone. Pin the head hash above "
           "against a head")
    r.note("      you hold independently.")


def check_expected_head(expected: str, r: Result) -> None:
    """Compare a verified chain head with a caller-supplied external pin."""
    r.expected_head = expected
    if not r.chain_checked:
        r.incomplete(
            "TV-HEAD-002",
            "expected head could not be checked because this run did not establish "
            "a linked chain head"
        )
        return

    r.head_pin_checked = True
    if r.chain_head != expected:
        r.fail("TV-HEAD-001", "chain head does not match the expected head supplied by the caller")
        r.note(f"        expected  {expected}")
        r.note(f"        observed  {r.chain_head}")
        return

    r.head_pin_matched = True
    r.note(f"ok    HEAD PIN CHECKED: observed chain head matches the caller-supplied "
           f"expected head: {expected}")
