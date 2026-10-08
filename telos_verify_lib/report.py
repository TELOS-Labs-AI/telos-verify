"""The verdict block: what a run established, and what it did not."""
from __future__ import annotations

from .common import FAILED, INCOMPLETE, VERIFIED
from .result import Result


def print_schema_limitation() -> None:
    """State exactly which structure was checked, in every successful output mode."""
    print("NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and")
    print("      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not")
    print("      content: it does not show that a recorded action, verdict, or score is correct.")


def print_report(r: Result, args, loaded: list, files: list) -> None:
    """Print the trace (unless --quiet) and the verdict block for a finished run."""
    if not args.quiet:
        for line in r.lines:
            print(line)
        print()
    print_verdict(r, args, loaded, files, chain_notes(r))
    print_trailer(r)


def chain_notes(r: Result) -> list[str]:
    """What the run established about linkage, and the end it could not reach."""
    # Every sentence below is gated on r.chain_checked, which only verify_chain
    # sets and only after validating every link. The file count is not evidence
    # that linkage ran, and using it as a proxy is how the tool came to assert
    # "the chain is intact" four lines under a note saying it was not checked.
    if not r.chain_checked:
        reason = r.chain_not_evaluable_reason or (
            "A required linkage check did not complete, so no linkage result is available."
        )
        return ["NOTE: CHAIN LINKAGE NOT EVALUABLE from this set. " + reason]
    # Linkage passed. Say what that established and, in the same breath, the
    # end it could not reach. The head hash goes in the NOTE rather than only
    # in the trace, because --quiet prints the verdict alone and the head is
    # the one value an outside record can be pinned against.
    # F1: "these receipts" is a claim about the WHOLE set. When some
    # receipts carry no `sequence` they were never linked at all, so that
    # sentence asserts work the run did not perform. Name the covered
    # subset instead, and carry the exclusion into the verdict block so it
    # survives --quiet -- the trace note above it does not.
    total = r.chain_linked + r.chain_excluded
    coverage = (f"{r.chain_linked} of {total} receipt(s)"
                if r.chain_excluded else
                f"all {r.chain_linked} receipt(s)")
    notes = [
        (f"NOTE: CHAIN LINKAGE CHECKED for {coverage}: {r.chain_linked - 1} "
         f"neighbouring link(s) validated; sequences are contiguous from genesis "
         f"0 through {r.chain_top_seq}."),
    ]
    if r.chain_excluded:
        notes += [
            (f"NOTE: {r.chain_excluded} receipt(s) carry no `sequence` field and were "
             "NOT linked at all."),
        ]
    if r.head_pin_matched:
        notes += [
            (f"NOTE: HEAD PIN CHECKED: the observed chain head matches the expected "
             f"head supplied by the caller: "
             f"{r.chain_head}"),
            ("      The verifier cannot determine whether that external pin is "
             "authoritative or current."),
        ]
    else:
        notes += [
            (f"NOTE: chain COMPLETENESS was NOT assessed. Receipts newer than sequence "
             f"{r.chain_top_seq} could be"),
            ("      missing and nothing in this set would show it. Pin this observed "
             "head against a head you"),
            f"      hold independently:  {r.chain_head}",
        ]
    return notes


def print_verdict(r: Result, args, loaded: list, files: list, chain_notes: list[str]) -> None:
    verdict = {VERIFIED: "VERIFIED", FAILED: "FAILED", INCOMPLETE: "INCOMPLETE"}[r.state]
    if r.state == VERIFIED and r.signed:
        print_signed(r, loaded, chain_notes)
    elif r.state == VERIFIED and r.unsigned:
        print(f"VERIFIED (UNSIGNED INTEGRITY ONLY — CONTENT NOT VALIDATED): "
              f"PAYLOAD-TO-HASH BINDING ESTABLISHED for {r.unsigned} receipt(s): each "
              "recorded hash matches canonical JSON of its supplied payload.")
        for line in chain_notes:
            print(line)
        print_schema_limitation()
        print("WARNING: CONTENT NOT VALIDATED. Anyone can fabricate an unsigned receipt and")
        print("         compute a matching hash. This result does not show that the described action")
        print("         happened, that its parameters are genuine, or that its verdict/score is correct.")
        print("NOTE: these receipts carry no signature, so this does NOT establish who issued them or when.")
    else:
        if r.state == FAILED and r.head_pin_checked and not r.head_pin_matched:
            print(f"FAILED: {len(loaded)} of {len(files)} individual receipt check(s) "
                  "passed; the chain-head check failed.")
        else:
            action = ("one or more required checks failed" if r.state == FAILED else
                      "one or more required checks could not be completed")
            print(f"{verdict}: {len(loaded)} of {len(files)} receipt(s) passed the "
                  f"implemented per-receipt checks; {action}.")
        if r.state == INCOMPLETE:
            if args.quiet:
                print("NOTE: INCOMPLETE is not a pass. Diagnostic detail was suppressed by --quiet.")
            else:
                print("NOTE: INCOMPLETE is not a pass. The reason(s) are listed above.")
        if args.quiet:
            print("NOTE: Re-run without --quiet to see the failure or incomplete reason(s).")
        if r.head_pin_checked and not r.head_pin_matched:
            print(f"NOTE: expected chain head: {r.expected_head}")
            print(f"      observed chain head: {r.chain_head}")


def print_signed(r: Result, loaded: list, chain_notes: list[str]) -> None:
    """The VERIFIED block when at least one signature was checked."""
    if r.unsigned:
        print(f"VERIFIED (MIXED AUTHENTICATION — CONTENT NOT VALIDATED): {r.signed} signed "
              f"and {r.unsigned} unsigned receipt(s). PAYLOAD-TO-HASH BINDING "
              f"ESTABLISHED for {len(loaded)} receipts: each recorded hash matches "
              "canonical JSON of its supplied payload.")
    elif r.self_rooted:
        print(f"VERIFIED (SELF-ROOTED TEST BUNDLE — NOT ANCHORED, CONTENT NOT VALIDATED): "
              f"{r.signed} receipt(s) internally consistent under the bundle's own root.")
    else:
        print(f"VERIFIED (SIGNED — CONTENT NOT VALIDATED): {r.signed} receipt(s). The "
              f"PAYLOAD-TO-HASH BINDING is established for {len(loaded)} receipt(s).")
    print_signed_basis(r)
    if r.anchored:
        print("NOTE: projection currency and completeness were NOT checked. Later rotate or revoke")
        print("      entries may be missing from the supplied projection. This version has no")
        print("      --expected-projection-head option to check an independently held projection head.")
    for line in chain_notes:
        print(line)
    print_schema_limitation()
    if r.unsigned:
        print(f"NOTE: {r.unsigned} receipt(s) carry no signature, so for those this does "
              "NOT establish who issued them or when.")
        print("WARNING: Anyone can fabricate each unsigned receipt and compute its matching hash.")
    print("NOTE: the signature covers the integrity hash, so after the payload-to-hash "
          "check it binds")
    print("      the key to the canonical JSON payload. Fields outside the hash")
    print("      (issued_at, agent_id, kind, engine) are NOT covered by it. This is "
          "tamper-evident, not tamper-proof.")
    print("WARNING: CONTENT NOT VALIDATED. A valid signature does not show that the described")
    print("         action happened or that its parameters, verdict, or score are correct.")


def print_signed_basis(r: Result) -> None:
    """Which key the signatures were checked under: self-rooted, anchored, or caller-supplied."""
    if r.self_rooted:
        print(f"NOTE: SELF-ROOTED for {r.anchored_ok} receipt(s): each signature, certificate "
              "and projection entry is consistent under the root key the bundle asserts")
        print("      for itself. That root is not a trust anchor, so NOT ANCHORED: no "
              "receipt is reported as anchored under it.")
    elif r.anchored:
        print(f"NOTE: ANCHORED for {r.anchored_ok} receipt(s): each Ed25519 signature verifies "
              "under a deployment key whose certificate verifies under the root key, whose")
        print("      issuance is logged in the root-signed Lineage Chain projection. Each receipt "
              "precedes every rotate or revoke entry for its key, by projection order.")
    else:
        print(f"NOTE: SIGNATURE CHECKED for {r.signed} signed receipt(s): each Ed25519 "
              "signature verifies under a caller-supplied key.")


def print_trailer(r: Result) -> None:
    """Warnings that survive every verdict: the test-bundle root and the check-id note."""
    if r.self_rooted:
        print("WARNING: TEST BUNDLE. The root key was taken from the bundle itself (section 4.11 "
              "test packaging).")
        print("         That is not a trust anchor: the result shows only that the bundle is "
              "internally consistent.")
        print("         Pass --root-key with a root you obtained independently to anchor it.")
    if r.saw_failed or r.saw_incomplete:
        print("NOTE: [TV-OUT-001] every FAIL and INCOMPLETE line names its check id in brackets; "
              "--list-checks lists them.")
