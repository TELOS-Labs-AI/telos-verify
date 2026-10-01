#!/usr/bin/env python3
"""Prove named controls go red when their claimed mechanism is broken.

Every mutation runs against a temporary COPY of the repository. The live source
tree is read-only to this harness, so a reviewer can validate restore claims
without granting the harness permission to rewrite the artifact under review.

Classification uses each targeted unittest process's exit code and its summary,
not the wrapped ``unittest -v`` progress line that produced false-red reports in
the previous harness.

Bytecode isolation: Python reuses a cached .pyc when the source file's size and
mtime (whole seconds) match the cache. Two mutants of one file with the same
byte length, written within one second, would then run the FIRST mutant's code
for the SECOND. So every child runs with PYTHONDONTWRITEBYTECODE=1, every
__pycache__ in the copy is removed after each source write, and the
S0b control forces that collision and requires the second mutant to go red.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent

SABOTAGES = {
    "S1_remove_minimum_link_participants_guard": {
        "file": "telos_verify_lib/chain.py",
        "edits": [
            (
                '''    if len(linked) < 2:
        r.chain_linked = len(linked)
        r.chain_excluded = len(receipts) - len(linked)
        r.chain_not_evaluable_reason = (
            f"Only {len(linked)} of {len(receipts)} receipt(s) carries a `sequence` field; "
            "at least two sequenced receipts are needed to evaluate a neighbouring link."
        )
        r.note("chain  NOT EVALUABLE from this set: only one receipt carries a `sequence` "
               "field, so there is no neighbouring link to check.")
        return''',
                '''    if False:
        pass''',
            ),
        ],
        "tests": [
            "test_ed25519.Round3_H1_LinkageRequiresANeighbour.test_one_sequenced_receipt_plus_bystander_never_claims_linkage",
            "test_ed25519.Round3_H1_LinkageRequiresANeighbour.test_unsequenced_bystander_does_not_change_the_linkage_disposition",
        ],
    },
    "S2_remove_sequence_type_guard": {
        "file": "telos_verify_lib/chain.py",
        "edits": [
            (
                '''    if bad:
        for path, seq in bad:
            r.incomplete("TV-CHAIN-001", f"{path.name}: `sequence` is {type(seq).__name__} ({seq!r}), "
                         "not an integer, so its chain position cannot be evaluated")
        r.note("chain  NOT EVALUABLE: a `sequence` value is not an integer, so linkage "
               "was NOT checked.")
        return''',
                '''    if False:
        pass''',
            ),
        ],
        "tests": [
            "test_ed25519.Tier2_F2_SequenceTypeIsValidated.test_boolean_sequence_cannot_report_a_clean_chain",
            "test_ed25519.Tier2_F2_SequenceTypeIsValidated.test_string_sequence_is_INCOMPLETE_not_a_crash_and_not_FAILED",
            "test_ed25519.Tier2_F2_SequenceTypeIsValidated.test_the_reason_names_the_offending_type",
        ],
    },
    "S3_incomplete_overwrites_failed": {
        "file": "telos_verify_lib/result.py",
        "edits": [
            (
                '''        if self.state != FAILED:
            self.state = INCOMPLETE''',
                '''        self.state = INCOMPLETE''',
            ),
        ],
        "tests": [
            "test_ed25519.Tier2_F3_FailedOutranksIncomplete.test_FAILED_outranks_INCOMPLETE_failed_first",
        ],
    },
    "S3b_failed_cannot_override_incomplete": {
        "file": "telos_verify_lib/result.py",
        "edits": [
            (
                '''        self.saw_failed = True
        self.state = FAILED''',
                '''        self.saw_failed = True
        if self.state != INCOMPLETE:
            self.state = FAILED''',
            ),
        ],
        "tests": [
            "test_ed25519.Tier2_F3_FailedOutranksIncomplete.test_FAILED_outranks_INCOMPLETE_incomplete_first",
        ],
    },
    "S4_require_signature_option_removed": {
        "file": "telos_verify_lib/cli.py",
        "edits": [
            (
                '''    if args.require_signature and r.unsigned:''',
                '''    if False and r.unsigned:''',
            ),
        ],
        "tests": [
            "test_ed25519.Ed25519Path.test_require_signature_distinguishes_all_signed_from_one_unsigned",
        ],
    },
    "S5_verify_chain_noop": {
        "file": "telos_verify_lib/chain.py",
        "edits": [
            (
                '''    """Check sequence contiguity and neighbouring links where evaluable."""''',
                '''    """Check sequence contiguity and neighbouring links where evaluable."""
    return''',
            ),
        ],
        "tests": [
            "test_ed25519.ChainCompleteness.test_control_chain_checker_distinguishes_intact_from_broken_link",
        ],
    },
    "S6_expected_head_comparison_removed": {
        "file": "telos_verify_lib/chain.py",
        "edits": [
            (
                '''    if r.chain_head != expected:''',
                '''    if False:''',
            ),
        ],
        "tests": [
            "test_ed25519.ExpectedHeadPinning.test_truncated_tail_FAILS_against_the_published_head_even_under_quiet",
        ],
    },
    "S7_unsigned_content_warning_removed": {
        "file": "telos_verify_lib/report.py",
        "edits": [
            (
                '''        print("WARNING: CONTENT NOT VALIDATED. Anyone can fabricate an unsigned receipt and")
        print("         compute a matching hash. This result does not show that the described action")
        print("         happened, that its parameters are genuine, or that its verdict/score is correct.")''',
                '''        print("NOTE: unsigned hash matched")''',
            ),
        ],
        "tests": [
            "test_ed25519.UnsignedContentMessaging.test_fabricated_unsigned_claim_exits_zero_but_says_content_not_validated",
        ],
    },
    "S8_schema_boundary_note_removed": {
        "file": "telos_verify_lib/report.py",
        "edits": [
            (
                '''def print_schema_limitation() -> None:
    """State exactly which structure was checked, in every successful output mode."""
    print("NOTE: SCHEMA CHECKED against the TELOS Receipt Standard v0.1 section 1 structure and")
    print("      section 2 scoring-field forms (TV-SCHEMA-001, TV-S2-*). That is structure, not")
    print("      content: it does not show that a recorded action, verdict, or score is correct.")''',
                '''def print_schema_limitation() -> None:
    pass''',
            ),
        ],
        "tests": [
            "test_ed25519.UnsignedContentMessaging.test_fabricated_unsigned_claim_exits_zero_but_says_content_not_validated",
        ],
    },
    "S9_quiet_failure_clarity_removed": {
        "file": "telos_verify_lib/report.py",
        "edits": [
            (
                '''            action = ("one or more required checks failed" if r.state == FAILED else
                      "one or more required checks could not be completed")
            print(f"{verdict}: {len(loaded)} of {len(files)} receipt(s) passed the "
                  f"implemented per-receipt checks; {action}.")''',
                '''            print(f"{verdict}: {len(loaded)} of {len(files)} receipt(s) verified.")''',
            ),
            (
                '''        if args.quiet:
            print("NOTE: Re-run without --quiet to see the failure or incomplete reason(s).")''',
                '''        if args.quiet:
            pass''',
            ),
        ],
        "tests": [
            "test_ed25519.ExistingBehaviourUnchanged.test_tampered_chain_quiet_output_is_standalone_and_not_contradictory",
            "test_ed25519.ChainCompleteness.test_broken_link_quiet_output_is_standalone_and_not_contradictory",
            "test_ed25519.ExpectedHeadPinning.test_missing_head_file_quiet_output_points_to_visible_diagnostics",
        ],
    },
    "S10_signed_action_schema_parity_removed": {
        "file": "docs/receipt-spec-signed.schema.json",
        "edits": [
            (
                '''"required": ["action_name", "action_params_hash", "verdict", "composite_score", "scores", "pa_id"]''',
                '''"required": ["action_name", "action_params_hash", "verdict", "composite_score", "pa_id"]''',
            ),
        ],
        "tests": [
            "test_ed25519.PublishedSchemaConsistency.test_signed_and_unsigned_structural_constraints_differ_only_in_three_fields",
        ],
    },
    "S11_signed_base64_constraints_removed": {
        "file": "docs/receipt-spec-signed.schema.json",
        "edits": [
            (
                '''"pattern": "^[A-Za-z0-9+/]{43}=$"''',
                '''"pattern": ".*"''',
            ),
            (
                '''"pattern": "^[A-Za-z0-9+/]{86}==$"''',
                '''"pattern": ".*"''',
            ),
        ],
        "tests": [
            "test_ed25519.PublishedSchemaConsistency.test_signed_schema_rejects_non_base64_signature_material",
        ],
    },
    "S12_fabricated_vector_schema_fields_removed_with_hash_repaired": {
        "file": "vectors/fabricated/unsigned-content-claim.json",
        "edits": [
            (
                '''    "composite_score": 1.0,
    "scores": {
      "fabricated_score": 1.0
    },
    "pa_id": "untrusted/fabricated-purpose-anchor"''',
                '''    "composite_score": 1.0''',
            ),
            (
                '''"integrity_hash": "sha256:0277fa6cf19871125d21e84c725a69966616f883ff626560f808eb606f275c2e"''',
                '''"integrity_hash": "sha256:34fcf6f297b9675fb7f564664145b3856e70a7da5c32dbbaa75a1622a8a24b38"''',
            ),
        ],
        "tests": [
            "test_ed25519.UnsignedContentMessaging.test_fabricated_vector_meets_bundled_action_schema_constraints",
        ],
    },
    'S13_certificate_root_signature_not_checked': {
        "file": "telos_verify_lib/anchored.py",
        "edits": [
            (
                '            and ed25519_ok(root_raw, cert.get("root_signature"), CERT_COVERS, chash)):',
                '            and True):',
            ),
        ],
        "tests": ['test_s3_conformance.Anchored.test_trust_001_certificate_changed_after_signing', 'test_s3_conformance.Anchored.test_trust_001_certificate_signed_by_other_root'],
    },
    'S14_projection_link_not_checked': {
        "file": "telos_verify_lib/anchored.py",
        "edits": [
            (
                '        if why:\n            r.fail("TV-REGISTRY-001",',
                '        if False:\n            r.fail("TV-REGISTRY-001",',
            ),
        ],
        "tests": ['test_s3_conformance.Anchored.test_registry_001_broken_link', 'test_s3_conformance.Anchored.test_registry_001_this_hash_wrong'],
    },
    'S15_unlogged_certificate_accepted': {
        "file": "telos_verify_lib/anchored.py",
        "edits": [
            (
                '    if not issued:\n        r.fail("TV-TRUST-004",',
                '    if False:\n        r.fail("TV-TRUST-004",',
            ),
        ],
        "tests": ['test_s3_conformance.Anchored.test_trust_004_unlogged_certificate'],
    },
    'S16_revocation_ignored': {
        "file": "telos_verify_lib/anchored.py",
        "edits": [
            (
                '    if placed == "undecided" or cert.get("valid_until") is not None:',
                '    if False:',
            ),
        ],
        "tests": ['test_s3_conformance.Anchored.test_anchor_003_revoked_is_incomplete', 'test_s3_conformance.Anchored.test_anchor_003_valid_until_is_incomplete'],
    },
    'S17_schema_check_removed': {
        "file": "telos_verify_lib/receipt.py",
        "edits": [
            (
                '    problems = schema_problems(receipt)',
                '    problems = []',
            ),
        ],
        "tests": ['test_s3_conformance.Schema.test_missing_member', 'test_s3_conformance.Schema.test_extra_member'],
    },
    'S18_canonical_domain_removed': {
        "file": "telos_verify_lib/receipt.py",
        "edits": [
            (
                '    domain = canon_problems(receipt["payload"])',
                '    domain = []',
            ),
        ],
        "tests": ['test_s3_conformance.HashAndCanon.test_canon_001_float_out_of_range', 'test_s3_conformance.HashAndCanon.test_canon_002_unpaired_surrogate'],
    },
    'S19_chain_file_resorted_silently': {
        "file": "telos_verify_lib/inputs.py",
        "edits": [
            (
                '            if seqs[i] < seqs[i - 1]:',
                '            if False:',
            ),
        ],
        "tests": ['test_s3_conformance.Chains.test_chain_006_reordered_file'],
    },
    'S20_check_tags_dropped': {
        "file": "telos_verify_lib/result.py",
        "edits": [
            (
                '        self.lines.append(f"FAIL [{check}] {s}")',
                '        self.lines.append(f"FAIL  {s}")',
            ),
        ],
        "tests": ['test_s3_conformance.ListChecks.test_out_001_trailer_and_tags'],
    },
    'S21_small_order_keys_accepted': {
        "file": "telos_verify_lib/keys.py",
        "edits": [
            ('    if pt[0] == 0 and pt[1] == pt[2]:', '    if False:'),
        ],
        "tests": ['test_small_order.SmallOrderKeys.test_identity_forgery_with_key_is_refused',
                  'test_small_order.SmallOrderKeys.test_identity_root_key_bundle_never_anchored'],
    },
    'S22_caller_key_not_admitted': {
        "file": "telos_verify_lib/keys.py",
        "edits": [
            ('return key_id(admit_key(raw)), Ed25519PublicKey', 'return key_id(raw), Ed25519PublicKey'),
        ],
        "tests": ['test_small_order.SmallOrderKeys.test_identity_forgery_with_key_is_refused',
                  'test_small_order.SmallOrderKeys.test_identity_root_key_bundle_never_anchored'],
    },
    'S23_embedded_key_not_admitted': {
        "file": "telos_verify_lib/keys.py",
        "edits": [
            ('        return None\n    return admit_key(raw)\n', '        return None\n    return raw\n'),
        ],
        "tests": ['test_small_order.SmallOrderKeys.test_identity_bundle_root_embedded_is_failed',
                  'test_small_order.SmallOrderKeys.test_certified_small_order_child_key_is_failed'],
    },
    'S24_unused_certificates_not_scanned': {
        "file": "telos_verify_lib/keys.py",
        "edits": [
            ('        except KeyRefused as e:\n            return n, e\n    return None',
             '        except KeyRefused as e:\n            pass\n    return None'),
        ],
        "tests": ['test_small_order.SmallOrderKeys.test_unused_small_order_certificate_in_trust_dir_is_failed',
                  'test_small_order.SmallOrderKeys.test_unused_small_order_certificate_in_bundle_is_failed'],
    },
    'S25_closing_adjacency_dropped': {
        "file": "telos_verify_lib/anchored.py",
        "edits": [
            ('        if applies and c["sequence"] == ev["sequence"] - 1:',
             '        if applies:'),
        ],
        "tests": ['test_checkpoint_order.CheckpointOrder.test_non_adjacent_checkpoint_higher_sequence_is_undecided'],
    },
    'S26_checkpoint_head_hash_not_matched': {
        "file": "telos_verify_lib/anchored.py",
        "edits": [
            ('                   and (c["chain_sequence"], c["chain_head"]) in chain_heads)',
             '                   and c["chain_sequence"] in {q for q, _ in chain_heads})'),
        ],
        "tests": ['test_checkpoint_order.CheckpointOrder.test_checkpoint_head_on_another_chain_is_undecided',
                  'test_checkpoint_order.CheckpointOrder.test_checkpoint_head_at_wrong_sequence_is_undecided'],
    },
}


def copy_repo(parent: pathlib.Path) -> pathlib.Path:
    candidate = parent / "candidate"
    shutil.copytree(
        REPO,
        candidate,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "review-artifacts"),
    )
    return candidate


CHILD_ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}


def purge_bytecode(candidate: pathlib.Path) -> None:
    """Remove every cached .pyc in the copy, so the next run compiles the source on disk."""
    for cache in candidate.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)


def write_source(candidate: pathlib.Path, target: pathlib.Path, text: str) -> None:
    target.write_text(text, encoding="utf-8")
    purge_bytecode(candidate)


def run_suite(candidate: pathlib.Path):
    return subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=candidate,
        capture_output=True,
        text=True,
        check=False,
        env=CHILD_ENV,
    )


def run_test(candidate: pathlib.Path, test: str):
    return subprocess.run(
        [sys.executable, "-m", "unittest", test],
        cwd=candidate / "tests",
        capture_output=True,
        text=True,
        check=False,
        env=CHILD_ENV,
    )


def bytecode_isolation_control(candidate: pathlib.Path) -> str:
    """S0b: two same-length mutants of keys.py with one mtime; the second must still go red.

    S22 and S23 shorten keys.py by the same number of bytes. Without isolation,
    the S22 run caches bytecode that the S23 run then reuses, and S23's targeted
    tests stay green although its mutation breaks the guard they test.
    """
    first, second = SABOTAGES["S22_caller_key_not_admitted"], SABOTAGES["S23_embedded_key_not_admitted"]
    target = candidate / first["file"]
    original = target.read_text(encoding="utf-8")
    m1 = apply_edits(original, first["edits"], "S0b/S22")
    m2 = apply_edits(original, second["edits"], "S0b/S23")
    if len(m1.encode()) != len(m2.encode()):
        raise AssertionError("S0b: the two mutants no longer have equal length; pick another pair")
    stamp = (1_700_000_000, 1_700_000_000)
    write_source(candidate, target, m1)
    os.utime(target, stamp)
    run_test(candidate, first["tests"][0])
    target.write_text(m2, encoding="utf-8")   # deliberately no purge here: the collision under test
    os.utime(target, stamp)
    red = [t for t in second["tests"] if classified_red(run_test(candidate, t))]
    write_source(candidate, target, original)
    ok = red == second["tests"]
    return (f"S0b_stale_bytecode_isolation: {'DEMONSTRATED' if ok else 'ASSERTED'} "
            f"({len(red)}/{len(second['tests'])} targeted controls red)")


def apply_edits(source: str, edits, name: str) -> str:
    mutated = source
    for old, new in edits:
        count = mutated.count(old)
        if count != 1:
            raise AssertionError(f"{name}: mutation anchor count is {count}, expected 1")
        mutated = mutated.replace(old, new, 1)
    return mutated


def classified_red(proc: subprocess.CompletedProcess) -> bool:
    """A targeted test is red only when unittest itself reports failure/error."""
    summary = proc.stdout + proc.stderr
    return proc.returncode != 0 and ("FAILED (" in summary or "FAILED\n" in summary)


def main() -> int:
    results = []
    with tempfile.TemporaryDirectory(prefix="telos-verify-sabotage-") as tmp:
        candidate = copy_repo(pathlib.Path(tmp))
        tool = candidate / "telos_verify_lib" / "cli.py"
        original = tool.read_text(encoding="utf-8")

        baseline = run_suite(candidate)
        results.append(f"BASELINE: exit={baseline.returncode}")
        if baseline.returncode != 0:
            print("\n".join(results))
            print(baseline.stdout)
            print(baseline.stderr, file=sys.stderr)
            return 1

        # Catastrophic control: break the real CLI entrypoint and confirm the
        # aggregate suite goes red before trusting targeted classifications.
        broken = original.replace(
            '''def main(argv: list[str]) -> int:
    ap = build_parser()''',
            '''def main(argv: list[str]) -> int:
    raise RuntimeError("catastrophic harness validation")
    ap = build_parser()''',
            1,
        )
        if broken == original:
            raise AssertionError("S0: catastrophic mutation anchor not found")
        write_source(candidate, tool, broken)
        catastrophic = run_suite(candidate)
        results.append(f"S0_catastrophic_entrypoint: exit={catastrophic.returncode}")
        if catastrophic.returncode == 0:
            print("\n".join(results))
            return 1

        write_source(candidate, tool, original)
        results.append(bytecode_isolation_control(candidate))
        for name, case in SABOTAGES.items():
            target = candidate / case.get("file", "telos_verify.py")
            target_original = target.read_text(encoding="utf-8")
            write_source(candidate, target, apply_edits(target_original, case["edits"], name))
            red = []
            for test in case["tests"]:
                proc = run_test(candidate, test)
                if classified_red(proc):
                    red.append(test)
            passed = red == case["tests"]
            results.append(
                f"{name}: {'DEMONSTRATED' if passed else 'ASSERTED'} "
                f"({len(red)}/{len(case['tests'])} targeted controls red)"
            )
            if not passed:
                results.append(f"  expected: {case['tests']}")
                results.append(f"  red: {red}")
            write_source(candidate, target, target_original)

        restored = run_suite(candidate)
        results.append(f"RESTORED COPY: exit={restored.returncode}")

    print("\n".join(results))
    return 0 if all("ASSERTED" not in line for line in results) and restored.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
