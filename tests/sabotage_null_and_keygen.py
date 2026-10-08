#!/usr/bin/env python3
"""One hand mutation per control, each after GREEN in a fresh disposable copy.

No live source is changed; only Python sources and public test fixtures are
copied. Every child has bytecode caching disabled. Evidence includes positive
Ran N, the exit code, and the complete baseline/mutant unittest output.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
TEST = "test_null_and_keygen."

# Each row is exactly one replacement in one production file.
MUTATIONS = (
    ("M1-null-shape", "telos_verify_lib/inputs.py",
     "if obj is _UNUSABLE:", "if obj is _UNUSABLE or obj is None:",
     "ReceiptRefusal.test_non_objects_alone"),
    ("M2-partial-count", "telos_verify_lib/cli.py",
     "if r.state == VERIFIED and (not files or len(s.loaded) < len(files)):",
     "if False:", "ReceiptRefusal.test_silent_backend_skip_cannot_exit_zero"),
    ("M3-empty-bundle", "telos_verify_lib/cli.py",
     "if r.state == VERIFIED and (not files or len(s.loaded) < len(files)):",
     "if False:", "ReceiptRefusal.test_empty_bundle_is_not_a_pass"),
    ("M4-existing-preflight", "telos_sign.py",
     "if os.path.lexists(path):", "if False:",
     "KeygenRefusal.test_existing_target_refuses_before_any_create"),
    ("M5-private-exclusive", "telos_sign.py",
     "os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode",
     "os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if path == priv_path else os.O_EXCL), mode",
     "KeygenRefusal.test_race_at_either_create_preserves_existing_dummy"),
    ("M6-public-exclusive", "telos_sign.py",
     "os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode",
     "os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if path == pub_path else os.O_EXCL), mode",
     "KeygenRefusal.test_race_at_either_create_preserves_existing_dummy"),
    ("M7-private-initial-mode", "telos_sign.py",
     "(priv_path, priv_pem, 0o600)", "(priv_path, priv_pem, 0o644)",
     "KeygenRefusal.test_private_has_mode_0600_at_creation_before_bytes"),
    ("M8-private-final-mode", "telos_sign.py",
     "os.fchmod(fd, 0o600)", "pass",
     "KeygenRefusal.test_private_created_mode_0600_even_with_restrictive_umask"),
    ("M9-rollback-open", "telos_sign.py",
     "path.unlink()", "pass",
     "KeygenRefusal.test_open_failure_leaves_no_pair"),
    ("M10-rollback-write", "telos_sign.py",
     "path.unlink()", "pass",
     "KeygenRefusal.test_write_failure_leaves_no_pair"),
    ("M11-projection-disclosure", "telos_verify_lib/report.py",
     "    if r.anchored:\n", "    if False:\n",
     "ProjectionDisclosure.test_anchored_pass_discloses_unchecked_projection_tail"),
)


def public_inputs():
    # Never discover or copy a PEM, key, env, or authentication file.
    paths = list(REPO.glob("*.py")) + [REPO / "README.md"]
    for directory, suffixes in (("telos_verify_lib", {".py"}), ("tests", {".py"}),
                                ("docs", {".json"}), ("vectors", {".json", ".sha256"})):
        paths.extend(p for p in (REPO / directory).rglob("*")
                     if p.suffix in suffixes and p.is_file())
    return sorted(paths)


def run_test(candidate, test, output):
    command = [sys.executable, "-B", "-m", "unittest", TEST + test, "-v"]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": str(candidate / "tests")}
    p = subprocess.run(command, cwd=candidate, env=env, capture_output=True,
                       text=True, timeout=60)
    log = p.stdout + p.stderr
    output.write_text(public_log(log))
    ran = re.search(r"^Ran (\d+) tests? in ", log, re.M)
    if not ran or int(ran[1]) <= 0:
        raise AssertionError(f"no positive Ran N: {output}")
    return {"command": command, "exit_code": p.returncode, "ran": int(ran[1]),
            "assertion_failures": bool(re.search(r"^FAIL: ", log, re.M)),
            "unittest_failed": bool(re.search(r"^FAILED(?:\s|$)", log, re.M))}


def public_log(log):
    # unittest diffs can echo an ephemeral private key when an overwrite mutant
    # replaces a dummy canary. Retain the test/traceback and failure status, but
    # omit the assertion values containing that test-only key material.
    def redact(match):
        block = match.group(0)
        if "PRIVATE KEY" in block or "MC4CAQ" in block:
            return "AssertionError: [ephemeral test private-key assertion values redacted]"
        return block
    return re.sub(r"^AssertionError:.*?(?=\n\n|\Z)", redact, log, flags=re.M | re.S)


def main():
    evidence = REPO / "fix-evidence" / "mutations"
    evidence.mkdir(parents=True, exist_ok=True)
    inputs = public_inputs()
    fingerprints = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in inputs}
    rows = []
    for name, file, before, after, test in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix=f"telos-fix-{name}-") as td:
            candidate = pathlib.Path(td)
            for source in inputs:
                destination = candidate / source.relative_to(REPO)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            baseline = run_test(candidate, test, evidence / f"{name}-baseline.log")
            if baseline["exit_code"] != 0:
                raise AssertionError(f"baseline was not GREEN: {name}")
            target = candidate / file
            original = target.read_text()
            if original.count(before) != 1:
                raise AssertionError(f"ambiguous mutation anchor: {name}")
            target.write_text(original.replace(before, after, 1))
            mutant = run_test(candidate, test, evidence / f"{name}-mutant.log")
            caught = (mutant["exit_code"] != 0 and mutant["unittest_failed"]
                      and mutant["assertion_failures"])
            rows.append({"name": name, "file": file, "before": before, "after": after,
                         "test": TEST + test, "baseline": baseline, "mutant": mutant,
                         "status": "DEMONSTRATED" if caught else "ASSERTED"})
            print(f"{name}: {'DEMONSTRATED' if caught else 'ASSERTED'}; "
                  f"baseline Ran {baseline['ran']}, exit {baseline['exit_code']}; "
                  f"mutant Ran {mutant['ran']}, exit {mutant['exit_code']}", flush=True)
    unchanged = all(hashlib.sha256((REPO / p).read_bytes()).hexdigest() == digest
                    for p, digest in fingerprints.items())
    report = {"rows": rows, "live_inputs_unchanged": unchanged,
              "caught": sum(row["status"] == "DEMONSTRATED" for row in rows),
              "total": len(rows)}
    (evidence / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if unchanged and report["caught"] == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
