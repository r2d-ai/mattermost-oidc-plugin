#!/usr/bin/env python3
"""Check the recorded fork commit ledger; optionally report live Git divergence.

Read-only and standard-library only. This checks history coverage, not behavior.
"""
import argparse
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", help="Already fetched upstream SHA or ref")
    args = parser.parse_args()
    document = (ROOT / "docs/fork-differences.md").read_text()
    markers = {}
    for name in ("base", "head"):
        match = re.search(rf"^Audit {name}: `([0-9a-f]{{40}})`$", document, re.M)
        if not match:
            raise SystemExit(f"Missing full Audit {name} SHA in fork-differences.md")
        markers[name] = match[1]
    base, head = markers["base"], markers["head"]
    if git("merge-base", base, head) != base:
        raise SystemExit("Audit base is not an ancestor of audit head")
    expected = set(git("rev-list", f"{base}..{head}").splitlines())
    entries = re.findall(r"^\| \[([0-9a-f]{7,40})\]\(", document, re.M)
    recorded = [git("rev-parse", "--verify", entry + "^{commit}") for entry in entries]
    missing = expected - set(recorded)
    extra = set(recorded) - expected
    if missing or extra or len(recorded) != len(set(recorded)):
        raise SystemExit(
            f"Ledger mismatch: missing={sorted(missing)}, extra={sorted(extra)}, "
            f"duplicate_rows={len(recorded) - len(set(recorded))}"
        )
    print(f"PASS: all {len(expected)} commits in {base[:7]}..{head[:7]} documented")
    documented_tests = set(re.findall(r"`(Test[A-Za-z0-9_]+)`", document))
    defined_tests = set()
    for directory in ("server", "mobile-bridge"):
        for path in (ROOT / directory).glob("*_test.go"):
            defined_tests.update(re.findall(r"^func (Test\w+)\(", path.read_text(), re.M))
    missing_tests = documented_tests - defined_tests
    if missing_tests:
        raise SystemExit(f"Documented regression tests not found: {sorted(missing_tests)}")
    print(f"PASS: all {len(documented_tests)} named regression tests exist")
    current = git("rev-parse", "HEAD")
    if current != head:
        print(f"Current HEAD {current[:7]} differs from audit head; review later commits separately.")
    if args.upstream:
        upstream = git("rev-parse", "--verify", args.upstream + "^{commit}")
        print(f"Fork HEAD: {current}\nUpstream: {upstream}")
        print("Merge base:", git("merge-base", current, upstream))
        print("Upstream-only / fork-only counts:", git("rev-list", "--left-right", "--count", f"{upstream}...{current}"))
        print("Fork-only commits:\n" + git("log", "--reverse", "--oneline", f"{upstream}..{current}"))
        print("Upstream-only commits:\n" + git("log", "--reverse", "--oneline", f"{current}..{upstream}"))


if __name__ == "__main__":
    main()
