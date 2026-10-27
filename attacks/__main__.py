"""``python -m attacks``: one door for the ATTACK-side checks.

python -m attacks build     [--check] [--prune]
python -m attacks lint
python -m attacks harness   [--scanner keyword|read] [--layer READ|RUN]
python -m attacks leakage   [--data-dir DIR]
python -m attacks check     # lint + generated-tree drift + both gates
"""

from __future__ import annotations

import argparse
import sys

from attacks import build, harness, leakage, lint

__all__ = ["main"]


def _check() -> int:
    failures = 0
    violations = lint.lint_paths(lint.default_paths())
    if violations:
        failures += len(violations)
        for violation in violations:
            print(f"lint: {violation}", file=sys.stderr)
    else:
        print("lint: clean")

    drift = build.check_tree()
    if drift:
        failures += len(drift)
        for item in drift:
            print(f"drift: {item}", file=sys.stderr)
    else:
        print("generated tree: clean")

    reports = harness.run_all(scanner=harness.keyword_scanner, layer="READ", scanner_name="keyword")
    for report in reports:
        status = "ok" if report.ok else "FAIL"
        print(
            f"gate {report.layer} {report.repo}: {status} "
            f"({report.recovered}/{report.recoverable} payloads recovered)"
        )
        if not report.ok:
            failures += 1
            for missed in sorted(report.missed):
                print(f"  missed: {missed}", file=sys.stderr)
            for extra in sorted(report.extra):
                print(f"  extra: {extra}", file=sys.stderr)
    if failures:
        print(f"FAIL: {failures} problem(s)", file=sys.stderr)
        return 1
    print("PASS: lint, generated tree, and READ gate")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m attacks")
    parser.add_argument("command", choices=("build", "lint", "harness", "leakage", "check"))
    args, rest = parser.parse_known_args(argv)
    if args.command == "build":
        return build.main(rest)
    if args.command == "lint":
        return lint.main(rest)
    if args.command == "harness":
        return harness.main(rest)
    if args.command == "leakage":
        return leakage.main(rest)
    return _check()


if __name__ == "__main__":
    raise SystemExit(main())
