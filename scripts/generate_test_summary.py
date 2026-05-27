#!/usr/bin/env python3
"""Generate a test summary JSON from pytest JUnit XML and coverage data.

Produces a machine-readable evidence artifact for enterprise-beta readiness:
- Python versions tested
- Total tests, passed, failed, skipped, errors
- Wall-clock duration
- Line coverage percentage
- Known slow tests (>= 5s)
- Flaky/skipped test list

Usage:
    python scripts/generate_test_summary.py --junitxml=test-results.xml --coverage-json=coverage.json
    python scripts/generate_test_summary.py --junitxml=test-results.xml --python-version=3.12
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

SLOW_THRESHOLD_S = 5.0


def parse_junit_xml(path: str) -> dict:
    """Parse pytest JUnit XML and return summary stats."""
    tree = ET.parse(path)
    root = tree.getroot()

    testsuites = root.findall(".//testsuite")
    total = 0
    passed = 0
    failures = 0
    skipped = 0
    errors = 0
    duration = 0.0
    slow_tests = []

    for ts in testsuites:
        total += int(ts.get("tests", 0))
        failures += int(ts.get("failures", 0))
        errors += int(ts.get("errors", 0))
        skipped += int(ts.get("skipped", 0))
        try:
            duration += float(ts.get("time", 0))
        except (ValueError, TypeError):
            pass

        for tc in ts.findall("testcase"):
            tc_time = 0.0
            try:
                tc_time = float(tc.get("time", 0))
            except (ValueError, TypeError):
                pass
            if tc_time >= SLOW_THRESHOLD_S:
                classname = tc.get("classname", "")
                name = tc.get("name", "")
                slow_tests.append(
                    {
                        "name": f"{classname}::{name}" if classname else name,
                        "duration_s": round(tc_time, 2),
                    }
                )

    passed = total - failures - errors - skipped

    return {
        "total": total,
        "passed": passed,
        "failed": failures,
        "skipped": skipped,
        "errors": errors,
        "duration_s": round(duration, 2),
        "slow_tests": slow_tests,
    }


def parse_coverage_json(path: str | None) -> dict | None:
    """Parse pytest-cov JSON output for line coverage."""
    if not path or not Path(path).exists():
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        totals = data.get("totals", {})
        return {
            "line_coverage_pct": round(
                totals.get("covered_lines", 0) / max(totals.get("num_statements", 1), 1) * 100, 2
            ),
            "covered_lines": totals.get("covered_lines", 0),
            "num_statements": totals.get("num_statements", 0),
            "missing_lines": totals.get("missing_lines", 0),
            "excluded_lines": totals.get("excluded_lines", 0),
        }
    except (json.JSONDecodeError, KeyError, ZeroDivisionError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate IronDome test summary")
    parser.add_argument("--junitxml", required=True, help="Path to JUnit XML")
    parser.add_argument("--coverage-json", default=None, help="Path to coverage JSON")
    parser.add_argument("--python-version", default=None, help="Python version string")
    parser.add_argument("--output", "-o", default=None, help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    test_stats = parse_junit_xml(args.junitxml)
    coverage = parse_coverage_json(args.coverage_json)

    summary = {
        "apiVersion": "irondome.kirkforge.dev/v1",
        "kind": "TestSummary",
        "metadata": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "pythonVersion": args.python_version,
            "generator": "generate_test_summary.py",
        },
        "spec": {
            "total": test_stats["total"],
            "passed": test_stats["passed"],
            "failed": test_stats["failed"],
            "skipped": test_stats["skipped"],
            "errors": test_stats["errors"],
            "duration_s": test_stats["duration_s"],
            "slowTests": test_stats["slow_tests"],
            "coverage": coverage,
            "slowThreshold_s": SLOW_THRESHOLD_S,
        },
    }

    output = json.dumps(summary, indent=2, default=str) + "\n"

    if args.output:
        Path(args.output).write_text(output)
        print(f"Test summary written to {args.output}")
    else:
        sys.stdout.write(output)

    # Exit with error if there were test failures
    return 1 if test_stats["failed"] > 0 or test_stats["errors"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
