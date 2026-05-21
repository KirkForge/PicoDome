"""Iron Dome CLI — deterministic runtime sandbox and behavioral analysis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from irondome import __version__
from irondome.l3.engine import sandbox_run
from irondome.l3.models import SandboxResult
from irondome.l3.policy import load_policy
from irondome.l4.engine import create_default_engine
from irondome.l4.models import AnalysisResult
from irondome.l4.profiler import profile_from_sandbox_result
from irondome.formatters.json_fmt import format_json, format_pipeline_json
from irondome.formatters.sarif import format_sarif
from irondome.formatters.table import format_table


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="irondome",
        description="Iron Dome — deterministic runtime sandbox and behavioral analysis",
    )
    parser.add_argument("--version", action="version", version=f"irondome {__version__}")

    sub = parser.add_subparsers(dest="command", help="sub-commands")

    # ── sandbox ──────────────────────────────────────────────────────
    sandbox_parser = sub.add_parser("sandbox", help="Run a command under L3 sandbox policy")
    sandbox_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    sandbox_parser.add_argument("--policy", "-p", type=Path, help="Policy file (default: built-in)")
    sandbox_parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    sandbox_parser.add_argument("--cwd", "-C", help="Working directory")
    sandbox_parser.add_argument("--format", "-f", choices=["json", "sarif", "table"], default="table")

    # ── analyze ──────────────────────────────────────────────────────
    analyze_parser = sub.add_parser("analyze", help="Run L4 behavioral analysis on L3 output")
    analyze_parser.add_argument("--input", "-i", type=Path, help="JSON file from 'irondome sandbox --format json'")
    analyze_parser.add_argument("--format", "-f", choices=["json", "sarif", "table"], default="table")
    analyze_parser.add_argument("--rules", "-r", nargs="*", help="Specific rule IDs to run")

    # ── pipeline ─────────────────────────────────────────────────────
    pipeline_parser = sub.add_parser("pipeline", help="Run full L3+L4 pipeline on a command")
    pipeline_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    pipeline_parser.add_argument("--policy", "-p", type=Path, help="Policy file")
    pipeline_parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    pipeline_parser.add_argument("--cwd", "-C", help="Working directory")
    pipeline_parser.add_argument("--format", "-f", choices=["json", "sarif", "table"], default="table")
    pipeline_parser.add_argument("--rules", "-r", nargs="*", help="Specific L4 rule IDs to run")

    # ── rules ────────────────────────────────────────────────────────
    rules_parser = sub.add_parser("rules", help="List available L4 detector rules")
    rules_parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args(argv)

    if args.command == "sandbox":
        return _cmd_sandbox(args)
    elif args.command == "analyze":
        return _cmd_analyze(args)
    elif args.command == "pipeline":
        return _cmd_pipeline(args)
    elif args.command == "rules":
        return _cmd_rules(args)
    else:
        parser.print_help()
        return 1


def _cmd_sandbox(args) -> int:
    """Run L3 sandbox."""
    if not args.command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    policy = load_policy(args.policy) if args.policy else None
    result = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=args.cwd,
    )

    _output(result, args.format)
    return 0 if result.overall_verdict.value == "ALLOW" else 1


def _cmd_analyze(args) -> int:
    """Run L4 analysis on L3 output."""
    if not args.input or not args.input.exists():
        print("Error: --input file required and must exist", file=sys.stderr)
        return 1

    with open(args.input) as f:
        data = json.load(f)

    # Reconstruct SandboxResult from JSON.
    # Note: JSON output is deterministic and may omit run_id/timestamp.
    from irondome.l3.models import SandboxEvent, Verdict

    events = [
        SandboxEvent(
            rule_id=e["rule_id"],
            verdict=Verdict(e["verdict"]),
            operation=e["operation"],
            detail=e["detail"],
            path=e.get("path", ""),
            address=e.get("address", ""),
        )
        for e in data.get("events", [])
    ]

    sandbox = SandboxResult(
        backend=data.get("backend", ""),
        policy_hash=data.get("policy_hash", ""),
        policy_version=data.get("policy_version", ""),
        command=data.get("command", []),
        overall_verdict=Verdict(data.get("overall_verdict", "ALLOW")),
        exit_code=data.get("exit_code", 0),
        duration_ms=data.get("duration_ms", 0),
        events=events,
        policy_name=data.get("policy_name", ""),
        stdout=data.get("stdout", ""),
        stderr=data.get("stderr", ""),
    )

    profile = profile_from_sandbox_result(sandbox)
    engine = create_default_engine()
    result = engine.analyze(profile, rules=args.rules)

    _output(result, args.format)
    return 0 if result.overall_verdict.value == "CLEAN" else 1


def _cmd_pipeline(args) -> int:
    """Run full L3+L4 pipeline."""
    if not args.command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    policy = load_policy(args.policy) if args.policy else None

    # L3
    sandbox = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=args.cwd,
    )

    # L4
    profile = profile_from_sandbox_result(sandbox)
    engine = create_default_engine()
    analysis = engine.analyze(profile, rules=args.rules)

    # Output
    if args.format == "json":
        print(format_pipeline_json(sandbox, analysis))
    elif args.format == "sarif":
        print(format_sarif(sandbox))
        print(format_sarif(analysis))
    else:  # table
        print(format_table(sandbox))
        print()
        print(format_table(analysis))

    return 0 if analysis.overall_verdict.value == "CLEAN" else 1


def _cmd_rules(args) -> int:
    """List available L4 rules."""
    engine = create_default_engine()
    rules = engine.list_rules()
    if args.json:
        print(json.dumps({"rules": rules}))
    else:
        for r in rules:
            print(r)
    return 0


def _output(result, fmt: str):
    """Output a result in the requested format."""
    if fmt == "json":
        print(format_json(result))
    elif fmt == "sarif":
        print(format_sarif(result))
    else:
        print(format_table(result))
