"""Iron Dome CLI — deterministic runtime sandbox and behavioral analysis.

Supports multiple output formats, deterministic mode, verification,
and a full guard stack for CI/CD pipelines.
"""

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
from irondome.formatters.ml_context import format_ml_context
from irondome.formatters.github import format_github
from irondome.formatters.cyclonedx import format_cyclonedx
from irondome.guards import verify_determinism, diff_results, DeterministicGuard


# Severity levels for --fail-on
_SEVERITY_LEVELS = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Exit codes that trigger --exit-code
_BAD_VERDICTS = {"DENY", "KILL", "MALICIOUS", "SUSPICIOUS"}


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="irondome",
        description="Iron Dome — deterministic runtime sandbox and behavioral analysis",
    )
    parser.add_argument("--version", action="version", version=f"irondome {__version__}")

    sub = parser.add_subparsers(dest="command", help="sub-commands")

    # ── version ─────────────────────────────────────────────────────
    version_parser = sub.add_parser("version", help="Print version and exit")

    # ── sandbox ──────────────────────────────────────────────────────
    sandbox_parser = sub.add_parser("sandbox", help="Run a command under L3 sandbox policy")
    sandbox_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    sandbox_parser.add_argument("--policy", "-p", type=Path, help="Policy file (default: built-in)")
    sandbox_parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    sandbox_parser.add_argument("--cwd", "-C", help="Working directory")
    sandbox_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default="table",
    )
    _add_common_flags(sandbox_parser)
    sandbox_parser.add_argument(
        "--verify-determinism",
        action="store_true",
        help="Run twice and compare SHA-256 hashes to verify determinism",
    )

    # ── analyze ──────────────────────────────────────────────────────
    analyze_parser = sub.add_parser("analyze", help="Run L4 behavioral analysis on L3 output")
    analyze_parser.add_argument("--input", "-i", type=Path, help="JSON file from 'irondome sandbox --format json'")
    analyze_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default="table",
    )
    analyze_parser.add_argument("--rules", "-r", nargs="*", help="Specific rule IDs to run")
    _add_common_flags(analyze_parser)

    # ── pipeline ─────────────────────────────────────────────────────
    pipeline_parser = sub.add_parser("pipeline", help="Run full L3+L4 pipeline on a command")
    pipeline_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    pipeline_parser.add_argument("--policy", "-p", type=Path, help="Policy file")
    pipeline_parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    pipeline_parser.add_argument("--cwd", "-C", help="Working directory")
    pipeline_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default="table",
    )
    pipeline_parser.add_argument("--rules", "-r", nargs="*", help="Specific L4 rule IDs to run")
    _add_common_flags(pipeline_parser)

    # ── rules ────────────────────────────────────────────────────────
    rules_parser = sub.add_parser("rules", help="List available L4 detector rules")
    rules_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # ── diff ──────────────────────────────────────────────────────────
    diff_parser = sub.add_parser("diff", help="Compare two result JSON files")
    diff_parser.add_argument("file_a", type=Path, help="First result JSON file")
    diff_parser.add_argument("file_b", type=Path, help="Second result JSON file")
    diff_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed diff")

    # ── init ──────────────────────────────────────────────────────────
    init_parser = sub.add_parser("init", help="Initialize Iron Dome configuration")
    init_parser.add_argument("target", nargs="?", default=".", help="Target directory (default: current)")

    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"irondome {__version__}")
        return 0
    elif args.command == "sandbox":
        return _cmd_sandbox(args)
    elif args.command == "analyze":
        return _cmd_analyze(args)
    elif args.command == "pipeline":
        return _cmd_pipeline(args)
    elif args.command == "rules":
        return _cmd_rules(args)
    elif args.command == "diff":
        return _cmd_diff(args)
    elif args.command == "init":
        return _cmd_init(args)
    else:
        parser.print_help()
        return 1


def _add_common_flags(parser: argparse.ArgumentParser) -> None:
    """Add common flags to a subcommand parser."""
    parser.add_argument(
        "--deterministic-output", "-D",
        action="store_true",
        help="Produce deterministic output (no timestamps, random IDs, or timing)",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit 1 on DENY/KILL/MALICIOUS/SUSPICIOUS verdict",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit 1 if any finding at or above this severity",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output except exit code",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="One-line summary output",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output with full details",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log output format (default: text)",
    )


def _cmd_sandbox(args) -> int:
    """Run L3 sandbox."""
    if not args.command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    policy = load_policy(args.policy) if args.policy else None
    deterministic = args.deterministic_output

    result = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=args.cwd,
        deterministic=deterministic,
    )

    # Run determinism guard check if in deterministic mode
    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(result)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)

    # Verify determinism if requested
    if hasattr(args, 'verify_determinism') and args.verify_determinism:
        is_match, hash_a, hash_b = verify_determinism(
            args.command,
            policy=policy,
            timeout=args.timeout,
            cwd=args.cwd,
        )
        if not args.quiet:
            if is_match:
                print(f"✓ Determinism verified: {hash_a}", file=sys.stderr)
            else:
                print(f"✗ Determinism FAILED: {hash_a} != {hash_b}", file=sys.stderr)
        if not is_match:
            return 4

    # Output
    if not args.quiet:
        _output(result, args)

    # Exit code logic
    return _compute_exit_code_sandbox(result, args)


def _cmd_analyze(args) -> int:
    """Run L4 analysis on L3 output."""
    if not args.input or not args.input.exists():
        print("Error: --input file required and must exist", file=sys.stderr)
        return 1

    with open(args.input) as f:
        data = json.load(f)

    # Reconstruct SandboxResult from JSON
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
    from irondome.l3.models import SandboxResult
    sandbox = SandboxResult(
        run_id=data.get("run_id", ""),
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
    deterministic = args.deterministic_output
    result = engine.analyze(profile, rules=args.rules, deterministic=deterministic)

    # Run determinism guard check if in deterministic mode
    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(result)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)

    # Output
    if not args.quiet:
        _output(result, args)

    return _compute_exit_code_analysis(result, args)


def _cmd_pipeline(args) -> int:
    """Run full L3+L4 pipeline."""
    if not args.command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    policy = load_policy(args.policy) if args.policy else None
    deterministic = args.deterministic_output

    # L3
    sandbox = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=args.cwd,
        deterministic=deterministic,
    )

    # L4
    profile = profile_from_sandbox_result(sandbox)
    engine = create_default_engine()
    analysis = engine.analyze(profile, rules=args.rules, deterministic=deterministic)

    # Run determinism guard check if in deterministic mode
    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(sandbox) + guard.check(analysis)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)

    # Output
    if not args.quiet:
        fmt = args.format
        if args.summary:
            _output_summary_pipeline(sandbox, analysis)
        elif fmt == "json":
            print(format_pipeline_json(sandbox, analysis, deterministic=deterministic))
        elif fmt == "sarif":
            print(format_sarif(sandbox))
            print(format_sarif(analysis))
        elif fmt == "ml-context":
            print(format_ml_context(sandbox))
            print(format_ml_context(analysis))
        elif fmt == "github":
            print(format_github(sandbox))
            print(format_github(analysis))
        elif fmt == "cyclonedx":
            print(format_cyclonedx(sandbox))
            print(format_cyclonedx(analysis))
        else:  # table
            print(format_table(sandbox))
            print()
            print(format_table(analysis))

    return _compute_exit_code_pipeline(sandbox, analysis, args)


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


def _cmd_diff(args) -> int:
    """Compare two result JSON files."""
    exit_code, message = diff_results(args.file_a, args.file_b, verbose=args.verbose)
    print(message)
    return exit_code


def _cmd_init(args) -> int:
    """Initialize Iron Dome configuration."""
    target = Path(args.target).resolve()
    config_dir = target / ".irondome"
    config_file = config_dir / "policy.json"

    if config_file.exists():
        print(f"Iron Dome config already exists: {config_file}")
        return 0

    config_dir.mkdir(parents=True, exist_ok=True)

    default_config = {
        "name": "iron-dome-default",
        "version": "1.0",
        "default_action": "deny",
        "rules": [
            {
                "rule_id": "L3-FILE-R-001",
                "target": "file_read",
                "action": "allow",
                "paths": ["/usr/lib/**", "/lib/**", "/usr/share/**"],
                "description": "Read system libraries",
            },
            {
                "rule_id": "L3-NET-OUT-001",
                "target": "network_out",
                "action": "deny",
                "description": "Block all outbound network",
            },
        ],
    }

    config_file.write_text(json.dumps(default_config, indent=2, sort_keys=True) + "\n")
    print(f"Created Iron Dome config: {config_file}")
    return 0


def _output(result, args) -> None:
    """Output a result in the requested format."""
    if args.summary:
        _output_summary(result)
        return

    fmt = args.format
    deterministic = args.deterministic_output

    if fmt == "json":
        print(format_json(result, deterministic=deterministic))
    elif fmt == "sarif":
        print(format_sarif(result))
    elif fmt == "ml-context":
        print(format_ml_context(result))
    elif fmt == "github":
        print(format_github(result))
    elif fmt == "cyclonedx":
        print(format_cyclonedx(result))
    else:  # table
        print(format_table(result))


def _output_summary(result) -> None:
    """One-line summary output."""
    if isinstance(result, SandboxResult):
        verdict = result.overall_verdict.value
        events = len(result.events)
        cmd = " ".join(result.command)
        print(f"L3: {verdict} | {events} events | {cmd}")
    elif isinstance(result, AnalysisResult):
        verdict = result.overall_verdict.value
        findings = len(result.findings)
        print(f"L4: {verdict} | {findings} findings | {result.target}")


def _output_summary_pipeline(sandbox: SandboxResult, analysis: AnalysisResult) -> None:
    """One-line summary for pipeline."""
    l3_verdict = sandbox.overall_verdict.value
    l4_verdict = analysis.overall_verdict.value
    events = len(sandbox.events)
    findings = len(analysis.findings)
    cmd = " ".join(sandbox.command)
    print(f"L3: {l3_verdict} ({events} events) → L4: {l4_verdict} ({findings} findings) | {cmd}")


def _compute_exit_code_sandbox(result: SandboxResult, args) -> int:
    """Compute exit code for sandbox command based on flags."""
    # --exit-code: exit 1 on bad verdicts
    if args.exit_code and result.overall_verdict.value in _BAD_VERDICTS:
        return 1

    # --fail-on: check severity levels
    if args.fail_on:
        threshold = _SEVERITY_LEVELS.get(args.fail_on, 99)
        # Sandbox events don't have severity, but DENY/KILL are bad
        if result.overall_verdict.value in ("DENY", "KILL"):
            return 1

    # Default: exit 0 on ALLOW, 1 otherwise
    return 0 if result.overall_verdict.value == "ALLOW" else 1


def _compute_exit_code_analysis(result: AnalysisResult, args) -> int:
    """Compute exit code for analyze command based on flags."""
    # --exit-code: exit 1 on bad verdicts
    if args.exit_code and result.overall_verdict.value in _BAD_VERDICTS:
        return 1

    # --fail-on: check severity levels
    if args.fail_on:
        threshold = _SEVERITY_LEVELS.get(args.fail_on, 99)
        for f in result.findings:
            finding_level = _SEVERITY_LEVELS.get(f.severity.value.lower(), 99)
            if finding_level <= threshold:
                return 1

    # Default: exit 0 on CLEAN, 1 otherwise
    return 0 if result.overall_verdict.value == "CLEAN" else 1


def _compute_exit_code_pipeline(sandbox: SandboxResult, analysis: AnalysisResult, args) -> int:
    """Compute exit code for pipeline command."""
    # Check L4 verdict first (it's the final arbiter)
    if args.exit_code and analysis.overall_verdict.value in _BAD_VERDICTS:
        return 1

    if args.fail_on:
        threshold = _SEVERITY_LEVELS.get(args.fail_on, 99)
        for f in analysis.findings:
            finding_level = _SEVERITY_LEVELS.get(f.severity.value.lower(), 99)
            if finding_level <= threshold:
                return 1

    # Default: exit 0 on CLEAN, 1 otherwise
    return 0 if analysis.overall_verdict.value == "CLEAN" else 1