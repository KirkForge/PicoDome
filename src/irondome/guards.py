"""
Deterministic guard stack — enforcement, verification, and fingerprinting.

Iron Dome's core thesis: same command + same policy = same output, every time.

This module provides the guard stack that enforces and verifies that guarantee:
- DeterministicGuard: validates invariants at scan time
- deterministic_hash: SHA-256 of deterministic fields only (excludes timing)
- verify_determinism: run twice and compare
- diff_results: compare two saved JSON files

Architecture:
    ┌─────────────────────────────────────────┐
    │  Layer 4: CI Gate                       │
    │  --verify-determinism (CLI)             │
    │  Runs scan twice, asserts SHA-256 match │
    ├─────────────────────────────────────────┤
    │  Layer 3: Diff                          │
    │  irondome diff a.json b.json            │
    │  Compare two saved scans field-by-field │
    ├─────────────────────────────────────────┤
    │  Layer 2: Guard (runtime)               │
    │  Validates invariants after each scan:  │
    │  - No uuid4/random in findings          │
    │  - No timestamps in findings           │
    │  - Findings sorted by sort_key()        │
    │  - run_id is deterministic (empty)      │
    ├─────────────────────────────────────────┤
    │  Layer 1: Models (structural)           │
    │  Finding(frozen=True), sorted keys,    │
    │  no random IDs, no prose in output      │
    └─────────────────────────────────────────┘

Exit codes:
    0 = deterministic (verified)
    1 = different results (diff command)
    2 = file error
    4 = determinism violation (verify command)
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from irondome.l3.models import SandboxResult
from irondome.l4.models import AnalysisResult

# Patterns that should never appear in deterministic output
_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
_ISO_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
)


class DeterminismViolation(Exception):
    """Raised when a result violates determinism invariants."""

    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__(
            f"Determinism violation(s): {len(violations)}\n"
            + "\n".join(f"  - {v}" for v in violations)
        )


class DeterministicGuard:
    """Runtime guard that validates determinism invariants after each scan.

    Called by the engine after scanning, before returning results.
    Ensures no random state has leaked into the output.

    Usage:
        guard = DeterministicGuard()
        violations = guard.check(result)
        if violations:
            raise DeterminismViolation(violations)
    """

    def check(self, result: SandboxResult | AnalysisResult) -> list[str]:
        """Validate determinism invariants. Returns list of violations (empty = pass)."""
        violations: list[str] = []

        if isinstance(result, SandboxResult):
            violations.extend(self._check_sandbox(result))
        elif isinstance(result, AnalysisResult):
            violations.extend(self._check_analysis(result))

        return violations

    def _check_sandbox(self, result: SandboxResult) -> list[str]:
        """Check L3 SandboxResult for determinism violations."""
        violations: list[str] = []

        # 1. run_id must be empty (deterministic) or a valid UUID
        if result.run_id and _UUID_PATTERN.fullmatch(result.run_id):
            violations.append(f"run_id is a UUID (non-deterministic): {result.run_id}")

        # 2. timestamp must be empty (deterministic)
        if result.timestamp and _ISO_TIMESTAMP_PATTERN.search(result.timestamp):
            violations.append(f"timestamp is non-deterministic: {result.timestamp}")

        # 3. Events must not contain UUIDs in detail
        for event in result.events:
            if _UUID_PATTERN.search(event.detail):
                violations.append(
                    f"event {event.rule_id} contains UUID in detail: {event.detail[:80]}"
                )

        # 4. Verify to_dict produces sorted keys
        d = result.to_dict(deterministic=True)
        if list(d.keys()) != sorted(d.keys()):
            violations.append("SandboxResult.to_dict() keys are not sorted")

        return violations

    def _check_analysis(self, result: AnalysisResult) -> list[str]:
        """Check L4 AnalysisResult for determinism violations."""
        violations: list[str] = []

        # 1. Findings must not have UUID finding_ids
        for f in result.findings:
            if f.finding_id and _UUID_PATTERN.fullmatch(f.finding_id):
                violations.append(
                    f"finding {f.rule_id} has UUID finding_id: {f.finding_id}"
                )

        # 2. Findings must not contain timestamps in message or evidence
        for f in result.findings:
            if _ISO_TIMESTAMP_PATTERN.search(f.message):
                violations.append(
                    f"finding {f.rule_id} has timestamp in message: {f.message[:80]}"
                )
            evidence_str = str(f.evidence)
            if _ISO_TIMESTAMP_PATTERN.search(evidence_str):
                violations.append(
                    f"finding {f.rule_id} has timestamp in evidence"
                )

        # 3. Findings must not contain random values
        for f in result.findings:
            if _UUID_PATTERN.search(f.message):
                violations.append(
                    f"finding {f.rule_id} has UUID in message: {f.message[:80]}"
                )

        # 4. Verify to_dict produces sorted keys
        d = result.to_dict(deterministic=True)
        if list(d.keys()) != sorted(d.keys()):
            violations.append("AnalysisResult.to_dict() keys are not sorted")

        return violations

    def assert_deterministic(self, result: SandboxResult | AnalysisResult) -> None:
        """Assert that a result is deterministic. Raises DeterminismViolation if not."""
        violations = self.check(result)
        if violations:
            raise DeterminismViolation(violations)


def validate_findings_deterministic(findings: list) -> list[str]:
    """Validate that a list of findings is deterministic.

    Checks for:
    - No UUID4 finding_ids
    - No timestamps in messages
    - No random values in evidence

    Returns list of violations (empty = pass).
    """
    DeterministicGuard()
    violations: list[str] = []

    for f in findings:
        if f.finding_id and _UUID_PATTERN.fullmatch(f.finding_id):
            violations.append(f"finding {f.rule_id} has UUID finding_id: {f.finding_id}")
        if _ISO_TIMESTAMP_PATTERN.search(f.message):
            violations.append(f"finding {f.rule_id} has timestamp in message")
        evidence_str = str(f.evidence)
        if _UUID_PATTERN.search(evidence_str):
            violations.append(f"finding {f.rule_id} has UUID in evidence")

    return violations


def validate_result_sorted(result_dict: dict) -> list[str]:
    """Validate that a result dict has sorted keys at all levels.

    Returns list of violations (empty = pass).
    """
    violations: list[str] = []

    def _check_sorted(d: dict, path: str = "") -> None:
        keys = list(d.keys())
        if keys != sorted(keys):
            violations.append(f"keys not sorted at {path or 'root'}: {keys}")
        for k, v in d.items():
            if isinstance(v, dict):
                _check_sorted(v, f"{path}.{k}" if path else k)

    _check_sorted(result_dict)
    return violations


def validate_no_randomness(result_dict: dict) -> list[str]:
    """Validate that a result dict contains no random values.

    Checks for UUIDs and timestamps anywhere in the dict.

    Returns list of violations (empty = pass).
    """
    violations: list[str] = []

    def _check_value(v, path: str = "") -> None:
        if isinstance(v, str):
            if _UUID_PATTERN.search(v):
                violations.append(f"UUID found at {path}: {v[:50]}")
            if _ISO_TIMESTAMP_PATTERN.search(v):
                violations.append(f"timestamp found at {path}: {v[:50]}")
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                _check_value(v2, f"{path}.{k2}")
        elif isinstance(v, list):
            for i, item in enumerate(v):
                _check_value(item, f"{path}[{i}]")

    _check_value(result_dict)
    return violations


def deterministic_hash(result: SandboxResult | AnalysisResult) -> str:
    """SHA-256 hash of deterministic fields only.

    Excludes run_id, timestamp, and duration_ms (timing is inherently
    non-deterministic). This is the canonical determinism fingerprint.

    Two scans of the same command with the same policy MUST produce
    the same deterministic_hash, or the determinism guarantee is broken.
    """
    data = result.to_dict(deterministic=True)
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def verify_determinism(
    target: list[str],
    policy=None,
    timeout: float | None = None,
    cwd: str | None = None,
) -> tuple:
    """Run sandbox twice and compare SHA-256 hashes.

    Returns (is_match, hash_a, hash_b).
    If is_match is True, the results are deterministic.
    If False, there's a bug in the sandbox.

    Args:
        target: Command and arguments to execute.
        policy: Sandbox policy (None = default).
        timeout: Wall-time limit in seconds.
        cwd: Working directory.

    Returns:
        Tuple of (is_match, hash_a, hash_b).
    """
    from irondome.l3.engine import sandbox_run

    result_a = sandbox_run(target, policy=policy, timeout=timeout, cwd=cwd, deterministic=True)
    result_b = sandbox_run(target, policy=policy, timeout=timeout, cwd=cwd, deterministic=True)

    hash_a = deterministic_hash(result_a)
    hash_b = deterministic_hash(result_b)

    return (hash_a == hash_b, hash_a, hash_b)


def diff_results(
    path_a: Path,
    path_b: Path,
    verbose: bool = False,
) -> tuple:
    """Compare two result JSON files.

    Returns (exit_code, output_message).
    Exit codes: 0=identical, 1=different, 2=error
    """
    if not path_a.is_file():
        return (2, f"Error: {path_a} does not exist")
    if not path_b.is_file():
        return (2, f"Error: {path_b} does not exist")

    try:
        data_a = json.loads(path_a.read_text(encoding="utf-8"))
        data_b = json.loads(path_b.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return (2, f"Error reading result files: {e}")

    det_hash_a = _deterministic_hash_raw(data_a)
    det_hash_b = _deterministic_hash_raw(data_b)

    if det_hash_a == det_hash_b:
        lines = [
            "✓ Results are IDENTICAL — determinism verified",
            f"  sha256:  {det_hash_a}",
            f"  findings_a: {len(data_a.get('findings', []))}",
            f"  findings_b: {len(data_b.get('findings', []))}",
        ]
        # Check if full JSON differs (timing only)
        full_hash_a = hashlib.sha256(json.dumps(data_a, sort_keys=True).encode()).hexdigest()
        full_hash_b = hashlib.sha256(json.dumps(data_b, sort_keys=True).encode()).hexdigest()
        if full_hash_a != full_hash_b:
            lines.append(
                f"  note: full JSON differs (timing: "
                f"{data_a.get('duration_ms', '?')}ms vs "
                f"{data_b.get('duration_ms', '?')}ms)"
            )
        return (0, "\n".join(lines))

    # Different — build diff output
    lines = [
        "✗ Results DIFFER — determinism violation detected",
        f"  sha256_a: {det_hash_a[:16]}...",
        f"  sha256_b: {det_hash_b[:16]}...",
        f"  findings_a: {len(data_a.get('findings', []))}",
        f"  findings_b: {len(data_b.get('findings', []))}",
    ]

    # Compare metadata
    for key in sorted(set(list(data_a.keys()) + list(data_b.keys()))):
        if key == "findings":
            continue
        val_a = data_a.get(key)
        val_b = data_b.get(key)
        if val_a != val_b:
            lines.append(f"  {key}: {val_a!r} → {val_b!r}")

    if verbose:
        findings_a = data_a.get("findings", [])
        findings_b = data_b.get("findings", [])
        set_a = {(f.get("rule_id", ""), f.get("message", "")) for f in findings_a}
        set_b = {(f.get("rule_id", ""), f.get("message", "")) for f in findings_b}

        added = set_b - set_a
        removed = set_a - set_b

        if removed:
            lines.append(f"\n  Removed findings ({len(removed)}):")
            for rule_id, msg in sorted(removed):
                lines.append(f"    - {rule_id}: {msg[:60]}")

        if added:
            lines.append(f"\n  Added findings ({len(added)}):")
            for rule_id, msg in sorted(added):
                lines.append(f"    + {rule_id}: {msg[:60]}")

    return (1, "\n".join(lines))


def _deterministic_hash_raw(data: dict) -> str:
    """Hash raw result JSON data (dict), excluding timing fields."""
    det = {k: v for k, v in data.items() if k not in ("run_id", "timestamp", "duration_ms")}
    # Strip timing from nested objects
    if "stats" in det and isinstance(det["stats"], dict):
        det["stats"] = {k: v for k, v in det["stats"].items() if k != "duration_ms"}
    return hashlib.sha256(json.dumps(det, sort_keys=True).encode()).hexdigest()
