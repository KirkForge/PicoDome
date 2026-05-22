"""Shared models for Iron Dome L3 + L4 pipeline.

Deterministic by default: Finding.finding_id defaults to "" (empty string),
not uuid4. SandboxResult.run_id and .timestamp also default to "".
Use _generate_finding_id(), _generate_run_id(), _generate_timestamp() to
fill in non-deterministic values when needed.
"""

from __future__ import annotations

import uuid
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    KILL = "KILL"


class BehavioralVerdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass(frozen=True)
class Finding:
    """A single finding from a detector rule. Frozen for determinism.

    finding_id defaults to "" (deterministic mode). Use _generate_finding_id()
    to produce a real UUID when non-deterministic output is desired.
    """
    rule_id: str
    severity: Severity
    message: str
    location: str = ""
    evidence: Dict = field(default_factory=dict)
    finding_id: str = ""

    def to_dict(self, deterministic: bool = False) -> Dict:
        """Serialize to dict. Sort keys for deterministic JSON output.

        In deterministic mode, omit finding_id if empty.
        """
        d: Dict = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location,
            "evidence": self.evidence,
        }
        if not deterministic and self.finding_id:
            d["finding_id"] = self.finding_id
        return {k: v for k, v in sorted(d.items())}


@dataclass(frozen=True)
class ScanStats:
    """Aggregate statistics for a scan or analysis. Frozen for determinism."""
    packages_scanned: int = 0
    files_scanned: int = 0
    duration_ms: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_rule: Dict[str, int] = field(default_factory=dict)

    def to_dict(self, deterministic: bool = False) -> Dict:
        """Serialize to dict with sorted keys.

        In deterministic mode, omit duration_ms (timing is non-deterministic).
        """
        d: Dict = {
            "packages_scanned": self.packages_scanned,
            "files_scanned": self.files_scanned,
            "findings_by_severity": dict(sorted(self.findings_by_severity.items())),
            "findings_by_rule": dict(sorted(self.findings_by_rule.items())),
        }
        if not deterministic:
            d["duration_ms"] = self.duration_ms
        return {k: v for k, v in sorted(d.items())}


def _now_ms() -> float:
    """Monotonic clock in milliseconds."""
    return time.monotonic() * 1000


def _now_iso() -> str:
    """ISO 8601 timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _generate_finding_id() -> str:
    """Generate a non-deterministic finding ID (UUID4)."""
    return str(uuid.uuid4())


def _generate_run_id() -> str:
    """Generate a non-deterministic run ID (UUID4)."""
    return str(uuid.uuid4())


def _generate_timestamp() -> str:
    """Generate a non-deterministic timestamp (ISO 8601)."""
    return _now_iso()