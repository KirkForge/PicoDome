"""Shared models for Iron Dome L3 + L4 pipeline."""

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
    """A single finding from a detector rule. Frozen for determinism."""
    rule_id: str
    severity: Severity
    message: str
    location: str = ""
    evidence: Dict = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class ScanStats:
    """Aggregate statistics for a scan or analysis. Frozen for determinism."""
    packages_scanned: int = 0
    files_scanned: int = 0
    duration_ms: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_rule: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "packages_scanned": self.packages_scanned,
            "files_scanned": self.files_scanned,
            "duration_ms": self.duration_ms,
            "findings_by_severity": dict(self.findings_by_severity),
            "findings_by_rule": dict(self.findings_by_rule),
        }


def _now_ms() -> float:
    """Monotonic clock in milliseconds."""
    return time.monotonic() * 1000


def _now_iso() -> str:
    """ISO 8601 timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
