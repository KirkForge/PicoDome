"""L4 Behavioral Analysis — data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from irondome.models import (
    BehavioralVerdict,
    Finding,
    ScanStats,
    Severity,
    _now_iso,
)


@dataclass(frozen=True)
class NetworkCall:
    """A single network call observed during execution."""
    address: str
    port: int = 0
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    timestamp_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "address": self.address,
            "port": self.port,
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
        }


@dataclass(frozen=True)
class DnsQuery:
    """A DNS query observed during execution."""
    hostname: str
    resolved_ips: List[str] = field(default_factory=list)
    timestamp_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "hostname": self.hostname,
            "resolved_ips": list(self.resolved_ips),
        }


@dataclass(frozen=True)
class FileOperation:
    """A filesystem operation observed during execution."""
    path: str
    operation: str  # read, write, delete, create, chmod, chown
    success: bool = True
    bytes_transferred: int = 0
    timestamp_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "operation": self.operation,
            "success": self.success,
            "bytes_transferred": self.bytes_transferred,
        }


@dataclass(frozen=True)
class ProcessSpawn:
    """A child process spawned during execution."""
    executable: str
    args: List[str] = field(default_factory=list)
    pid: int = 0
    exit_code: Optional[int] = None
    timestamp_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "executable": self.executable,
            "args": list(self.args),
            "pid": self.pid,
            "exit_code": self.exit_code,
        }


@dataclass(frozen=True)
class TimingPoint:
    """A timing measurement during execution."""
    label: str
    elapsed_ms: int
    timestamp_ms: int = 0

    def to_dict(self) -> Dict:
        return {"label": self.label, "elapsed_ms": self.elapsed_ms}


@dataclass(frozen=True)
class BehavioralProfile:
    """Full behavioral profile of a sandbox execution."""
    package: str
    timing_points: List[TimingPoint] = field(default_factory=list)
    network_calls: List[NetworkCall] = field(default_factory=list)
    dns_queries: List[DnsQuery] = field(default_factory=list)
    fs_ops: List[FileOperation] = field(default_factory=list)
    spawns: List[ProcessSpawn] = field(default_factory=list)
    entrypoint: str = ""
    total_runtime_ms: int = 0
    exit_code: int = 0
    stdout_len: int = 0
    stderr_len: int = 0

    def to_dict(self) -> Dict:
        return {
            "package": self.package,
            "entrypoint": self.entrypoint,
            "total_runtime_ms": self.total_runtime_ms,
            "exit_code": self.exit_code,
            "stdout_len": self.stdout_len,
            "stderr_len": self.stderr_len,
            "timing_points_count": len(self.timing_points),
            "network_calls_count": len(self.network_calls),
            "dns_queries_count": len(self.dns_queries),
            "fs_ops_count": len(self.fs_ops),
            "spawns_count": len(self.spawns),
        }


@dataclass(frozen=True)
class Baseline:
    """A known-good behavioral baseline for a package."""
    name: str
    package: str
    version: str = ""
    expected_network_calls: int = 0
    expected_dns_queries: int = 0
    expected_fs_ops: int = 0
    expected_spawns: int = 0
    expected_runtime_ms_range: tuple = (0, 0)
    allowed_domains: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "package": self.package,
            "version": self.version,
            "expected_network_calls": self.expected_network_calls,
            "expected_dns_queries": self.expected_dns_queries,
            "expected_fs_ops": self.expected_fs_ops,
            "expected_spawns": self.expected_spawns,
            "expected_runtime_ms_range": list(self.expected_runtime_ms_range),
            "allowed_domains": list(self.allowed_domains),
            "allowed_paths": list(self.allowed_paths),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class DriftResult:
    """Result of comparing a profile against a baseline."""
    baseline_name: str
    score: float  # 0.0 = identical, 1.0 = completely different
    network_drift: bool = False
    dns_drift: bool = False
    fs_drift: bool = False
    spawn_drift: bool = False
    timing_drift: bool = False
    details: str = ""

    def to_dict(self) -> Dict:
        return {
            "baseline_name": self.baseline_name,
            "score": self.score,
            "network_drift": self.network_drift,
            "dns_drift": self.dns_drift,
            "fs_drift": self.fs_drift,
            "spawn_drift": self.spawn_drift,
            "timing_drift": self.timing_drift,
            "details": self.details,
        }


@dataclass(frozen=True)
class AnalysisResult:
    """Complete L4 behavioral analysis result."""
    target: str
    findings: List[Finding] = field(default_factory=list)
    profile: Optional[BehavioralProfile] = None
    drift_results: List[DriftResult] = field(default_factory=list)
    overall_verdict: BehavioralVerdict = BehavioralVerdict.CLEAN
    stats: ScanStats = field(default_factory=ScanStats)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "profile": self.profile.to_dict() if self.profile else None,
            "drift_results": [d.to_dict() for d in self.drift_results],
            "overall_verdict": self.overall_verdict.value,
            "stats": self.stats.to_dict(),
        }
