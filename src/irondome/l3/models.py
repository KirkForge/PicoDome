"""L3 Execution Sandbox — data models."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

from irondome.models import Verdict, _now_iso


class SyscallAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    KILL = "kill"
    TRACE = "trace"


class RuleTarget(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_EXEC = "file_exec"
    NETWORK_OUT = "network_out"
    NETWORK_IN = "network_in"
    NETWORK_BIND = "network_bind"
    PROCESS_SPAWN = "process_spawn"
    PROCESS_KILL = "process_kill"
    DNS_QUERY = "dns_query"
    SIGNAL_SEND = "signal_send"
    SYSCALL_GENERIC = "syscall_generic"


@dataclass(frozen=True)
class PolicyRule:
    """A single rule in a sandbox policy. Frozen for determinism."""

    rule_id: str
    target: RuleTarget
    action: SyscallAction
    paths: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)
    syscalls: List[str] = field(default_factory=list)
    description: str = ""


@dataclass(frozen=True)
class Policy:
    """Sandbox execution policy. Frozen for determinism."""

    name: str
    version: str = "1.0"
    default_action: SyscallAction = SyscallAction.DENY
    rules: List[PolicyRule] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "default_action": self.default_action.value,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "target": r.target.value,
                    "action": r.action.value,
                    "paths": list(r.paths),
                    "addresses": list(r.addresses),
                    "syscalls": list(r.syscalls),
                    "description": r.description,
                }
                for r in self.rules
            ],
        }


@dataclass(frozen=True)
class SandboxEvent:
    """A single event from a sandbox run. Frozen for determinism."""

    rule_id: str
    verdict: Verdict
    operation: str
    detail: str
    path: str = ""
    address: str = ""
    timestamp_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "verdict": self.verdict.value,
            "operation": self.operation,
            "detail": self.detail,
            "path": self.path,
            "address": self.address,
        }


@dataclass(frozen=True)
class SandboxResult:
    """Result of a sandbox execution.

    NOTE: `run_id` and `timestamp` exist for internal tracing, but are deliberately
    omitted from `to_dict()` to preserve deterministic output.
    """

    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_now_iso)

    # Evidence metadata (deterministic)
    backend: str = ""
    policy_hash: str = ""
    policy_version: str = ""

    command: List[str] = field(default_factory=list)
    overall_verdict: Verdict = Verdict.ALLOW
    exit_code: int = 0
    duration_ms: int = 0
    events: List[SandboxEvent] = field(default_factory=list)
    policy_name: str = ""
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> Dict:
        return {
            "command": list(self.command),
            "overall_verdict": self.overall_verdict.value,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "events": [e.to_dict() for e in self.events],
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "backend": self.backend,
        }
