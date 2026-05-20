"""L3 policy loading and defaults."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from irondome.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction

# Default deny-by-default policy with common safe allowances
DEFAULT_RULES: list = [
    # Allow reading system libraries and config
    {"rule_id": "L3-FILE-R-001", "target": "file_read", "action": "allow",
     "paths": ["/usr/lib/**", "/lib/**", "/usr/share/**", "/etc/ld.so.cache", "/etc/localtime", "/proc/self/**"],
     "description": "Read system libraries and locale info"},
    # Allow reading Python standard library
    {"rule_id": "L3-FILE-R-002", "target": "file_read", "action": "allow",
     "paths": ["/usr/lib/python3*/**", "**/site-packages/**"],
     "description": "Read Python packages"},
    # Allow reading the project directory
    {"rule_id": "L3-FILE-R-003", "target": "file_read", "action": "allow",
     "paths": ["**"], "description": "Read project files"},
    # Deny writing outside /tmp and project dir
    {"rule_id": "L3-FILE-W-001", "target": "file_write", "action": "allow",
     "paths": ["/tmp/**", "/dev/null", "/dev/stdout", "/dev/stderr"],
     "description": "Write to temp and stdio only"},
    # Deny network outbound (except DNS for resolution)
    {"rule_id": "L3-NET-OUT-001", "target": "network_out", "action": "deny",
     "description": "Block all outbound network"},
    # Allow DNS for name resolution
    {"rule_id": "L3-DNS-001", "target": "dns_query", "action": "allow",
     "description": "Allow DNS resolution"},
    # Deny process spawning
    {"rule_id": "L3-PROC-001", "target": "process_spawn", "action": "deny",
     "description": "Block process spawning"},
    # Deny network bind/listen
    {"rule_id": "L3-NET-BIND-001", "target": "network_bind", "action": "deny",
     "description": "Block network bind/listen"},
]


def load_policy(path: Optional[Path] = None) -> Policy:
    """Load a sandbox policy from a JSON file, or return the default."""
    if path is not None:
        with open(path) as f:
            data = json.load(f)
        return _policy_from_dict(data)

    return default_policy()


def default_policy() -> Policy:
    """Return the built-in default policy."""
    rules = []
    for r in DEFAULT_RULES:
        rules.append(PolicyRule(
            rule_id=r["rule_id"],
            target=RuleTarget(r["target"]),
            action=SyscallAction(r["action"]),
            paths=r.get("paths", []),
            addresses=r.get("addresses", []),
            syscalls=r.get("syscalls", []),
            description=r.get("description", ""),
        ))
    return Policy(
        name="iron-dome-default",
        version="1.0",
        default_action=SyscallAction.DENY,
        rules=rules,
    )


def _policy_from_dict(data: dict) -> Policy:
    """Build a Policy from a dictionary."""
    rules = []
    for r in data.get("rules", []):
        rules.append(PolicyRule(
            rule_id=r["rule_id"],
            target=RuleTarget(r["target"]),
            action=SyscallAction(r["action"]),
            paths=r.get("paths", []),
            addresses=r.get("addresses", []),
            syscalls=r.get("syscalls", []),
            description=r.get("description", ""),
        ))
    return Policy(
        name=data.get("name", "custom"),
        version=data.get("version", "1.0"),
        default_action=SyscallAction(data.get("default_action", "deny")),
        rules=rules,
    )
