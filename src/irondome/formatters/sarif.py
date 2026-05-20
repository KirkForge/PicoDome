"""SARIF 2.1.0 formatter for Iron Dome results."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Union

from irondome.l3.models import SandboxResult
from irondome.l4.models import AnalysisResult


def format_sarif(result: Union[SandboxResult, AnalysisResult]) -> str:
    """Format sandbox or analysis result as SARIF 2.1.0."""
    if isinstance(result, SandboxResult):
        return _l3_sarif(result)
    return _l4_sarif(result)


def _l3_sarif(result: SandboxResult) -> str:
    """Format L3 sandbox result as SARIF."""
    results: List[Dict] = []
    for event in result.events:
        results.append({
            "ruleId": event.rule_id,
            "level": _severity_to_sarif(event.verdict.value),
            "message": {"text": event.detail},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": event.path or "unknown"},
                    "region": {"startLine": 1},
                }
            }] if event.path else [],
            "properties": {
                "operation": event.operation,
                "address": event.address,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "IronDome",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/KirkForge/IronDome",
                    "rules": list({
                        "id": e.rule_id,
                        "shortDescription": {"text": e.operation},
                    } for e in result.events),
                }
            },
            "results": results,
            "properties": {
                "command": result.command,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "overall_verdict": result.overall_verdict.value,
                "policy": result.policy_name,
            },
        }],
    }
    return json.dumps(sarif, indent=2, default=str)


def _l4_sarif(result: AnalysisResult) -> str:
    """Format L4 analysis result as SARIF."""
    results: List[Dict] = []
    for finding in result.findings:
        results.append({
            "ruleId": finding.rule_id,
            "level": _severity_to_sarif(finding.severity.value),
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location or "unknown"},
                }
            }],
            "properties": finding.evidence,
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "IronDome",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/KirkForge/IronDome",
                }
            },
            "results": results,
            "properties": {
                "target": result.target,
                "overall_verdict": result.overall_verdict.value,
            },
        }],
    }
    return json.dumps(sarif, indent=2, default=str)


def _severity_to_sarif(severity: str) -> str:
    """Map Iron Dome severity to SARIF level."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
        "ALLOW": "none",
        "DENY": "error",
        "KILL": "error",
    }
    return mapping.get(severity, "warning")
