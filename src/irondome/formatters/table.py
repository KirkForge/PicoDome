"""Table formatter for Iron Dome results."""

from __future__ import annotations

from typing import Union

from irondome.l3.models import SandboxResult, Verdict
from irondome.l4.models import AnalysisResult, BehavioralVerdict


def format_table(result: Union[SandboxResult, AnalysisResult]) -> str:
    """Format sandbox or analysis result as a human-readable table."""
    if isinstance(result, SandboxResult):
        return _l3_table(result)
    return _l4_table(result)


def _l3_table(result: SandboxResult) -> str:
    """Format L3 sandbox result as a table."""
    width = max(80, len(" ".join(result.command)) + 20)

    lines = [
        "╔" + "═" * (width - 2) + "╗",
        f"║ {'IRON DOME — L3 SANDBOX':^{width - 4}} ║",
        "╠" + "═" * (width - 2) + "╣",
        f"║ {'Command:':<16} {' '.join(result.command):<{width - 20}} ║",
        f"║ {'Run ID:':<16} {result.run_id:<{width - 20}} ║",
        f"║ {'Policy:':<16} {result.policy_name:<{width - 20}} ║",
        f"║ {'Duration:':<16} {result.duration_ms}ms{'':<{width - 23 - len(str(result.duration_ms))}} ║",
        f"║ {'Exit Code:':<16} {result.exit_code:<{width - 20}} ║",
    ]

    verdict_icon = _verdict_icon(result.overall_verdict)
    lines.append(f"║ {'Verdict:':<16} {verdict_icon} {result.overall_verdict.value}{'':<{width - 23 - len(result.overall_verdict.value)}} ║")

    if result.events:
        lines.append("╠" + "═" * (width - 2) + "╣")
        lines.append(f"║ {'EVENTS':^{width - 4}} ║")
        lines.append("╟" + "─" * (width - 2) + "╢")

        for event in result.events[:20]:
            icon = _verdict_icon(event.verdict)
            detail = event.detail[:width - 30] if len(event.detail) > width - 30 else event.detail
            lines.append(f"║ {icon} {event.rule_id:<16} {detail:<{width - 21}} ║")

        if len(result.events) > 20:
            lines.append(f"║ {'... and ' + str(len(result.events) - 20) + ' more events':^{width - 4}} ║")

    lines.append("╚" + "═" * (width - 2) + "╝")

    if result.stderr:
        lines.append("")
        lines.append("STDERR:")
        lines.append(result.stderr[:500])

    return "\n".join(lines)


def _l4_table(result: AnalysisResult) -> str:
    """Format L4 analysis result as a table."""
    width = 80

    verdict_icon = _behavioral_icon(result.overall_verdict)
    lines = [
        "╔" + "═" * (width - 2) + "╗",
        f"║ {'IRON DOME — L4 BEHAVIORAL ANALYSIS':^{width - 4}} ║",
        "╠" + "═" * (width - 2) + "╣",
        f"║ {'Target:':<16} {result.target:<{width - 20}} ║",
        f"║ {'Verdict:':<16} {verdict_icon} {result.overall_verdict.value}{'':<{width - 26 - len(result.overall_verdict.value)}} ║",
        f"║ {'Duration:':<16} {result.stats.duration_ms}ms{'':<{width - 20 - len(str(result.stats.duration_ms))}} ║",
    ]

    if result.findings:
        lines.append("╠" + "═" * (width - 2) + "╣")
        lines.append(f"║ {'FINDINGS (' + str(len(result.findings)) + ')':^{width - 4}} ║")
        lines.append("╟" + "─" * (width - 2) + "╢")

        for finding in result.findings[:20]:
            sev = finding.severity.value[:4]
            msg = finding.message[:width - 30] if len(finding.message) > width - 30 else finding.message
            lines.append(f"║ [{sev}] {finding.rule_id:<14} {msg:<{width - 22}} ║")

        if len(result.findings) > 20:
            lines.append(f"║ {'... and ' + str(len(result.findings) - 20) + ' more findings':^{width - 4}} ║")

    if result.drift_results:
        lines.append("╠" + "═" * (width - 2) + "╣")
        lines.append(f"║ {'BASELINE DRIFT':^{width - 4}} ║")
        for drift in result.drift_results:
            lines.append(f"║   Baseline: {drift.baseline_name:<{width - 16}} ║")
            lines.append(f"║   Drift Score: {drift.score:.0%}{'':<{width - 19}} ║")

    lines.append("╚" + "═" * (width - 2) + "╝")
    return "\n".join(lines)


def _verdict_icon(verdict: Verdict) -> str:
    if verdict == Verdict.ALLOW:
        return "✅"
    if verdict == Verdict.DENY:
        return "🚫"
    if verdict == Verdict.KILL:
        return "💀"
    return "❓"


def _behavioral_icon(verdict: BehavioralVerdict) -> str:
    if verdict == BehavioralVerdict.CLEAN:
        return "✅"
    if verdict == BehavioralVerdict.SUSPICIOUS:
        return "⚠️"
    if verdict == BehavioralVerdict.MALICIOUS:
        return "🚫"
    return "❓"
