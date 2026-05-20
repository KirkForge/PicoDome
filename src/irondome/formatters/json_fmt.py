"""JSON formatter for Iron Dome results."""

from __future__ import annotations

import json
from typing import Any, Dict, Union

from irondome.l3.models import SandboxResult
from irondome.l4.models import AnalysisResult


def format_json(result: Union[SandboxResult, AnalysisResult], indent: int = 2) -> str:
    """Format a sandbox or analysis result as JSON."""
    return json.dumps(result.to_dict(), indent=indent, default=str)


def format_pipeline_json(
    sandbox: SandboxResult,
    analysis: AnalysisResult,
    indent: int = 2,
) -> str:
    """Format the full L3+L4 pipeline result as JSON."""
    output = {
        "pipeline": "iron-dome",
        "version": "0.1.0",
        "l3_sandbox": sandbox.to_dict(),
        "l4_analysis": analysis.to_dict(),
    }
    return json.dumps(output, indent=indent, default=str)
