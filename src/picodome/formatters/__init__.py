"""PicoDome output formatters.

Available formatters:
- format_json: JSON output (deterministic mode available)
- format_sarif: SARIF 2.1.0 output
- format_table: Human-readable table with dome pinch labels
- format_ml_context: Compact token-budgeted output for LLM context
- format_github: GitHub Actions SARIF + markdown summary
- format_cyclonedx: CycloneDX 1.5 SBOM format
"""

from picodome.formatters.cyclonedx import format_cyclonedx
from picodome.formatters.github import format_github
from picodome.formatters.json_fmt import format_json, format_pipeline_json
from picodome.formatters.ml_context import format_ml_context
from picodome.formatters.sarif import format_sarif
from picodome.formatters.table import format_table

__all__ = [
    "format_json",
    "format_pipeline_json",
    "format_sarif",
    "format_table",
    "format_ml_context",
    "format_github",
    "format_cyclonedx",
]
