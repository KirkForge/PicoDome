"""L4 Behavioral Analysis — post-execution profiling and anomaly detection."""

from irondome.l4.engine import L4Engine, analyze, create_default_engine
from irondome.l4.models import (
    BehavioralProfile,
    AnalysisResult,
    Baseline,
    DriftResult,
)
from irondome.l4.profiler import profile_from_sandbox_result, profile_from_trace

__all__ = [
    "L4Engine",
    "analyze",
    "create_default_engine",
    "BehavioralProfile",
    "AnalysisResult",
    "Baseline",
    "DriftResult",
    "profile_from_sandbox_result",
    "profile_from_trace",
]
