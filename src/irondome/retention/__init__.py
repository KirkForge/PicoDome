"""Data retention lifecycle management.

Configurable TTL per data type (scan results, audit logs, baselines).
Automatic cleanup of expired data. Secure deletion support.
"""

from __future__ import annotations

from irondome.retention.manager import (
    RetentionManager,
    RetentionConfig,
    RetentionPolicy,
    get_retention_manager,
)

__all__ = ["RetentionManager", "RetentionConfig", "RetentionPolicy", "get_retention_manager"]
