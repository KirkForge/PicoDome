"""Versioned policy store — track who changed what and when.

Wraps the existing Policy model with versioning metadata (author,
timestamp, change description) and provides diff, rollback, and
signing capabilities.
"""

from __future__ import annotations

from irondome.policy_versioned.store import (
    PolicyVersion,
    VersionedPolicyStore,
    get_policy_store,
)

__all__ = ["PolicyVersion", "VersionedPolicyStore", "get_policy_store"]
