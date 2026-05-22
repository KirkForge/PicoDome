"""Iron Dome Audit — structured, tamper-evident audit logging.

Append-only JSON-lines audit log with hash chaining for integrity.
Every policy mutation, scan execution, and baseline change is recorded
with actor identity, timestamp, and a chain link to the previous entry.
"""

from __future__ import annotations

from irondome.audit.logger import AuditLogger, AuditEvent, AuditEventType, get_audit_logger, setup_audit_logger

__all__ = [
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "get_audit_logger",
    "setup_audit_logger",
]
