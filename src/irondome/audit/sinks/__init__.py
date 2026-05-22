"""Audit sinks — forward audit events to external systems.

Sinks receive AuditEvent objects after they are recorded in the local
audit log.  Each sink is an independent output: failure in one sink
must never block or crash another.

Built-in sinks:
  NullSink   — no-op (default, used when no external sink is configured)
  FileSink   — JSONL with size-based rotation  (B02)
  WebhookSink — POST JSON to URL with retry    (B03)
  SyslogSink — RFC 5424 UDP                    (B04)
"""

from irondome.audit.sinks.base import AuditSink, NullSink, SinkConfig

__all__ = ["AuditSink", "NullSink", "SinkConfig"]
