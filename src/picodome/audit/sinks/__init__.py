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

from picodome.audit.sinks.base import (
    SINK_REGISTRY,
    AuditSink,
    NullSink,
    SinkConfig,
    create_sink,
    register_sink,
)
from picodome.audit.sinks.file_sink import FileSink
from picodome.audit.sinks.syslog_sink import SyslogSink
from picodome.audit.sinks.webhook_sink import WebhookSink

# Register built-in sinks
register_sink("null", NullSink)
register_sink("file", FileSink)
register_sink("webhook", WebhookSink)
register_sink("syslog", SyslogSink)

__all__ = [
    "AuditSink",
    "NullSink",
    "SinkConfig",
    "SINK_REGISTRY",
    "create_sink",
    "register_sink",
    "FileSink",
    "WebhookSink",
    "SyslogSink",
]
