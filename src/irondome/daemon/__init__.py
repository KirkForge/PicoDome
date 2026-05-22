"""Iron Dome Daemon — HTTP API for sandbox-as-a-service.

Provides a REST API so the Shogun command center and other orchestration
tools can submit sandbox jobs, query results, and manage policies
programmatically.

Authentication: token-based (``Authorization: Bearer <token>``).
Transport: HTTP/1.1 over Unix socket or TCP.
"""

from __future__ import annotations

from irondome.daemon.server import IronDomeDaemon, create_app

__all__ = ["IronDomeDaemon", "create_app"]
