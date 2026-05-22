"""Iron Dome Daemon — HTTP API server for sandbox-as-a-service.

Uses Python's built-in ``http.server`` for zero-dependency deployment.
No Flask, no FastAPI — Iron Dome stays dependency-free at runtime.

Endpoints:

    GET  /health                 — Health check (unauthenticated)
    GET  /ready                  — Readiness probe
    POST /api/v1/scan            — Submit a sandbox scan job
    GET  /api/v1/scan/:id        — Get scan result by ID
    GET  /api/v1/scans           — List recent scans
    GET  /api/v1/policies        — List policies
    GET  /api/v1/policies/:name  — Get policy detail
    POST /api/v1/policies        — Create/update a policy
    GET  /api/v1/baselines       — List baselines
    GET  /api/v1/audit           — Query audit log
    GET  /api/v1/stats           — System statistics
    GET  /metrics                — Prometheus-format metrics

Authentication: Bearer token via ``Authorization`` header.
Tokens are validated against ``IRONDOME_API_TOKENS`` (comma-separated)
or a tokens file at ``~/.irondome/api-tokens``.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import import_module
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from irondome import __version__
from irondome.audit import AuditEventType, get_audit_logger
from irondome.l3.backends.base import SandboxBackend
from irondome.l3.engine import sandbox_run
from irondome.l3.policy import default_policy, load_policy
from irondome.l4.engine import create_default_engine
from irondome.l4.profiler import profile_from_sandbox_result
from irondome.retention import get_retention_manager

logger = logging.getLogger("irondome.daemon")

# ─── API version ────────────────────────────────────────────────────────────

API_VERSION = "v1"

# ─── Token auth ─────────────────────────────────────────────────────────────


class TokenAuth:
    """Simple bearer-token authentication.

    Tokens are loaded from:
    1. ``IRONDOME_API_TOKENS`` env var (comma-separated)
    2. ``~/.irondome/api-tokens`` file (one token per line)

    Token format: ``irondome-<role>-<secret>`` (e.g., ``irondome-admin-abc123``)
    """

    def __init__(self, rbac: RBAC | None = None) -> None:
        self._tokens: set = set()
        self._rbac = rbac
        self._load_tokens()

    def _load_tokens(self) -> None:
        # From environment
        env_tokens = os.environ.get("IRONDOME_API_TOKENS", "")
        for token in env_tokens.split(","):
            token = token.strip()
            if token:
                self._tokens.add(token)
                self._register_role(token)

        # From file
        token_file = Path.home() / ".irondome" / "api-tokens"
        if token_file.is_file():
            try:
                for line in token_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._tokens.add(line)
                        self._register_role(line)
            except OSError:
                pass

        logger.info("Loaded %d API token(s)", len(self._tokens))

    def _register_role(self, token: str) -> None:
        """Parse token format irondome-<role>-<secret> and register with RBAC."""
        if self._rbac and token.startswith("irondome-"):
            parts = token.split("-", 2)
            if len(parts) >= 3:
                role = parts[1]
                self._rbac.register_token(token, role)

    def validate(self, token: str) -> bool:
        """Check if a token is valid."""
        if not self._tokens:
            if os.environ.get("IRONDOME_DEV_MODE", "").lower() in ("1", "true", "yes"):
                logger.warning("DEV MODE: No API tokens configured — all requests authenticated")
                return True
            logger.warning(
                "No API tokens configured — rejecting all requests. "
                "Set IRONDOME_API_TOKENS or IRONDOME_DEV_MODE=1"
            )
            return False
        return token in self._tokens

    @property
    def is_configured(self) -> bool:
        return len(self._tokens) > 0

# ─── RBAC ───────────────────────────────────────────────────────────────────


class Role(str):
    SUBMITTER = "submitter"
    READER = "reader"
    ADMIN = "admin"


class RBAC:
    """Simple role-based access control.

    Tokens are registered explicitly with their role. No role is
    extracted from the token string — this prevents spoofing via
    token prefix parsing.
    """

    ROLE_PERMISSIONS = {
        Role.SUBMITTER: {"scan:submit", "scan:read", "health"},
        Role.READER: {"scan:read", "policy:read", "baseline:read", "audit:read", "health"},
        Role.ADMIN: {"*"},  # all permissions
    }

    def __init__(self) -> None:
        self._token_roles: dict[str, str] = {}

    def register_token(self, token: str, role: str) -> None:
        """Register a token with a specific role."""
        self._token_roles[token] = role

    def get_role(self, token: str) -> str:
        """Look up role for a token from the registered mapping."""
        return self._token_roles.get(token, Role.READER)

    def has_permission(self, token: str, permission: str) -> bool:
        """Check if a token's role has a specific permission."""
        role = self.get_role(token)
        perms = self.ROLE_PERMISSIONS.get(role, set())
        return "*" in perms or permission in perms

# ─── Scan job tracker ───────────────────────────────────────────────────────


class ScanJob:
    """Track an in-flight or completed scan job."""

    def __init__(self, job_id: str, command: list[str], actor: str) -> None:
        self.job_id = job_id
        self.command = command
        self.actor = actor
        self.status = "pending"
        self.created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.completed_at: str | None = None
        self.result: dict | None = None
        self.error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "command": self.command,
            "created_at": self.created_at,
            "job_id": self.job_id,
            "status": self.status,
        }
        if self.completed_at:
            d["completed_at"] = self.completed_at
        if self.result:
            d["result"] = self.result
        if self.error:
            d["error"] = self.error
        return d


class ScanJobStore:
    """In-memory store of recent scan jobs (bounded)."""

    def __init__(self, max_jobs: int = 1000) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._max_jobs = max_jobs

    def add(self, job: ScanJob) -> None:
        self._jobs[job.job_id] = job
        # Evict oldest if over limit
        if len(self._jobs) > self._max_jobs:
            oldest_key = min(self._jobs, key=lambda k: self._jobs[k].created_at)
            del self._jobs[oldest_key]

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def list_recent(self, limit: int = 50) -> list[ScanJob]:
        jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

# ─── HTTP handler ────────────────────────────────────────────────────────────


class IronDomeHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Iron Dome daemon."""

    # Set by the server at creation time
    # Set by the server at creation time
    # Set by the server at creation time
    rbac: RBAC = RBAC()
    auth: TokenAuth = TokenAuth(rbac=rbac)
    job_store: ScanJobStore = ScanJobStore()
    _start_time: float = time.time()
    _scan_count: int = 0
    _scan_total_ms: int = 0
    _alert_count: int = 0

    def log_message(self, format, *args):
        logger.debug("HTTP %s", format % args)

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json({"error": message, "status": status}, status)

    def _get_token(self) -> str | None:
        """Extract bearer token from Authorization header."""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        return None

    def _require_auth(self) -> str | None:
        """Validate authentication. Returns token or sends 401."""
        token = self._get_token()

        if not self.auth.is_configured:
            return "no-auth-dev-mode"

        if not token or not self.auth.validate(token):
            self._send_error(401, "Unauthorized: invalid or missing token")
            return None

        return token

    def _require_permission(self, permission: str) -> str | None:
        """Require auth + permission. Returns token or sends 403."""
        token = self._require_auth()
        if token is None:
            return None

        if not self.rbac.has_permission(token, permission):
            self._send_error(403, f"Forbidden: insufficient permissions ({permission})")
            return None

        return token

    # ── GET ──────────────────────────────────────────────────────────────

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        # Health / ready (unauthenticated)
        if path == "/health":
            self._handle_health()
        elif path == "/ready":
            self._handle_ready()
        elif path == "/metrics":
            token = self._require_permission("scan:read")
            if token:
                self._handle_metrics()

        # Authenticated GET endpoints
        elif path == f"/api/{API_VERSION}/scans":
            token = self._require_permission("scan:read")
            if token:
                self._handle_list_scans(query)
        elif path.startswith(f"/api/{API_VERSION}/scan/"):
            token = self._require_permission("scan:read")
            if token:
                job_id = path.split("/")[-1]
                self._handle_get_scan(job_id)
        elif path == f"/api/{API_VERSION}/policies":
            token = self._require_permission("policy:read")
            if token:
                self._handle_list_policies()
        elif path.startswith(f"/api/{API_VERSION}/policies/"):
            token = self._require_permission("policy:read")
            if token:
                name = path.split("/")[-1]
                self._handle_get_policy(name)
        elif path == f"/api/{API_VERSION}/baselines":
            token = self._require_permission("baseline:read")
            if token:
                self._handle_list_baselines()
        elif path == f"/api/{API_VERSION}/audit":
            token = self._require_permission("audit:read")
            if token:
                self._handle_audit_query(query)
        elif path == f"/api/{API_VERSION}/stats":
            token = self._require_permission("scan:read")
            if token:
                self._handle_stats()
        else:
            self._send_error(404, f"Not found: {path}")

    # ── POST ─────────────────────────────────────────────────────────────

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == f"/api/{API_VERSION}/scan":
            token = self._require_permission("scan:submit")
            if token:
                self._handle_submit_scan(token)
        elif path == f"/api/{API_VERSION}/policies":
            token = self._require_permission("policy:write")
            if token:
                self._handle_create_policy(token)
        else:
            self._send_error(404, f"Not found: {path}")

    # ── Route handlers ───────────────────────────────────────────────────

    def _handle_health(self) -> None:
        uptime = int(time.time() - self._start_time)
        self._send_json({
            "status": "healthy",
            "version": __version__,
            "api_version": API_VERSION,
            "uptime_seconds": uptime,
        })

    def _handle_ready(self) -> None:
        # Check that sandbox engine works
        try:
            from irondome.l3.engine import get_backend
            backend = get_backend()
            self._send_json({"status": "ready", "backend": backend.name})
        except Exception as e:
            self._send_error(503, f"Not ready: {e}")

    def _handle_metrics(self) -> None:
        """Prometheus-format metrics endpoint."""
        uptime = int(time.time() - self._start_time)
        avg_ms = self._scan_total_ms / max(self._scan_count, 1)

        lines = [
            "# HELP irondome_scans_total Total number of scans executed",
            "# TYPE irondome_scans_total counter",
            f"irondome_scans_total {self._scan_count}",
            "",
            "# HELP irondome_scan_duration_ms_avg Average scan duration in ms",
            "# TYPE irondome_scan_duration_ms_avg gauge",
            f"irondome_scan_duration_ms_avg {avg_ms}",
            "",
            "# HELP irondome_alerts_total Total number of alerts generated",
            "# TYPE irondome_alerts_total counter",
            f"irondome_alerts_total {self._alert_count}",
            "",
            "# HELP irondome_uptime_seconds Daemon uptime in seconds",
            "# TYPE irondome_uptime_seconds gauge",
            f"irondome_uptime_seconds {uptime}",
            "",
            "# HELP irondome_version IronDome version info",
            '# TYPE irondome_version gauge',
            f'irondome_version{{version="{__version__}"}} 1',
        ]

        body = "\n".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_submit_scan(self, token: str) -> None:
        """Submit a sandbox scan job."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._send_error(400, f"Invalid JSON body: {e}")
            return

        command = data.get("command")
        if not command or not isinstance(command, list):
            self._send_error(400, "Missing or invalid 'command' field (must be a list)")
            return

        timeout = data.get("timeout", 30.0)
        data.get("policy")

        job_id = str(uuid.uuid4())[:8]
        job = ScanJob(job_id=job_id, command=command, actor=token[:16] if token else "unknown")
        self.job_store.add(job)

        # Audit
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor=job.actor,
                detail=f"{' '.join(command)}",
                target=command[0] if command else "",
                metadata={"job_id": job_id, "timeout": timeout},
            )
        except Exception:
            pass

        try:
            # Resolve policy
            policy_name = data.get("policy")
            if policy_name:
                try:
                    policy = load_policy(name=policy_name)
                except Exception:
                    logger.warning(
                        "Policy '%s' not found, using default", policy_name
                    )
                    policy = default_policy()
            else:
                policy = default_policy()

            # Resolve backend
            backend_name = data.get("backend", "auto")
            backend: SandboxBackend | None = None
            if backend_name != "auto":
                backend_map = {
                    "subprocess": "irondome.l3.backends.subprocess_backend:SubprocessBackend",
                    "seccomp-bpf": "irondome.l3.backends.seccomp_backend:SeccompBackend",
                    "seatbelt": "irondome.l3.backends.seatbelt_backend:SeatbeltBackend",
                }
                cls_path = backend_map.get(backend_name)
                if cls_path is None:
                    self._send_error(400, f"Unknown backend: {backend_name}")
                    return
                try:
                    module_path, cls_name = cls_path.rsplit(":", 1)

                    backend_cls = getattr(import_module(module_path), cls_name)
                    backend = backend_cls()
                    if not backend.is_available():
                        self._send_error(503, f"Backend '{backend_name}' not available on this system")
                        return
                except Exception as e:
                    self._send_error(503, f"Backend '{backend_name}' unavailable: {e}")
                    return

            # Run sandbox
            sandbox_result = sandbox_run(
                command=command,
                policy=policy,
                timeout=timeout,
                backend=backend,
                deterministic=False,
            )

            # Run L4 analysis
            engine = create_default_engine()
            profile = profile_from_sandbox_result(sandbox_result)
            analysis_result = engine.analyze(profile, deterministic=False)

            # Build result
            result = {
                "job_id": job_id,
                "sandbox": sandbox_result.to_dict(deterministic=False),
                "analysis": analysis_result.to_dict(deterministic=False),
                "l3_verdict": sandbox_result.overall_verdict.value,
                "l4_verdict": analysis_result.overall_verdict.value,
                "findings_count": len(analysis_result.findings),
                "backend": sandbox_result.backend_name,
                "isolation_level": sandbox_result.isolation_level,
                "enforcement_guarantee": sandbox_result.enforcement_guarantee,
                "degraded": sandbox_result.degraded,
                "policy_name": policy.name,
                "policy_version": policy.version,
            }

            job.status = "completed"
            job.completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            job.result = result

            # Update metrics
            self._scan_count += 1
            self._scan_total_ms += sandbox_result.duration_ms
            self._alert_count += len(analysis_result.findings)

            # Audit
            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.SCAN_COMPLETE,
                    actor=job.actor,
                    detail=f"l3={sandbox_result.overall_verdict.value} l4={analysis_result.overall_verdict.value}",
                    target=command[0] if command else "",
                    metadata={"job_id": job_id, "findings": len(analysis_result.findings)},
                )
            except Exception:
                pass

            # Persist result
            try:
                rm = get_retention_manager()
                rm.save_scan_result(
                    json.dumps(result, sort_keys=True, default=str),
                    package_name=command[0] if command else "unknown",
                )
            except Exception:
                pass

            self._send_json(result, status=201)

        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            logger.exception("Scan job %s failed", job_id)
            self._send_error(500, f"Scan failed: {e}")

    def _handle_get_scan(self, job_id: str) -> None:
        job = self.job_store.get(job_id)
        if job:
            self._send_json(job.to_dict())
        else:
            self._send_error(404, f"Scan job not found: {job_id}")

    def _handle_list_scans(self, query: dict) -> None:
        limit = int(query.get("limit", ["50"])[0])
        jobs = self.job_store.list_recent(limit=limit)
        self._send_json({
            "scans": [j.to_dict() for j in jobs],
            "count": len(jobs),
        })

    def _handle_list_policies(self) -> None:
        from irondome.policy_versioned import get_policy_store
        store = get_policy_store()
        names = store.list_policies()
        self._send_json({"policies": names, "count": len(names)})

    def _handle_get_policy(self, name: str) -> None:
        from irondome.policy_versioned import get_policy_store
        store = get_policy_store()
        pv = store.load(name)
        if pv:
            self._send_json(pv.to_dict())
        else:
            self._send_error(404, f"Policy not found: {name}")

    def _handle_create_policy(self, token: str) -> None:
        """Create or update a policy."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._send_error(400, f"Invalid JSON body: {e}")
            return

        from irondome.l3.policy import _policy_from_dict
        from irondome.policy_versioned import get_policy_store

        try:
            policy = _policy_from_dict(data)
            store = get_policy_store()
            author = data.get("author", token[:16] if token else "unknown")
            description = data.get("change_description", "")
            pv = store.save(policy, author=author, change_description=description)
            self._send_json(pv.to_dict(), status=201)
        except Exception as e:
            self._send_error(400, f"Invalid policy: {e}")

    def _handle_list_baselines(self) -> None:
        from irondome.l4.baseline import load_all_baselines
        baselines = load_all_baselines()
        self._send_json({
            "baselines": {k: v.to_dict() for k, v in baselines.items()},
            "count": len(baselines),
        })

    def _handle_audit_query(self, query: dict) -> None:
        from irondome.audit import AuditEventType, get_audit_logger
        audit = get_audit_logger()

        event_type = None
        if "event_type" in query:
            try:
                event_type = AuditEventType(query["event_type"][0])
            except ValueError:
                pass

        events = audit.query(
            event_type=event_type,
            actor=query.get("actor", [None])[0],
            target=query.get("target", [None])[0],
            since=query.get("since", [None])[0],
            until=query.get("until", [None])[0],
            limit=int(query.get("limit", ["100"])[0]),
        )
        self._send_json({
            "events": [e.to_dict() for e in events],
            "count": len(events),
        })

    def _handle_stats(self) -> None:
        rm = get_retention_manager()
        storage = rm.get_storage_stats()
        audit = get_audit_logger()
        audit_stats = audit.get_stats()

        self._send_json({
            "version": __version__,
            "uptime_seconds": int(time.time() - self._start_time),
            "scans_total": self._scan_count,
            "scans_avg_ms": self._scan_total_ms / max(self._scan_count, 1),
            "alerts_total": self._alert_count,
            "storage": storage,
            "audit": audit_stats,
        })

# ─── Daemon class ────────────────────────────────────────────────────────────


class IronDomeDaemon:
    """Iron Dome daemon — HTTP API server for sandbox-as-a-service.

    Usage::

        daemon = IronDomeDaemon(host="0.0.0.0", port=8443)
        daemon.start()   # blocking
        # or
        daemon.start(background=True)

    Configuration:
        - ``IRONDOME_DAEMON_HOST`` — bind address (default: 127.0.0.1)
        - ``IRONDOME_DAEMON_PORT`` — bind port (default: 8443)
        - ``IRONDOME_API_TOKENS`` — comma-separated auth tokens
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        self._host = host or os.environ.get("IRONDOME_DAEMON_HOST", "127.0.0.1")
        self._port = port or int(os.environ.get("IRONDOME_DAEMON_PORT", "8443"))
        self._server: HTTPServer | None = None

    def start(self, background: bool = False) -> None:
        """Start the daemon HTTP server."""
        server = HTTPServer((self._host, self._port), IronDomeHandler)
        self._server = server

        # Audit
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.DAEMON_START,
                actor="irondome-daemon",
                detail=f"Listening on {self._host}:{self._port}",
            )
        except Exception:
            pass

        logger.info("Iron Dome daemon starting on %s:%d", self._host, self._port)

        if background:
            import threading
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
        else:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        """Stop the daemon."""
        if self._server:
            self._server.shutdown()

            try:
                audit = get_audit_logger()
                audit.record(
                    event_type=AuditEventType.DAEMON_STOP,
                    actor="irondome-daemon",
                    detail="Daemon stopped",
                )
            except Exception:
                pass

            logger.info("Iron Dome daemon stopped")


def create_app() -> IronDomeDaemon:
    """Factory for creating a configured daemon instance."""
    return IronDomeDaemon()
