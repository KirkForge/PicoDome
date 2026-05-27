# Iron Dome — State & Status

**Version:** 0.5.0 | **Repo:** https://github.com/KirkForge/IronDome
**Tests:** 1406/1418 passing, 12 skipped (sandbox-dependent) | **Backends:** 3 (seccomp, seatbelt, subprocess)
**Formatters:** 6 (json, sarif, table, ml-context, github, cyclonedx)
**Transports:** 2 (HTTP, gRPC)
**Status:** Enterprise Beta — controlled pilot ready

---

## Architecture

```
CLI (cli.py)
  → L3 Engine (l3/engine.py) — auto-detects backend
     → SeccompBackend (l3/backends/seccomp_backend.py) — libseccomp via ctypes
     → SeatbeltBackend (l3/backends/seatbelt_backend.py) — sandbox-exec profile gen
     → SubprocessBackend (l3/backends/subprocess_backend.py) — universal fallback
  → L4 Engine (l4/engine.py) — behavioral analysis pipeline
     → Profiler (l4/profiler.py) — extract profile from sandbox output
     → Differ (l4/differ.py) — compare profile against baselines
     → Rules (l4/rules/*.py) — 5 detector rules
     → Baselines (l4/baseline.py) — 5 shipped baselines
  → Formatters (formatters/*.py) — json, sarif, table, ml-context, github, cyclonedx
  → Guards (guards.py) — 4-layer determinism enforcement
  → Daemon (daemon/) — HTTP API server with auth, RBAC, metrics
  → gRPC Transport (grpc_transport/) — optional high-throughput gRPC transport
     → Server (grpc_transport/server.py) — IronDomeGRPCServer wraps scan engine
     → Client (grpc_transport/client.py) — IronDomeGRPCClient with retry logic
     → Servicer (grpc_transport/_servicer.py) — IronDomeService RPC handlers
     → Proto (grpc_transport/proto/irondome.proto) — protobuf schema
  → License (license.py) — personal/commercial tier enforcement
  → Logging (logging.py) — structured JSON logging for SIEM
  → Models (models.py) — frozen dataclasses, determinism by design
  → Workspace (workspace.py) — multi-project monorepo scanning
```

## Backend Status

| Backend | Platform | Implementation | Syscall Filtering | Post-hoc Analysis |
|---------|----------|----------------|-------------------|-------------------|
| seccomp-bpf | Linux | libseccomp ctypes + fork/exec | ✅ Real BPF filter | ✅ Suspicious patterns |
| seatbelt | macOS | sandbox-exec + profile DSL | ✅ Generated profiles | ✅ Suspicious patterns |
| subprocess | Universal | Popen + regex analysis | ❌ (process-level only) | ✅ 10 pattern categories |

## L3 Default Policy

The built-in policy (`iron-dome-default`) is deny-by-default with explicit allows:

- **Allowed:** File reads (system libs, Python packages, project files), DNS resolution, writes to /tmp and stdio
- **Blocked:** Outbound network, inbound network, process spawning, network bind/listen
- **Detected:** 10 suspicious output patterns (eval, curl, chmod, base64, etc.)

## L4 Detector Details

| Rule ID | Rule | Detection Method | Baseline-Aware |
|---------|------|-----------------|----------------|
| L4-TIME | Timing anomalies | Runtime thresholds, baseline comparison | Yes |
| L4-EXFIL | Data exfiltration | Suspicious TLDs, non-standard ports, large transfers, credential reads + network | No |
| L4-ENTROPY | Entropy anomalies | Shannon entropy on filenames and DNS hostnames | No |
| L4-HONEY | Honeypot touches | Known-suspicious paths, priv-esc binary spawns | No |
| L4-BASE | Baseline drift | Compare profile metrics against shipped baselines | Yes |

## Enterprise Infrastructure (v0.5.0)

- **4-layer determinism guard stack** (Models → Guard → Diff → CI Gate)
- **6 output formats** (json, sarif, table, ml-context, github, cyclonedx)
- **Structured audit logging** with SHA-256 hash chaining (14 event types)
- **Policy versioning** with author, timestamp, diff, rollback, integrity verification
- **Data retention** with configurable TTL, secure deletion, storage quotas, compliance export
- **Health and readiness** checks (backend, audit chain, storage)
- **Daemon mode** with HTTP API (12 endpoints), token auth, RBAC, Prometheus metrics
- **gRPC transport** (optional) for high-throughput daemon mode — Scan, Health, GetPolicy, QueryAudit RPCs
- **mTLS transport security** with TLS 1.2+, strong ciphers, client cert verification
- **Rate limiting** with token-bucket per-actor limits and priority job queuing
- **Webhook notifications** with HMAC-SHA256 signing, severity filtering, retry with backoff
- **Baseline hardening** with HMAC signing, drift detection, update rate limiting
- **API versioning** with negotiation, deprecation notices, backward compatibility
- **SLO tracking** with 7 defined service-level objectives
- **Kubernetes deployment** with health probes, RBAC, Prometheus annotations
- **Helm chart** with configurable replicas, mTLS, rate limiting, SLOs, monitoring
- **Config file support** (.irondome.yml) with env overrides
- **Request ID tracing** with X-Request-ID header propagation
- **CORS support** with configurable origins, preflight handling
- **Graceful shutdown** with SIGTERM/SIGINT/SIGHUP signal handlers
- **Security response headers** (X-Content-Type-Options, X-Frame-Options, Cache-Control)
- **Workspace scanning** for monorepos
- **License enforcement** (personal/commercial tiers)
- **Sigstore-signed releases** with SLSA L3 provenance
- **JSON schemas** for all output formats
- **Security policy** (SECURITY.md) with vulnerability reporting
- **Threat model** documented (docs/security/threat-model.md)
- **Operational runbooks** (docs/runbooks/)
- **SOC 2 Type I readiness** assessment and evidence matrix (docs/compliance/)
- **Pre-commit hook** (.pre-commit-hooks.yaml)
- **Docker support** (Dockerfile)
- **Citation metadata** (CITATION.cff)

## Version History

- v0.5.0 — Enterprise hardening: request ID tracing, CORS, graceful shutdown, security headers, OpenAPI v0.5.0
- v0.4.0 — Enterprise governance: audit logging, policy versioning, data retention, daemon mode (HTTP API + token auth + RBAC), mTLS, rate limiting, webhooks, baseline hardening, API versioning, SLOs, K8s deployment, Helm chart, SOC 2 Type I readiness documentation, gRPC transport (optional), 332 tests
- v0.3.0 — Enterprise-grade infrastructure: SECURITY.md, CONTRIBUTING.md, SLSA.md, SCAAT.md, CITATION.cff, Dockerfile, .pre-commit-hooks.yaml, MANIFEST.in, mypy.ini, .editorconfig, .gitattributes, enterprise gap analysis, JSON schemas, CI scripts, release pipeline with Sigstore + SLSA L3, expanded pyproject.toml, 295 tests, 6 output formats, 4-layer guard stack
- v0.2.0 — Real seccomp backend (libseccomp ctypes + fork/exec), real seatbelt backend (sandbox-exec), 33 tests
- v0.1.0 — Initial release: L3 sandbox, L4 behavioral analysis, CLI, formatters, 28 tests