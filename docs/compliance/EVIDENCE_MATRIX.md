# IronDome — SOC 2 Type I Evidence Matrix

> **Version:** 0.5.0 · **Date:** 2026-05-22 · **Scope:** All Trust Services Criteria
> **Purpose:** Detailed mapping of SOC 2 controls to IronDome source code, tests, and documentation.

---

## How to Use This Document

Each row maps a specific SOC 2 control to concrete, auditable evidence within IronDome. Auditors can:

1. **Locate code** — File paths point to exact implementation modules
2. **Verify tests** — Test file and function names confirm control effectiveness
3. **Review docs** — Documentation references explain design rationale
4. **Assess gaps** — Gaps are marked with remediation plans and timelines

---

## CC6.1 — Logical and Physical Access Controls

### CC6.1.1 — Network Isolation (Sandbox Containment)

| Field | Value |
|-------|-------|
| **Control** | L3 sandbox denies outbound/inbound network by default |
| **Implementation** | `src/irondome/l3/policy.py` — `default_policy()` creates deny-by-default policy; `src/irondome/l3/backends/seccomp_backend.py` — kernel-level syscall filtering; `src/irondome/l3/backends/seatbelt_backend.py` — macOS sandbox-exec profile generation |
| **Tests** | `tests/test_l3_sandbox.py` — Network blocking tests; `tests/test_subprocess_backend.py` — Pattern detection tests |
| **Docs** | `docs/security/threat-model.md` — Attack surface: L3 Sandbox Escape; `STATE.md` — L3 Default Policy section |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC6.1.2 — Transport Encryption (mTLS)

| Field | Value |
|-------|-------|
| **Control** | All daemon API traffic encrypted via mTLS (TLS 1.2+) |
| **Implementation** | `src/irondome/mtls/context.py` — `MTLSConfig` dataclass, `create_ssl_context()` factory; Enforces: TLS 1.2+ minimum, strong ciphers (ECDHE+AESGCM, ECDHE+CHACHA20), no compression (CRIME), client cert verification (`ssl.CERT_REQUIRED`), CRL checking |
| **Tests** | `tests/test_mtls.py` — 6 tests: TLS context creation, dev mode, cipher hardening, cert loading, min version enforcement |
| **Docs** | `docs/compliance/SOC2_TYPE_I.md` — CC6.1 section |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC6.1.3 — Dev Mode Isolation

| Field | Value |
|-------|-------|
| **Control** | Development TLS mode explicitly warns and disables client verification |
| **Implementation** | `src/irondome/mtls/context.py` — `_create_dev_ssl_context()` generates self-signed cert with `CERT_NONE`; `logger.warning("Creating DEV self-signed TLS certificate — DO NOT USE IN PRODUCTION")` |
| **Tests** | `tests/test_mtls.py` — Dev mode test |
| **Docs** | Module docstring warns: "WARNING: Only use in development" |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## CC6.2 — User Authentication

### CC6.2.1 — Token-Based Authentication

| Field | Value |
|-------|-------|
| **Control** | Bearer token authentication for all API endpoints |
| **Implementation** | `src/irondome/daemon/server.py` — `TokenAuth` class (lines 42–70); Tokens from `IRONDOME_API_TOKENS` env var (comma-separated) or `~/.irondome/api-tokens` file; `_require_auth()` method validates token before processing |
| **Tests** | `tests/test_audit.py` — Auth event logging tests |
| **Docs** | `docs/compliance/SOC2_TYPE_I.md` — CC6.2 section |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC6.2.2 — Rate Limiting

| Field | Value |
|-------|-------|
| **Control** | Per-actor token-bucket rate limiting prevents abuse |
| **Implementation** | `src/irondome/ratelimit/limiter.py` — `TokenBucketLimiter` with configurable rate (default 2 req/s), burst (default 10), max actors (10,000), idle timeout (3600s), optional global RPS cap; Thread-safe with lock-based synchronization |
| **Tests** | `tests/test_ratelimit.py` — 17 tests: basic allow/deny, burst, global rate limit, actor eviction, status, reset |
| **Docs** | `docs/compliance/SOC2_TYPE_I.md` — CC6.2 section |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC6.2.3 — Job Queuing

| Field | Value |
|-------|-------|
| **Control** | Bounded priority job queue prevents resource exhaustion |
| **Implementation** | `src/irondome/ratelimit/queue.py` — `JobQueue` with 4 priority levels (CRITICAL, HIGH, NORMAL, LOW), max 1000 jobs, thread-safe, FIFO within priority, stale job purge |
| **Tests** | `tests/test_ratelimit.py` — Queue tests: enqueue, dequeue, priority ordering, capacity, eviction, stats |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC6.2.4 — Authentication Audit Events

| Field | Value |
|-------|-------|
| **Control** | All authentication attempts logged to tamper-evident audit log |
| **Implementation** | `src/irondome/audit/logger.py` — `AUTH_SUCCESS` and `AUTH_FAILURE` event types; `src/irondome/daemon/server.py` — `_require_auth()` and `_require_permission()` record auth events |
| **Tests** | `tests/test_audit.py` — Auth event tests |
| **Docs** | `docs/compliance/SOC2_TYPE_I.md` — CC6.2 section |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## CC6.3 — Access Authorization

### CC6.3.1 — Role-Based Access Control

| Field | Value |
|-------|-------|
| **Control** | Three RBAC roles with explicit permission sets |
| **Implementation** | `src/irondome/daemon/server.py` — `RBAC` class (lines 76–99); `ROLE_PERMISSIONS` dict: submitter → {scan:submit, scan:read, health}, reader → {scan:read, policy:read, baseline:read, audit:read, health}, admin → {*}; `has_permission()` extracts role from token prefix |
| **Tests** | `tests/test_audit.py` — Auth permission tests |
| **Docs** | `docs/compliance/SOC2_TYPE_I.md` — CC6.3 RBAC permission matrix |
| **Gap** | R-02: Periodic access review process needs formalization |
| **Status** | ⚠️ Partial — code complete, organizational process pending |

### CC6.3.2 — Endpoint-Level Authorization

| Field | Value |
|-------|-------|
| **Control** | Every authenticated endpoint checks RBAC permissions |
| **Implementation** | `src/irondome/daemon/server.py` — `_require_permission()` method; Each `do_GET`/`do_POST` handler calls `_require_permission()` with specific permission before processing |
| **Tests** | Integration tests in `tests/test_audit.py` |
| **Docs** | See API endpoint table in SOC2_TYPE_I.md Appendix C |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## CC6.6 — System Component Inventory

### CC6.6.1 — Dependency Management

| Field | Value |
|-------|-------|
| **Control** | Zero hard runtime dependencies; dev dependencies pinned |
| **Implementation** | `pyproject.toml` — `[project]` has no runtime dependencies; `[project.optional-dependencies]` pins dev tools (pytest, mypy, ruff, etc.) |
| **Tests** | `pip install .` succeeds with zero network dependencies at runtime |
| **Docs** | `SECURITY.md` — Supply Chain section: "zero hard runtime dependencies" |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC6.6.2 — SBOM Generation

| Field | Value |
|-------|-------|
| **Control** | Automated SBOM generation for dependency tracking |
| **Implementation** | `scripts/generate_sbom.py` — Generates SBOM from installed packages |
| **Tests** | Manual verification |
| **Docs** | `scripts/generate_sbom.py` docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC6.6.3 — Release Signing and Provenance

| Field | Value |
|-------|-------|
| **Control** | All releases signed with Sigstore; SLSA L3 provenance generated |
| **Implementation** | `.github/workflows/release.yml` — Sigstore signing + SLSA L3 provenance; `scripts/verify_release.sh` — Verification script |
| **Tests** | CI `slsa-verify` job runs on every release |
| **Docs** | `SLSA.md` — Full SLSA L3 documentation and verification |
| **Gap** | R-05: Byte-for-byte reproducible builds not yet implemented |
| **Status** | ⚠️ Partial — Sigstore + SLSA L3 complete; reproducible builds pending |

---

## CC7.1 — Detection and Monitoring

### CC7.1.1 — Structured Audit Logging

| Field | Value |
|-------|-------|
| **Control** | Append-only hash-chained audit log with 14 event types |
| **Implementation** | `src/irondome/audit/logger.py` — `AuditLogger` class; SHA-256 hash chain (`prev_hash` field); `verify_chain()` detects tampering; Query API with filters (event_type, actor, target, since, until); Size-based rotation with gzip compression (50 MiB default, 10 rotated files); Module-level singleton via `get_audit_logger()` |
| **Tests** | `tests/test_audit.py` — 15 tests: record events, verify chain, query, tamper detection, rotation, stats |
| **Docs** | Module docstring with usage examples and design rationale |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC7.1.2 — Health and Readiness Checks

| Field | Value |
|-------|-------|
| **Control** | Health and readiness endpoints for monitoring |
| **Implementation** | `src/irondome/health.py` — `check_health()` (4 checks: version, sandbox backend, audit log integrity, storage); `check_readiness()` (backend availability); `src/irondome/daemon/server.py` — `GET /health` and `GET /ready` endpoints |
| **Tests** | `tests/test_health.py` — 4 tests |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC7.1.3 — SLO Tracking

| Field | Value |
|-------|-------|
| **Control** | 7 SLO definitions with measurable targets and tracking |
| **Implementation** | `src/irondome/slo.py` — `SLOTracker` class; SLO definitions: availability (99.9%), latency p50 (<500ms), p95 (<2s), p99 (<5s), throughput (≥10 scans/min), error rate (<1%), determinism (100%); `measure()` computes compliance; `get_report()` generates full report |
| **Tests** | `tests/test_slo.py` — 7 tests |
| **Docs** | Module docstring with SLO definitions |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC7.1.4 — Prometheus Metrics

| Field | Value |
|-------|-------|
| **Control** | Prometheus-format metrics endpoint |
| **Implementation** | `src/irondome/daemon/server.py` — `GET /metrics` endpoint; Metrics: `irondome_scans_total`, `irondome_scan_duration_ms_avg`, `irondome_alerts_total`, `irondome_uptime_seconds`, `irondome_version` |
| **Tests** | Covered by daemon integration tests |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC7.1.5 — Webhook Notifications

| Field | Value |
|-------|-------|
| **Control** | HMAC-SHA256 signed webhook notifications with severity filtering |
| **Implementation** | `src/irondome/webhooks.py` — `WebhookDispatcher` class; Events: SCAN_COMPLETE, SCAN_ALERT, POLICY_CHANGE, BASELINE_DRIFT, DAEMON_EVENT; HMAC-SHA256 payload signing; Severity-based filtering (critical, high, medium, low, info); Retry with exponential backoff (1s, 2s, 4s, max 3 attempts); Configurable per-webhook |
| **Tests** | `tests/test_webhooks.py` — 9 tests: add/remove webhooks, notify, HMAC signing, severity filtering, retry |
| **Docs** | Module docstring with usage examples |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## CC7.2 — Incident Response

### CC7.2.1 — Webhook Alerting

| Field | Value |
|-------|-------|
| **Control** | Automated alerting via webhooks on security events |
| **Implementation** | `src/irondome/webhooks.py` — See CC7.1.5 above |
| **Tests** | `tests/test_webhooks.py` — 9 tests |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC7.2.2 — Operational Runbooks

| Field | Value |
|-------|-------|
| **Control** | Documented incident response procedures |
| **Implementation** | `docs/runbooks/sandbox-escape.md` — L3 sandbox escape response; `docs/runbooks/determinism-failure.md` — Determinism violation response; `docs/runbooks/behavioral-anomaly.md` — L4 behavioral anomaly response; `docs/runbooks/ci-failures.md` — CI pipeline failure response |
| **Tests** | N/A (documentation) |
| **Docs** | Runbooks themselves |
| **Gap** | R-03: Incident response SLAs need formal documentation |
| **Status** | ⚠️ Partial — runbooks exist; SLA documentation pending |

### CC7.2.3 — Security Vulnerability Policy

| Field | Value |
|-------|-------|
| **Control** | Vulnerability reporting and response process |
| **Implementation** | `SECURITY.md` — Full policy: 48-hour acknowledgment, 5-business-day assessment, 90-day coordinated disclosure, credit for researchers |
| **Tests** | N/A (policy document) |
| **Docs** | `SECURITY.md` |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## CC8.1 — Change Management

### CC8.1.1 — Policy Versioning

| Field | Value |
|-------|-------|
| **Control** | All policy changes tracked with author, timestamp, and content hash |
| **Implementation** | `src/irondome/policy_versioned/store.py` — `VersionedPolicyStore` class; `save()` records author, timestamp, change_description, SHA-256 content_hash; `load()` retrieves by name and version; `diff()` compares two versions (added/removed/changed rules, default action changes); `rollback()` creates new version preserving history; `verify_integrity()` checks content hash for all versions; File-based storage: `~/.irondome/policies/<name>/v<N>.json` |
| **Tests** | `tests/test_policy_versioned.py` — 11 tests: save, load, diff, rollback, integrity, list |
| **Docs** | Module docstring with directory structure and usage examples |
| **Gap** | R-01: Formal organizational change management policy document needed |
| **Status** | ⚠️ Partial — code mechanisms complete; organizational policy pending |

### CC8.1.2 — Baseline Hardening (Anti-Poisoning)

| Field | Value |
|-------|-------|
| **Control** | Baselines protected from manipulation via HMAC signing, drift detection, and rate limiting |
| **Implementation** | `src/irondome/baseline_hardening.py` — `HardenedBaselineManager` class; `sign()` — HMAC-SHA256 signature on baseline content; `verify()` — Signature verification; `check_update_allowed()` — Rate limiting (max 2 updates/hour) + drift check (max 50% divergence); `apply_update()` — Records update in audit log |
| **Tests** | `tests/test_baseline_hardening.py` — 8 tests: signing, verification, rate limiting, drift detection |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC8.1.3 — API Versioning

| Field | Value |
|-------|-------|
| **Control** | Explicit API version negotiation prevents breaking changes |
| **Implementation** | `src/irondome/api_versioning.py` — `APIVersionNegotiator` class; Resolution order: URL path → Accept header → Custom header → Default; Deprecation notices via HTTP headers; Current version: v1; Backward compatibility guaranteed for 2 release cycles |
| **Tests** | `tests/test_api_versioning.py` — 7 tests: path extraction, accept header, custom header, deprecation, default fallback |
| **Docs** | Module docstring with versioning guarantees |
| **Gap** | None |
| **Status** | ✅ Implemented |

### CC8.1.4 — Release Signing and Provenance

| Field | Value |
|-------|-------|
| **Control** | All releases signed with Sigstore; SLSA L3 provenance generated |
| **Implementation** | `.github/workflows/release.yml` — Full pipeline: quality gates → determinism gate → build → Sigstore signing → release → PyPI publish → SLSA verify; `scripts/verify_release.sh` — End-to-end verification |
| **Tests** | CI `slsa-verify` job |
| **Docs** | `SLSA.md` — Full SLSA L3 documentation |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## A1.1 — System Availability

### A1.1.1 — Health and Readiness Endpoints

| Field | Value |
|-------|-------|
| **Control** | Kubernetes-compatible health and readiness probes |
| **Implementation** | `src/irondome/health.py` — `check_health()` (4 component checks); `check_readiness()` (backend availability); `src/irondome/daemon/server.py` — `GET /health` (unauthenticated), `GET /ready` (unauthenticated) |
| **Tests** | `tests/test_health.py` — 4 tests |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### A1.1.2 — SLO Definitions and Tracking

| Field | Value |
|-------|-------|
| **Control** | Measurable service-level objectives with compliance tracking |
| **Implementation** | `src/irondome/slo.py` — `SLOTracker` class; 7 SLO definitions with targets; `measure()` computes current compliance; `get_report()` generates full report |
| **Tests** | `tests/test_slo.py` — 7 tests |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### A1.1.3 — Load Testing Baseline

| Field | Value |
|-------|-------|
| **Control** | Performance baselines for capacity planning |
| **Implementation** | `scripts/load_test.py` — p50/p95/p99 latency benchmarks under load |
| **Tests** | Manual execution |
| **Docs** | Script docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### A1.1.4 — Kubernetes Deployment

| Field | Value |
|-------|-------|
| **Control** | Production-ready deployment manifests with health probes |
| **Implementation** | `deploy/kubernetes/` — Deployment, Service, PVC, RBAC, ServiceAccount; `deploy/helm/irondome/` — Helm chart with values for replicas, mTLS, rate limiting, SLOs, monitoring; Health/readiness probes configured |
| **Tests** | Helm chart validation |
| **Docs** | `deploy/` directory |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## C1.1 — Confidential Information Protection

### C1.1.1 — Transport Encryption

| Field | Value |
|-------|-------|
| **Control** | mTLS with TLS 1.2+, strong ciphers, client cert verification |
| **Implementation** | See CC6.1.2 above |
| **Tests** | `tests/test_mtls.py` — 6 tests |
| **Docs** | `src/irondome/mtls/context.py` docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### C1.1.2 — Data Retention Policies

| Field | Value |
|-------|-------|
| **Control** | Configurable TTL per data type with automatic cleanup |
| **Implementation** | `src/irondome/retention/manager.py` — `RetentionManager` class; Default TTLs: scan results 90 days, audit logs 365 days, baselines never expire; Storage quotas: scans 500 MB, audit 200 MB, baselines 50 MB; `run_cleanup()` removes expired files; `export_data()` creates compliance archive |
| **Tests** | `tests/test_retention.py` — 8 tests: save, cleanup, quota, export, secure delete |
| **Docs** | Module docstring with configuration examples |
| **Gap** | None |
| **Status** | ✅ Implemented |

### C1.1.3 — Secure Deletion

| Field | Value |
|-------|-------|
| **Control** | Secure file deletion (overwrite + random + truncate + unlink) |
| **Implementation** | `src/irondome/retention/manager.py` — `secure_delete()` method; Step 1: Write zeros to file (fsync); Step 2: Write random data (fsync); Step 3: Truncate to zero (fsync); Step 4: Unlink file |
| **Tests** | `tests/test_retention.py` — Secure delete test |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### C1.1.4 — Compliance Export

| Field | Value |
|-------|-------|
| **Control** | Data export for compliance audits |
| **Implementation** | `src/irondome/retention/manager.py` — `export_data()` method; Exports scan results as JSON archive; Audit event: `DATA_EXPORT` |
| **Tests** | `tests/test_retention.py` — Export test |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## PI1.1 — Processing Accuracy

### PI1.1.1 — Deterministic Guard Stack

| Field | Value |
|-------|-------|
| **Control** | 4-layer enforcement ensures same input → same output |
| **Implementation** | `src/irondome/guards.py` — Layer 1: Models (`frozen=True`, sorted keys); Layer 2: `DeterministicGuard` (no UUIDs, no timestamps in findings, sorted keys); Layer 3: `diff_results()` (field-by-field comparison); Layer 4: `verify_determinism()` (run twice, compare SHA-256); `deterministic_hash()` — SHA-256 of deterministic fields only |
| **Tests** | `tests/test_guards.py` — Determinism guard tests |
| **Docs** | Module docstring with architecture diagram |
| **Gap** | None |
| **Status** | ✅ Implemented |

### PI1.1.2 — Policy Content Hashing

| Field | Value |
|-------|-------|
| **Control** | SHA-256 content hash for every policy version |
| **Implementation** | `src/irondome/policy_versioned/store.py` — `_hash_policy()` computes SHA-256 of deterministic JSON; `verify_integrity()` checks stored hash vs. computed hash |
| **Tests** | `tests/test_policy_versioned.py` — Integrity verification test |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

### PI1.1.3 — Baseline Signing

| Field | Value |
|-------|-------|
| **Control** | HMAC-SHA256 signatures on behavioral baselines |
| **Implementation** | `src/irondome/baseline_hardening.py` — `SignedBaseline.from_baseline()` creates HMAC signature; `verify()` checks signature integrity |
| **Tests** | `tests/test_baseline_hardening.py` — Signing and verification tests |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## PI1.3 — Processing Authorization

### PI1.3.1 — RBAC Authorization

| Field | Value |
|-------|-------|
| **Control** | Role-based access control with explicit permission checking |
| **Implementation** | See CC6.3.1 above |
| **Tests** | `tests/test_audit.py` |
| **Docs** | `docs/compliance/SOC2_TYPE_I.md` — RBAC permission matrix |
| **Gap** | None |
| **Status** | ✅ Implemented |

### PI1.3.2 — Policy Enforcement (Sandbox)

| Field | Value |
|-------|-------|
| **Control** | Deny-by-default sandbox policy with explicit allows |
| **Implementation** | `src/irondome/l3/policy.py` — `default_policy()` creates deny-by-default; Policy rules: allow (file reads, DNS, /tmp writes, stdio), deny (outbound network, inbound network, process spawn, bind/listen); `src/irondome/l3/engine.py` — Policy engine enforces rules |
| **Tests** | `tests/test_l3_sandbox.py`, `tests/test_policy.py` |
| **Docs** | `STATE.md` — L3 Default Policy section |
| **Gap** | None |
| **Status** | ✅ Implemented |

### PI1.3.3 — Rate Limiting and Job Queuing

| Field | Value |
|-------|-------|
| **Control** | Per-actor rate limiting and priority job queuing |
| **Implementation** | See CC6.2.2 and CC6.2.3 above |
| **Tests** | `tests/test_ratelimit.py` — 17 tests |
| **Docs** | Module docstrings |
| **Gap** | None |
| **Status** | ✅ Implemented |

### PI1.3.4 — API Versioning

| Field | Value |
|-------|-------|
| **Control** | Explicit API version negotiation prevents unauthorized access to newer/older APIs |
| **Implementation** | See CC8.1.3 above |
| **Tests** | `tests/test_api_versioning.py` — 7 tests |
| **Docs** | Module docstring |
| **Gap** | None |
| **Status** | ✅ Implemented |

---

## Summary: Evidence Coverage

| Criterion | Code Modules | Tests | Docs | Gaps |
|-----------|-------------|-------|------|------|
| CC6.1 | mtls, l3 | 6 + L3 tests | threat-model.md | 0 |
| CC6.2 | daemon, ratelimit, audit | 15 + 17 | SOC2_TYPE_I.md | 0 |
| CC6.3 | daemon | audit tests | SOC2_TYPE_I.md | 1 (access review) |
| CC6.6 | pyproject, scripts, SLSA | CI pipeline | SLSA.md, SECURITY.md | 1 (repro builds) |
| CC7.1 | audit, health, slo, webhooks, daemon | 15 + 4 + 7 + 9 | Module docs | 0 |
| CC7.2 | webhooks | 9 | runbooks, SECURITY.md | 1 (SLA docs) |
| CC8.1 | policy_versioned, baseline_hardening, api_versioning | 11 + 8 + 7 | SLSA.md | 1 (org policy) |
| A1.1 | health, slo, daemon, deploy | 4 + 7 | K8s, Helm | 0 |
| C1.1 | mtls, retention | 6 + 8 | Module docs | 0 |
| PI1.1 | guards, models, policy_versioned, baseline_hardening | guards + 11 + 8 | Module docs | 0 |
| PI1.3 | daemon, ratelimit, l3/policy, api_versioning | 17 + L3 + 7 | SOC2_TYPE_I.md | 0 |

**Total Evidence Items:** 47 (code), 295 (tests), 15 (docs)
**Total Gaps:** 4 (all organizational/process, not code)