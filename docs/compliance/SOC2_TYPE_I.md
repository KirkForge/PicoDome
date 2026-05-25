# IronDome — SOC 2 Type I Readiness Assessment

> **Version:** 0.5.0 · **Date:** 2026-05-22 · **Status:** Assessment Draft
> **Scope:** IronDome L3/L4 runtime sandbox and behavioral analysis platform
> **Trust Services Categories:** Security, Availability, Confidentiality, Processing Integrity

---

## 1. Executive Summary

IronDome is a deterministic runtime sandbox and behavioral analysis tool that provides supply-chain security through kernel-level containment (L3) and behavioral profiling (L4). This document assesses IronDome's readiness for a SOC 2 Type I audit against the AICPA Trust Services Criteria (TSC).

**Overall Assessment:** **Conditionally Ready** — IronDome has implemented the majority of controls required for SOC 2 Type I. The core infrastructure (audit logging, policy versioning, data retention, mTLS, RBAC, rate limiting, SLO tracking, webhooks, baseline hardening, API versioning) is in place and tested. Remaining gaps are primarily documentation and process controls that require organizational (not code) changes.

| Category | Criteria Mapped | Implemented | Partial | Gap |
|----------|----------------|-------------|---------|-----|
| Security (CC6–CC8) | 7 | 5 | 2 | 0 |
| Availability (A1) | 1 | 1 | 0 | 0 |
| Confidentiality (C1) | 1 | 1 | 0 | 0 |
| Processing Integrity (PI1) | 2 | 2 | 0 | 0 |
| **Total** | **11** | **9** | **2** | **0** |

**Key Strengths:**
- Hash-chained, append-only audit log with integrity verification
- mTLS transport security with TLS 1.2+ enforcement
- Token-based authentication with RBAC (submitter, reader, admin)
- Deterministic guard stack ensuring processing integrity
- Policy versioning with content hashing, diff, and rollback
- Data retention with secure deletion and compliance export
- SLO tracking with 7 defined service-level objectives

**Remaining Work:**
- Formalize change management policy documentation
- Complete incident response runbooks for SOC 2-specific scenarios
- Establish periodic access review process (organizational control)

---

## 2. Trust Services Criteria Mapping

### 2.1 Security (Common Criteria)

#### CC6.1 — Logical and Physical Access Controls

**Criterion:** The entity implements logical access security software, infrastructure, and architectures over protected information assets to meet access objectives.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Network isolation | L3 sandbox denies outbound/inbound network by default (seccomp-bpf, seatbelt) | ✅ Implemented |
| Transport encryption | mTLS with TLS 1.2+ minimum, strong cipher suites (ECDHE+AESGCM, ECDHE+CHACHA20) | ✅ Implemented |
| TLS hardening | No SSLv3/TLS 1.0/1.1, compression disabled (CRIME attack mitigation), OCSP/CRL checking | ✅ Implemented |
| Certificate verification | `ssl.CERT_REQUIRED` for client certs, CA bundle verification | ✅ Implemented |
| Dev mode isolation | Self-signed dev certs explicitly warn, `CERT_NONE` only in `IRONDOME_TLS_DEV=1` | ✅ Implemented |
| Sandbox containment | seccomp-bpf (Linux kernel enforcement), seatbelt (macOS), subprocess fallback | ✅ Implemented |

**Evidence:**
- `src/irondome/mtls/context.py` — mTLS configuration, SSL context factory, cipher hardening
- `src/irondome/l3/engine.py` — Sandbox engine with backend auto-detection
- `src/irondome/l3/backends/seccomp_backend.py` — Kernel-level syscall filtering
- `src/irondome/l3/backends/seatbelt_backend.py` — macOS sandbox-exec enforcement
- `tests/test_mtls.py` — 6 tests covering TLS configuration, dev mode, cipher suites
- `tests/test_l3_sandbox.py` — Sandbox isolation tests

---

#### CC6.2 — User Authentication

**Criterion:** The entity authenticates users and system components to protected information assets.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Token-based auth | Bearer token via `Authorization` header; tokens from env vars or file | ✅ Implemented |
| Token validation | `TokenAuth.validate()` checks against configured token set | ✅ Implemented |
| Dev mode | No tokens configured = open access (dev only, documented) | ✅ Implemented |
| Audit trail | Every auth success/failure logged to hash-chained audit log | ✅ Implemented |
| Rate limiting | Token-bucket per-actor rate limiting with configurable burst and rate | ✅ Implemented |

**Evidence:**
- `src/irondome/daemon/server.py` — `TokenAuth` class (lines 42–70)
- `src/irondome/ratelimit/limiter.py` — `TokenBucketLimiter` with per-actor and global limits
- `src/irondome/ratelimit/queue.py` — `JobQueue` with priority levels and bounded capacity
- `src/irondome/audit/logger.py` — `AUTH_SUCCESS` and `AUTH_FAILURE` event types
- `tests/test_ratelimit.py` — 17 tests for rate limiting and queuing

---

#### CC6.3 — Access Authorization

**Criterion:** The entity authorizes and modifies access to protected information assets based on business need and least privilege.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Role definitions | Three roles: `submitter` (scan:submit, scan:read, health), `reader` (read-only), `admin` (all) | ✅ Implemented |
| Permission checks | Every endpoint validates permissions before processing | ✅ Implemented |
| Role extraction | Roles extracted from token prefix (`irondome-<role>-<hash>`) | ✅ Implemented |
| Endpoint-level auth | Unauthenticated: `/health`, `/ready`; Authenticated: all `/api/v1/*` endpoints | ✅ Implemented |

**RBAC Permission Matrix:**

| Permission | Submitter | Reader | Admin |
|-----------|-----------|--------|-------|
| `scan:submit` | ✅ | ❌ | ✅ |
| `scan:read` | ✅ | ✅ | ✅ |
| `policy:read` | ❌ | ✅ | ✅ |
| `policy:write` | ❌ | ❌ | ✅ |
| `baseline:read` | ❌ | ✅ | ✅ |
| `audit:read` | ❌ | ✅ | ✅ |
| `health` | ✅ | ✅ | ✅ |
| `*` (wildcard) | ❌ | ❌ | ✅ |

**Evidence:**
- `src/irondome/daemon/server.py` — `RBAC` class (lines 76–99), `_require_auth()` and `_require_permission()` methods
- `tests/test_audit.py` — Auth event logging tests

---

#### CC6.6 — System Component Inventory

**Criterion:** The entity manages and tracks system components and their configurations to maintain accurate inventory.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Dependency pinning | Zero hard runtime dependencies; dev deps pinned in `pyproject.toml` | ✅ Implemented |
| SBOM generation | `scripts/generate_sbom.py` generates SBOM from installed packages | ✅ Implemented |
| Sigstore signing | All releases signed with Sigstore OIDC identity | ✅ Implemented |
| SLSA L3 provenance | Build provenance generated and verified on every release | ✅ Implemented |
| Release integrity | `scripts/verify_release.sh` verifies Sigstore signatures | ✅ Implemented |
| Reproducible builds | Deterministic guard stack ensures identical output on identical inputs | ⚠️ Partial — Python wheel builds not yet byte-for-byte reproducible |

**Evidence:**
- `pyproject.toml` — Dependency declarations with version pins
- `scripts/generate_sbom.py` — SBOM generator
- `scripts/verify_release.sh` — Release verification
- `SLSA.md` — SLSA L3 provenance documentation
- `SCAAT.md` — Supply chain attack technique mapping
- `src/irondome/guards.py` — 4-layer determinism enforcement

---

#### CC7.1 — Detection and Monitoring

**Criterion:** The entity detects and monitors events that may pose a security or availability risk.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Audit logging | Hash-chained append-only JSON-lines log with 14 event types | ✅ Implemented |
| Log integrity | SHA-256 hash chain; `verify_chain()` detects tampering | ✅ Implemented |
| Log rotation | Size-based rotation with gzip compression (50 MiB default, 10 rotated files) | ✅ Implemented |
| Health checks | `/health` and `/ready` endpoints checking backend, audit chain, storage | ✅ Implemented |
| SLO tracking | 7 SLO definitions: availability, latency (p50/p95/p99), throughput, error rate, determinism | ✅ Implemented |
| Prometheus metrics | `/metrics` endpoint with scan count, latency, alerts, uptime gauges | ✅ Implemented |
| Webhook alerts | HMAC-SHA256 signed notifications with severity filtering and retry | ✅ Implemented |

**Audit Event Types:**
- `SCAN_START`, `SCAN_COMPLETE`, `SCAN_ALERT`
- `POLICY_CREATE`, `POLICY_UPDATE`, `POLICY_ROLLBACK`, `POLICY_DELETE`
- `BASELINE_CREATE`, `BASELINE_UPDATE`, `BASELINE_DELETE`
- `DAEMON_START`, `DAEMON_STOP`
- `AUTH_SUCCESS`, `AUTH_FAILURE`
- `DATA_RETENTION_CLEANUP`, `DATA_EXPORT`, `DATA_DELETE`

**SLO Definitions:**

| SLO | Target | Measurement |
|-----|--------|-------------|
| Availability | 99.9% | Health checks passed / total |
| Latency p50 | <500ms | 50th percentile scan duration |
| Latency p95 | <2s | 95th percentile scan duration |
| Latency p99 | <5s | 99th percentile scan duration |
| Throughput | ≥10 scans/min | Sustained scan rate |
| Error rate | <1% | Failed scans / total |
| Determinism | 100% | Identical input → identical output |

**Evidence:**
- `src/irondome/audit/logger.py` — 14 event types, hash chain, rotation, query API
- `src/irondome/health.py` — Health/readiness checks
- `src/irondome/slo.py` — 7 SLO definitions + `SLOTracker`
- `src/irondome/webhooks.py` — Webhook dispatcher with HMAC signing
- `src/irondome/daemon/server.py` — `/health`, `/ready`, `/metrics` endpoints
- `tests/test_audit.py` — 15 tests
- `tests/test_health.py` — 4 tests
- `tests/test_slo.py` — 7 tests
- `tests/test_webhooks.py` — 9 tests

---

#### CC7.2 — Incident Response

**Criterion:** The entity responds to identified security incidents in a timely manner.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Webhook alerting | `WebhookDispatcher` with configurable severity thresholds | ✅ Implemented |
| Event types | `SCAN_ALERT`, `BASELINE_DRIFT`, `POLICY_CHANGE`, `DAEMON_EVENT` | ✅ Implemented |
| HMAC verification | Webhook payloads signed with HMAC-SHA256 for authenticity | ✅ Implemented |
| Retry with backoff | 3 attempts, exponential backoff (1s, 2s, 4s) | ✅ Implemented |
| Runbooks | 4 operational runbooks covering failure scenarios | ✅ Implemented |
| Security policy | `SECURITY.md` with vulnerability reporting and response timeline | ✅ Implemented |

**Runbooks:**
- `docs/runbooks/sandbox-escape.md` — L3 sandbox escape response
- `docs/runbooks/determinism-failure.md` — Determinism violation response
- `docs/runbooks/behavioral-anomaly.md` — L4 behavioral anomaly response
- `docs/runbooks/ci-failures.md` — CI pipeline failure response

**Evidence:**
- `src/irondome/webhooks.py` — Full webhook dispatch system
- `SECURITY.md` — Vulnerability reporting policy, response timeline, disclosure policy
- `docs/runbooks/` — 4 operational runbooks
- `tests/test_webhooks.py` — 9 tests

---

#### CC8.1 — Change Management

**Criterion:** The entity manages changes to infrastructure and software to maintain consistent, secure operations.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Policy versioning | Full version history with author, timestamp, change description | ✅ Implemented |
| Policy diff | `VersionedPolicyStore.diff()` compares two policy versions | ✅ Implemented |
| Policy rollback | `VersionedPolicyStore.rollback()` creates new version (audit trail preserved) | ✅ Implemented |
| Content hashing | SHA-256 hash of policy content stored with each version | ✅ Implemented |
| Integrity verification | `VersionedPolicyStore.verify_integrity()` detects tampering | ✅ Implemented |
| Baseline hardening | HMAC-SHA256 baseline signing, drift detection, rate-limited updates | ✅ Implemented |
| API versioning | Explicit version negotiation with deprecation notices | ✅ Implemented |
| Audit trail | All policy mutations logged: create, update, rollback, delete | ✅ Implemented |
| Release signing | Sigstore-signed releases with SLSA L3 provenance | ✅ Implemented |
| Formal change management policy | Documented process for production changes | ⚠️ Partial — code mechanisms exist; organizational policy needs formalization |

**Policy Versioning Workflow:**
```
1. Author creates/updates policy → VersionedPolicyStore.save()
   - Records: author, timestamp, change_description, content_hash
   - Audit event: POLICY_CREATE or POLICY_UPDATE

2. Review via diff → VersionedPolicyStore.diff(v1, v2)
   - Shows: added_rules, removed_rules, changed_rules, default_action_changed

3. Rollback if needed → VersionedPolicyStore.rollback(name, version, author)
   - Creates new version (not overwriting history)
   - Audit event: POLICY_ROLLBACK

4. Integrity verification → VersionedPolicyStore.verify_integrity(name)
   - Checks SHA-256 content hash for each version
   - Returns list of violations (empty = intact)
```

**Evidence:**
- `src/irondome/policy_versioned/store.py` — Full versioned policy store
- `src/irondome/baseline_hardening.py` — Baseline signing, drift detection, rate limiting
- `src/irondome/api_versioning.py` — API version negotiation and deprecation
- `src/irondome/audit/logger.py` — Audit trail for all mutations
- `SLSA.md` — Release signing and provenance
- `tests/test_policy_versioned.py` — 11 tests
- `tests/test_baseline_hardening.py` — 8 tests
- `tests/test_api_versioning.py` — 7 tests

---

### 2.2 Availability (A1)

#### A1.1 — System Availability

**Criterion:** The entity maintains system availability to meet its objectives.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Health endpoint | `GET /health` — version, uptime, component status | ✅ Implemented |
| Readiness endpoint | `GET /ready` — backend availability check | ✅ Implemented |
| Prometheus metrics | `GET /metrics` — scan count, latency, alerts, uptime | ✅ Implemented |
| SLO tracking | 7 SLOs with measurable targets and rolling window compliance | ✅ Implemented |
| Load testing baseline | `scripts/load_test.py` with p50/p95/p99 benchmarks | ✅ Implemented |
| Kubernetes deployment | Health probes, readiness probes, Prometheus annotations | ✅ Implemented |
| Helm chart | Configurable replicas, resource limits, persistence | ✅ Implemented |

**Deployment Evidence:**
- `deploy/kubernetes/` — K8s Deployment, Service, PVC, RBAC, ServiceAccount
- `deploy/helm/irondome/` — Helm chart with values for replicas, mTLS, rate limiting, SLOs
- `src/irondome/health.py` — Health/readiness check implementation
- `src/irondome/slo.py` — SLO definitions and tracker
- `scripts/load_test.py` — Load testing baseline

**Evidence:**
- `src/irondome/health.py` — `check_health()`, `check_readiness()`
- `src/irondome/daemon/server.py` — `/health`, `/ready`, `/metrics` endpoints
- `src/irondome/slo.py` — `SLOTracker` with measurement and reporting
- `deploy/kubernetes/` — K8s manifests with health/readiness probes
- `deploy/helm/irondome/` — Helm chart

---

### 2.3 Confidentiality (C1)

#### C1.1 — Confidential Information Protection

**Criterion:** The entity protects confidential information during storage, processing, and transmission.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Transport encryption | mTLS with TLS 1.2+, strong ciphers only | ✅ Implemented |
| Data at rest | Scan results stored as JSON; retention policies govern lifecycle | ✅ Implemented |
| Secure deletion | `RetentionManager.secure_delete()` — overwrite + random + truncate + unlink | ✅ Implemented |
| Data retention | Configurable TTL: scan results 90 days, audit logs 365 days, baselines never expire | ✅ Implemented |
| Storage quotas | Configurable per-type storage quotas (default: scans 500 MB, audit 200 MB, baselines 50 MB) | ✅ Implemented |
| Compliance export | `RetentionManager.export_data()` — JSON archive for audit | ✅ Implemented |
| Audit trail for data ops | `DATA_RETENTION_CLEANUP`, `DATA_EXPORT`, `DATA_DELETE` events | ✅ Implemented |

**Data Retention Configuration:**

| Data Type | Default TTL | Secure Delete | Quota |
|-----------|-------------|---------------|-------|
| Scan results | 90 days | Yes (overwrite + random + truncate) | 500 MB |
| Audit logs | 365 days | No (append-only) | 200 MB |
| Baselines | Never (0) | No | 50 MB |

**Secure Deletion Process:**
```
1. Overwrite file with zeros (fsync)
2. Overwrite file with random data (fsync)
3. Truncate to zero bytes (fsync)
4. Unlink (delete) the file
```

**Evidence:**
- `src/irondome/mtls/context.py` — mTLS configuration and TLS hardening
- `src/irondome/retention/manager.py` — Retention policies, secure deletion, compliance export
- `src/irondome/audit/logger.py` — Data governance event types
- `tests/test_retention.py` — 8 tests
- `tests/test_mtls.py` — 6 tests

---

### 2.4 Processing Integrity (PI1)

#### PI1.1 — Processing Accuracy

**Criterion:** The entity processes information accurately to meet its objectives.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Deterministic guard stack | 4-layer enforcement: Models → Guard → Diff → CI Gate | ✅ Implemented |
| Deterministic hash | SHA-256 of deterministic fields only (excludes timing) | ✅ Implemented |
| Verify determinism | Run twice, compare SHA-256 hashes | ✅ Implemented |
| CI determinism gate | Automated in `scripts/ci.sh` | ✅ Implemented |
| Frozen dataclasses | All models use `frozen=True` — immutable after creation | ✅ Implemented |
| Sorted key output | `to_dict()` uses `sort_keys=True` for consistent JSON | ✅ Implemented |
| No random IDs | `run_id` is empty in deterministic mode, `finding_id` is rule-based | ✅ Implemented |
| No timestamps in findings | Guard rejects timestamps in finding messages/evidence | ✅ Implemented |
| Policy content hashing | SHA-256 hash per policy version for integrity verification | ✅ Implemented |
| Baseline signing | HMAC-SHA256 signatures on baselines | ✅ Implemented |

**Deterministic Guard Stack Architecture:**
```
┌─────────────────────────────────────────┐
│  Layer 4: CI Gate                       │
│  --verify-determinism (CLI)             │
│  Runs scan twice, asserts SHA-256 match │
├─────────────────────────────────────────┤
│  Layer 3: Diff                           │
│  irondome diff a.json b.json            │
│  Compare two saved scans field-by-field  │
├─────────────────────────────────────────┤
│  Layer 2: Guard (runtime)               │
│  Validates invariants after each scan:  │
│  - No UUIDs in findings                 │
│  - No timestamps in findings            │
│  - Findings sorted by sort_key()        │
│  - run_id is deterministic (empty)       │
├─────────────────────────────────────────┤
│  Layer 1: Models (structural)           │
│  Finding(frozen=True), sorted keys,     │
│  no random IDs, no prose in output      │
└─────────────────────────────────────────┘
```

**Evidence:**
- `src/irondome/guards.py` — 4-layer determinism enforcement
- `src/irondome/models.py` — Frozen dataclasses
- `src/irondome/policy_versioned/store.py` — Content hashing and integrity verification
- `src/irondome/baseline_hardening.py` — HMAC baseline signing
- `tests/test_guards.py` — Determinism guard tests
- `scripts/ci.sh` — CI pipeline with determinism gate

---

#### PI1.3 — Processing Authorization

**Criterion:** The entity authorizes processing of information to meet its objectives.

| Aspect | IronDome Implementation | Status |
|--------|------------------------|--------|
| Policy enforcement | L3 sandbox policy: deny-by-default with explicit allows | ✅ Implemented |
| RBAC permissions | Role-based access to scan submission, policy management, audit | ✅ Implemented |
| Rate limiting | Token-bucket per-actor limiting with global rate cap | ✅ Implemented |
| Job queuing | Priority job queue with bounded capacity and eviction | ✅ Implemented |
| API versioning | Explicit version negotiation prevents unauthorized API use | ✅ Implemented |
| Audit trail | All processing actions logged with actor identity | ✅ Implemented |

**Policy Enforcement Model:**
- Default policy (`iron-dome-default`): deny-by-default
- Explicit allows: file reads (system libs, Python packages, project files), DNS resolution, writes to /tmp and stdio
- Blocked: outbound network, inbound network, process spawning, network bind/listen
- Detected: 10 suspicious output patterns (eval, curl, chmod, base64, etc.)

**Evidence:**
- `src/irondome/daemon/server.py` — RBAC, token auth, rate limiting
- `src/irondome/ratelimit/limiter.py` — Per-actor rate limiting
- `src/irondome/ratelimit/queue.py` — Priority job queue
- `src/irondome/api_versioning.py` — API version negotiation
- `src/irondome/l3/policy.py` — Deny-by-default policy engine
- `tests/test_ratelimit.py` — 17 tests

---

## 3. Evidence Collection

### 3.1 Evidence Summary by Criterion

| Criterion | Evidence | Location |
|-----------|----------|----------|
| CC6.1 | mTLS implementation, sandbox isolation | `src/irondome/mtls/`, `src/irondome/l3/` |
| CC6.2 | Token auth, rate limiting, audit logging | `src/irondome/daemon/server.py`, `src/irondome/ratelimit/`, `src/irondome/audit/` |
| CC6.3 | RBAC role definitions, permission checks | `src/irondome/daemon/server.py` |
| CC6.6 | Dependency pinning, SBOM, Sigstore, SLSA | `pyproject.toml`, `scripts/generate_sbom.py`, `SLSA.md`, `scripts/verify_release.sh` |
| CC7.1 | Audit log, health checks, SLOs, webhooks, metrics | `src/irondome/audit/`, `src/irondome/health.py`, `src/irondome/slo.py`, `src/irondome/webhooks.py` |
| CC7.2 | Webhook alerts, runbooks, security policy | `src/irondome/webhooks.py`, `docs/runbooks/`, `SECURITY.md` |
| CC8.1 | Policy versioning, baseline hardening, API versioning | `src/irondome/policy_versioned/`, `src/irondome/baseline_hardening.py`, `src/irondome/api_versioning.py` |
| A1.1 | Health/readiness endpoints, SLOs, K8s deployment | `src/irondome/health.py`, `src/irondome/slo.py`, `deploy/` |
| C1.1 | mTLS, retention policies, secure deletion | `src/irondome/mtls/`, `src/irondome/retention/` |
| PI1.1 | Guard stack, deterministic hash, content hashing | `src/irondome/guards.py`, `src/irondome/models.py`, `src/irondome/policy_versioned/` |
| PI1.3 | RBAC, rate limiting, policy enforcement | `src/irondome/daemon/server.py`, `src/irondome/ratelimit/`, `src/irondome/l3/policy.py` |

### 3.2 Test Coverage

| Module | Tests | Status |
|--------|-------|--------|
| `audit` | 15 | ✅ All passing |
| `policy_versioned` | 11 | ✅ All passing |
| `retention` | 8 | ✅ All passing |
| `health` | 4 | ✅ All passing |
| `ratelimit` | 17 | ✅ All passing |
| `mtls` | 6 | ✅ All passing |
| `slo` | 7 | ✅ All passing |
| `webhooks` | 9 | ✅ All passing |
| `baseline_hardening` | 8 | ✅ All passing |
| `api_versioning` | 7 | ✅ All passing |
| Core (L3/L4/guards) | 203 | ✅ All passing |
| **Total** | **295** | **✅ 295/295 passing** |

### 3.3 Gaps and Remediation

| Gap | Criterion | Remediation Plan | Priority | Status |
|-----|-----------|-------------------|----------|--------|
| Formal change management policy document | CC8.1 | Write organizational policy for production changes | Medium | Planned |
| Periodic access review process | CC6.3 | Define quarterly review of token access and RBAC roles | Medium | Planned |
| Byte-for-byte reproducible builds | CC6.6 | Implement SOURCE_DATE_EPOCH, pinned dep hashes | Low | Planned |
| External audit notary integration | CC7.1 | Integrate Rekor/Sigstore transparency log | Medium | Planned (PR-16) |
| Incident response SLA documentation | CC7.2 | Define SLAs for incident response times | Low | Planned |

---

## 4. Control Matrix

| Control ID | Description | Implementation | Evidence | Status |
|-----------|-------------|----------------|----------|--------|
| CC6.1 | Logical and physical access controls | mTLS (TLS 1.2+), sandbox isolation (seccomp/seatbelt/subprocess), deny-by-default policy | `mtls/context.py`, `l3/backends/`, `l3/policy.py`, `tests/test_mtls.py`, `tests/test_l3_sandbox.py` | ✅ Implemented |
| CC6.2 | User authentication | Bearer token auth, token file/env configuration, dev mode isolation, auth audit events | `daemon/server.py` (TokenAuth), `ratelimit/limiter.py`, `audit/logger.py` (AUTH_SUCCESS/FAILURE), `tests/test_audit.py` | ✅ Implemented |
| CC6.3 | Access authorization | RBAC with 3 roles (submitter, reader, admin), permission-gated endpoints, role extraction from token | `daemon/server.py` (RBAC), `tests/test_audit.py` | ✅ Implemented |
| CC6.6 | System component inventory | Zero runtime deps, SBOM generation, Sigstore signing, SLSA L3 provenance, dependency pinning | `pyproject.toml`, `scripts/generate_sbom.py`, `SLSA.md`, `scripts/verify_release.sh` | ⚠️ Partial — reproducible builds pending |
| CC7.1 | Detection and monitoring | Hash-chained audit log (14 event types), health/readiness endpoints, 7 SLOs, Prometheus metrics, webhook notifications | `audit/logger.py`, `health.py`, `slo.py`, `webhooks.py`, `daemon/server.py`, `tests/test_audit.py`, `tests/test_health.py`, `tests/test_slo.py`, `tests/test_webhooks.py` | ✅ Implemented |
| CC7.2 | Incident response | Webhook alerts (HMAC-signed, retry, severity filtering), 4 runbooks, SECURITY.md vulnerability policy | `webhooks.py`, `docs/runbooks/`, `SECURITY.md`, `tests/test_webhooks.py` | ✅ Implemented |
| CC8.1 | Change management | Policy versioning (author/timestamp/diff/rollback), content hashing, baseline signing, API versioning, audit trail, SLSA provenance | `policy_versioned/store.py`, `baseline_hardening.py`, `api_versioning.py`, `audit/logger.py`, `SLSA.md`, `tests/test_policy_versioned.py`, `tests/test_baseline_hardening.py` | ⚠️ Partial — organizational policy pending |
| A1.1 | System availability | Health/readiness probes, Prometheus metrics, SLO tracking, K8s deployment with probes, Helm chart, load testing | `health.py`, `slo.py`, `daemon/server.py`, `deploy/`, `scripts/load_test.py` | ✅ Implemented |
| C1.1 | Confidential information protection | mTLS transport, data retention policies (90/365/∞ days), secure deletion (overwrite+random+truncate+unlink), storage quotas, compliance export | `mtls/context.py`, `retention/manager.py`, `audit/logger.py`, `tests/test_retention.py`, `tests/test_mtls.py` | ✅ Implemented |
| PI1.1 | Processing accuracy | 4-layer determinism guard stack, SHA-256 deterministic hash, frozen dataclasses, sorted keys, no random IDs, verify-determinism CLI | `guards.py`, `models.py`, `policy_versioned/store.py` (content hashing), `baseline_hardening.py` (HMAC), `tests/test_guards.py` | ✅ Implemented |
| PI1.3 | Processing authorization | RBAC (3 roles), token-bucket rate limiting, priority job queue, deny-by-default sandbox policy, API versioning | `daemon/server.py` (RBAC), `ratelimit/limiter.py`, `ratelimit/queue.py`, `l3/policy.py`, `api_versioning.py`, `tests/test_ratelimit.py` | ✅ Implemented |

---

## 5. Remediation Roadmap

### Priority 1 — Close SOC 2 Type I Gaps (Target: v0.5.0)

| Item | Description | Effort | Criterion |
|------|-------------|--------|-----------|
| R-01 | Write formal Change Management Policy document | 2 days | CC8.1 |
| R-02 | Define Periodic Access Review process (quarterly token/RBAC review) | 1 day | CC6.3 |
| R-03 | Document Incident Response SLAs (response times, escalation paths) | 1 day | CC7.2 |
| R-04 | External audit notary integration (Rekor transparency log) | 5 days | CC7.1 |

### Priority 2 — Strengthen Existing Controls (Target: v0.6.0)

| Item | Description | Effort | Criterion |
|------|-------------|--------|-----------|
| R-05 | Implement byte-for-byte reproducible builds (SOURCE_DATE_EPOCH) | 3 days | CC6.6 |
| R-06 | Add audit log export for SIEM integration (CEF/LEEF format) | 2 days | CC7.1 |
| R-07 | Implement session timeout and token rotation for daemon mode | 3 days | CC6.2 |
| R-08 | Add network segmentation documentation for K8s deployments | 1 day | CC6.1 |

### Priority 3 — Enhance for Type II Readiness (Target: v1.0.0)

| Item | Description | Effort | Criterion |
|------|-------------|--------|-----------|
| R-09 | Implement continuous SLO monitoring with alerting thresholds | 3 days | CC7.1 |
| R-10 | Add automated compliance reporting (SOC 2 control testing) | 5 days | All |
| R-11 | Implement data classification labels on stored scan results | 2 days | C1.1 |
| R-12 | Add vulnerability scanning of IronDome's own dependencies in CI | 2 days | CC6.6 |

---

## Appendix A: IronDome Architecture for Auditors

```
┌──────────────────────────────────────────────────────────────┐
│                    IronDome v0.5.0 Architecture               │
│                                                              │
│  ┌──────────┐                                                │
│  │   CLI    │── Direct usage (single scan)                   │
│  └────┬─────┘                                                │
│       │                                                      │
│  ┌────▼─────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Daemon  │───▶│  L3 Sandbox  │───▶│  L4 Behavioral   │  │
│  │ (HTTP)   │    │  (seccomp/   │    │  (profiler +     │  │
│  │          │    │   seatbelt/   │    │   detector rules)│  │
│  │ TokenAuth│    │   subprocess) │    │                  │  │
│  │ RBAC     │    └──────────────┘    └──────────────────┘  │
│  │ RateLimit│                                                │
│  │ mTLS     │    ┌──────────────┐    ┌──────────────────┐  │
│  └────┬──────┘    │  Audit Log   │    │  Policy Store    │  │
│       │          │  (hash-chain) │    │  (versioned,     │  │
│       │          └──────────────┘    │   content-hash)   │  │
│       │                               └──────────────────┘  │
│       │          ┌──────────────┐    ┌──────────────────┐  │
│       │          │  Retention   │    │  Baselines       │  │
│       │          │  (TTL, shred)│    │  (HMAC-signed,   │  │
│       │          └──────────────┘    │   drift-checked) │  │
│       │                               └──────────────────┘  │
│       │          ┌──────────────┐    ┌──────────────────┐  │
│       │          │  SLO Tracker │    │  Webhooks        │  │
│       │          │  (7 SLOs)    │    │  (HMAC-signed,   │  │
│       │          └──────────────┘    │   severity-filter)│  │
│       │                               └──────────────────┘  │
│       │          ┌──────────────┐                              │
│       │          │  Guard Stack │                              │
│       │          │  (4 layers)  │                              │
│       │          └──────────────┘                              │
└──────────────────────────────────────────────────────────────┘
```

## Appendix B: Audit Log Event Types

| Event Type | SOC 2 Relevance | Criterion |
|-----------|----------------|-----------|
| `SCAN_START` | Processing initiated | PI1.1 |
| `SCAN_COMPLETE` | Processing completed | PI1.1 |
| `SCAN_ALERT` | Security incident detected | CC7.1, CC7.2 |
| `POLICY_CREATE` | Change management | CC8.1 |
| `POLICY_UPDATE` | Change management | CC8.1 |
| `POLICY_ROLLBACK` | Change management | CC8.1 |
| `POLICY_DELETE` | Change management | CC8.1 |
| `BASELINE_CREATE` | Change management | CC8.1 |
| `BASELINE_UPDATE` | Change management | CC8.1 |
| `BASELINE_DELETE` | Change management | CC8.1 |
| `DAEMON_START` | Availability | A1.1 |
| `DAEMON_STOP` | Availability | A1.1 |
| `AUTH_SUCCESS` | Access control | CC6.2 |
| `AUTH_FAILURE` | Access control | CC6.2 |
| `DATA_RETENTION_CLEANUP` | Data governance | C1.1 |
| `DATA_EXPORT` | Data governance | C1.1 |
| `DATA_DELETE` | Data governance | C1.1 |

## Appendix C: Daemon API Endpoints (SOC 2 Relevance)

| Endpoint | Method | Auth | RBAC | SOC 2 Criterion |
|----------|--------|------|------|-----------------|
| `/health` | GET | None | — | A1.1 |
| `/ready` | GET | None | — | A1.1 |
| `/metrics` | GET | None | — | CC7.1 |
| `/api/v1/scan` | POST | Token | `scan:submit` | PI1.3 |
| `/api/v1/scan/:id` | GET | Token | `scan:read` | PI1.1 |
| `/api/v1/scans` | GET | Token | `scan:read` | PI1.1 |
| `/api/v1/policies` | GET | Token | `policy:read` | CC8.1 |
| `/api/v1/policies` | POST | Token | `policy:write` | CC8.1 |
| `/api/v1/policies/:name` | GET | Token | `policy:read` | CC8.1 |
| `/api/v1/baselines` | GET | Token | `baseline:read` | CC8.1 |
| `/api/v1/audit` | GET | Token | `audit:read` | CC7.1 |
| `/api/v1/stats` | GET | Token | `scan:read` | CC7.1 |