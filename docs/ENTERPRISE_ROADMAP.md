# Iron Dome Enterprise Roadmap

> **Version:** 0.5.0 · **Date:** 2026-05-27 · **Status:** Updated

## Completed PRs

### Phase 1 — Foundation (v0.3.0 → v0.4.0) ✅

| PR | Module | Description | Tests |
|----|--------|-------------|-------|
| PR-1 | `irondome.audit` | Structured audit logging with SHA-256 hash chaining, query API, rotation | 15 |
| PR-2 | `irondome.policy_versioned` | Policy versioning with author/timestamp/diff/rollback/integrity verify | 11 |
| PR-3 | `irondome.retention` | Data retention lifecycle, TTL per type, secure deletion, compliance export | 8 |
| PR-4 | `irondome.health` | Health and readiness checks (backend, audit chain, storage) | 4 |
| PR-5 | `irondome.daemon` | HTTP API server (12 endpoints), token auth, RBAC, Prometheus metrics | — |
| PR-6 | CLI integration | 6 new CLI subcommands (daemon, health, audit, retention, policy-versions) | — |
| PR-7 | `scripts/load_test.py` | Load testing baseline with p50/p95/p99 latency benchmarks | — |

### Phase 2 — Daemon & Governance (v0.4.0 → v0.5.0) ✅

| PR | Module | Description | Tests |
|----|--------|-------------|-------|
| PR-8 | `irondome.ratelimit` | Token-bucket rate limiter + priority job queue (4 priority levels, bounded, thread-safe) | 17 |
| PR-9 | `irondome.mtls` | mTLS transport security (TLS 1.2+, strong ciphers, dev self-signed mode) | 6 |
| PR-10 | `irondome.slo` | 7 SLO definitions + tracker (availability 99.9%, latency p50/p95/p99, throughput, error rate, determinism) | 7 |
| PR-11 | `irondome.webhooks` | Webhook notifications with HMAC-SHA256 signing, severity/event filtering, retry with backoff | 9 |
| PR-12 | `irondome.baseline_hardening` | Anti-poisoning: HMAC baseline signing, update rate limiting, drift detection, audit logging | 8 |
| PR-13 | `irondome.api_versioning` | API version negotiation (path/header/Accept), deprecation notices, backward compat | 7 |
| PR-14 | `deploy/kubernetes/` | K8s Deployment, Service, PVC, RBAC, ServiceAccount, health probes, Prometheus annotations | — |
| PR-15 | `deploy/helm/irondome/` | Helm chart with values (replicas, mTLS, rate limiting, webhooks, retention, SLOs, monitoring) | — |

### Phase 3 — Hardening & Scale (v0.5.0 → v1.0.0) ✅

| PR | Description | Priority |
|----|-------------|----------|
| PR-16 | ✅ External audit notary integration (Rekor/Sigstore transparency log) | High |
| PR-17 | ✅ Reproducible builds (SOURCE_DATE_EPOCH, pinned dep hashes, hermetic pip) | High |
| PR-18 | ✅ Formal threat model with attack trees per surface | High |
| PR-19 | ✅ SOC 2 Type I readiness assessment documentation | Medium |
| PR-20 | ✅ Daemon cluster mode (multi-node, shared state) | Medium |
| PR-21 | ✅ gRPC transport option (in addition to HTTP) | Low |

### Phase 4 — Enterprise Production Readiness ✅

| PR | Description | Priority |
|----|-------------|----------|
| PR-22 | ✅ PDB, HPA, NetworkPolicy for admission controller Helm chart | High |
| PR-23 | ✅ Certificate rotation configuration, runbook, and tests | High |
| PR-24 | ✅ K8s compatibility matrix | High |
| PR-25 | ✅ Webhook outage runbook (failure policy tradeoffs, break-glass) | High |
| PR-26 | ✅ Policy governance docs (approval workflow, break-glass, bundle format, migration) | High |
| PR-27 | ✅ Seccomp/AppArmor profiles and strict network policies | High |
| PR-28 | ✅ Malicious workload test corpus | High |
| PR-29 | ✅ Sandbox hardening guide | Medium |
| PR-30 | ✅ Prometheus metrics contract (25+ metrics) | High |
| PR-31 | ✅ Grafana dashboard and Prometheus alert rules | High |
| PR-32 | ✅ RBAC matrix and tenant model documentation | Medium |
| PR-33 | ✅ OIDC/SAML identity provider integration guide | Medium |
| PR-34 | ✅ Release evidence bundle generator | Medium |
| PR-35 | ✅ Vulnerability management and patch SLA documentation | Medium |

## Enterprise Gate Status

| Gate | v0.3.0 | v0.5.0 | Phase 4 |
|------|--------|--------|---------|
| Shared-service access control | ❌ | ✅ Token auth + RBAC | ✅ + IdP integration |
| Data governance | ⚠️ Local only | ✅ Retention + secure deletion + export | ✅ |
| Provenance & policy | ❌ | ✅ Versioned policies + content hashing | ✅ + Approval workflow + break-glass |
| Auditability | ⚠️ Partial | ✅ Hash-chained audit log + query API | ✅ |
| Operational readiness | ❌ | ✅ Health/readiness + SLOs + metrics + runbooks | ✅ + Dashboards + alerts |
| K8s production lifecycle | ❌ | ✅ Helm chart + K8s deployment | ✅ + PDB/HPA/cert rotation/compat matrix |
| Compliance evidence | ❌ | ⚠️ SOC2 docs only | ✅ + Evidence bundle + patch SLA |
| Sandbox hardening proof | ❌ | ⚠️ Threat model only | ⚠️ + Profiles + tests; external validation pending |

## Architecture (Phase 4)

```
CLI (cli.py)
  ├── sandbox / analyze / pipeline  (existing)
  ├── daemon                         ← PR-5: HTTP API server
  ├── health                         ← PR-4: health checks
  ├── audit                          ← PR-1: audit log query/verify
  ├── retention                      ← PR-3: data lifecycle
  └── policy-versions                ← PR-2: versioned policies

Daemon (daemon/server.py)           ← PR-5
  ├── /health, /ready, /metrics     ← PR-4, PR-10 (SLOs)
  ├── /api/v1/scan, /scans           ← scan jobs
  ├── /api/v1/policies               ← PR-2
  ├── /api/v1/baselines              ← PR-12 (hardening)
  ├── /api/v1/audit                  ← PR-1
  ├── /api/v1/stats                  ← system stats
  ├── TokenAuth + RBAC               ← PR-5 + PR-33 (IdP)
  ├── RateLimiter                    ← PR-8
  └── mTLS (optional)               ← PR-9

Admission Controller (admission/)
  ├── scanner.py                     ← PR-22: image scanning
  ├── validator.py                    ← Pod security validation
  └── webhook.yaml                    ← ValidatingWebhookConfiguration

Infrastructure
  ├── audit/                         ← PR-1: hash-chained audit log
  ├── policy_versioned/             ← PR-2: versioned policy store + PR-26: governance
  ├── retention/                     ← PR-3: TTL, secure deletion, export
  ├── ratelimit/                     ← PR-8: token-bucket + job queue
  ├── mtls/                          ← PR-9: mutual TLS
  ├── slo.py                         ← PR-10: SLO definitions + tracker
  ├── webhooks.py                    ← PR-11: HMAC-signed notifications
  ├── baseline_hardening.py          ← PR-12: anti-poisoning
  ├── api_versioning.py              ← PR-13: version negotiation
  ├── health.py                      ← PR-4: health checks
  └── deploy/                        ← PR-14,15,22-29: K8s + Helm + security profiles

Monitoring
  ├── deploy/monitoring/            ← PR-30,31: Grafana + alerts
  ├── docs/PROMETHEUS_METRICS.md    ← PR-30: metrics contract
  └── /metrics endpoint              ← 25+ Prometheus metrics

Security
  ├── deploy/security/              ← PR-27,28: seccomp + AppArmor + network policy
  ├── docs/security/                ← PR-18,29: threat model + hardening guide
  └── tests/test_malicious_workloads ← PR-28: adversarial test corpus

Compliance
  ├── docs/compliance/              ← PR-19,35: SOC2 + evidence + patch SLA
  ├── scripts/generate_evidence_bundle ← PR-34: release evidence automation
  └── scripts/generate_sbom         ← CycloneDX SBOM generation
```

## Remaining Work (v1.0.0)

1. **External security validation** — Engage security firm (plan documented in `docs/security/THIRD_PARTY_REVIEW.md`)
2. **Published performance benchmarks** — Cluster-scale load test results with capacity planning guidance
3. **Helm values schema** — Add `values.schema.json` for both charts
4. **Per-tenant encryption keys (BYOK)** — Required for multi-tenant production deployments
5. **SOC 2 Type II readiness** — Requires 6-month operating period after pilot
6. **Capacity planning guidance** — Document resource requirements per scale tier

## Completed Enterprise-Beta Gaps (v0.5.0)

| # | Gap | Resolution |
|---|-----|------------|
| 1 | Test suite reliability evidence | ✅ Time-bounded pytest (120s/test), test summary JSON per CI run |
| 2 | Release artifact packaging hygiene | ✅ `global-exclude` in MANIFEST.in, verified clean builds |
| 3 | Release evidence bundle per version | ✅ Evidence job in release workflow, bundle attached to GitHub releases |
| 4 | Enterprise pilot limitations | ✅ `docs/ENTERPRISE_PILOT_LIMITATIONS.md` with scale limits, tenancy, unsupported claims |
| 5 | Third-party security review plan | ✅ `docs/security/THIRD_PARTY_REVIEW.md` with scope, timeline, budget |
| 6 | Missing `create_app` factory | ✅ Added `create_app()` to `daemon/server.py` for test/programmatic use |

## Test Summary

| Module | Tests | Status |
|--------|-------|--------|
| audit | 15 | ✅ All passing |
| policy_versioned | 11 | ✅ All passing |
| retention | 8 | ✅ All passing |
| health | 4 | ✅ All passing |
| ratelimit | 17 | ✅ All passing |
| mtls | 6 | ✅ All passing |
| slo | 7 | ✅ All passing |
| webhooks | 9 | ✅ All passing |
| baseline_hardening | 8 | ✅ All passing |
| api_versioning | 7 | ✅ All passing |
| admission helm | 30+ | ✅ All passing (expanded) |
| cert rotation | 11 | ✅ All passing |
| malicious workloads | 13 | ✅ Conditional (requires sandbox) |
| **Total** | **1170** | **✅ 1158 passed, 12 skipped** |
