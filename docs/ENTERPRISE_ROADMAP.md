# Iron Dome Enterprise Roadmap — Complete

> **Version:** 0.4.0 · **Date:** 2026-05-22 · **Status:** Active

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

### Phase 3 — Hardening & Scale (v0.5.0 → v1.0.0) — Remaining

| PR | Description | Priority |
|----|-------------|----------|
| PR-16 | External audit notary integration (Rekor/Sigstore transparency log) | High |
| PR-17 | Reproducible builds (SOURCE_DATE_EPOCH, pinned dep hashes, hermetic pip) | High |
| PR-18 | Formal threat model with attack trees per surface | High |
| PR-19 | SOC 2 Type I readiness assessment documentation | Medium |
| PR-20 | Daemon cluster mode (multi-node, shared state) | Medium |
| PR-21 | gRPC transport option (in addition to HTTP) | Low |

## Enterprise Gate Status

| Gate | v0.3.0 | v0.4.0 (Current) |
|------|--------|-------------------|
| Shared-service access control | ❌ | ✅ Token auth + RBAC |
| Data governance | ⚠️ Local only | ✅ Retention + secure deletion + export |
| Provenance & policy | ❌ | ✅ Versioned policies + content hashing |
| Auditability | ⚠️ Partial | ✅ Hash-chained audit log + query API |
| Operational readiness | ❌ | ✅ Health/readiness + SLOs + metrics + runbooks |

## Architecture (v0.4.0)

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
  ├── TokenAuth + RBAC               ← PR-5
  ├── RateLimiter                    ← PR-8
  └── mTLS (optional)               ← PR-9

Infrastructure
  ├── audit/                         ← PR-1: hash-chained audit log
  ├── policy_versioned/              ← PR-2: versioned policy store
  ├── retention/                     ← PR-3: TTL, secure deletion, export
  ├── ratelimit/                     ← PR-8: token-bucket + job queue
  ├── mtls/                          ← PR-9: mutual TLS
  ├── slo.py                         ← PR-10: SLO definitions + tracker
  ├── webhooks.py                    ← PR-11: HMAC-signed notifications
  ├── baseline_hardening.py          ← PR-12: anti-poisoning
  ├── api_versioning.py              ← PR-13: version negotiation
  ├── health.py                      ← PR-4: health checks
  └── deploy/                        ← PR-14,15: K8s + Helm
```

## Test Summary

| Module | New Tests | Status |
|--------|-----------|--------|
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
| **Total new** | **92** | **✅ 92/92 passing** |

## Remaining Work (v1.0.0)

1. **External audit notary** — Integrate Rekor transparency log for audit trail entries
2. **Reproducible builds** — SOURCE_DATE_EPOCH, dependency pinning, hermetic builds
3. **Formal threat model** — Attack trees per surface (seccomp, seatbelt, subprocess, L4 rules)
4. **SOC 2 Type I** — Trust services criteria mapping, evidence collection
5. **Cluster mode** — Multi-node daemon with shared state (Redis/SQLite)
6. **gRPC transport** — Binary protocol option for high-throughput environments
