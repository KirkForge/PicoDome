# IronDome — Enterprise Pilot Limitations

> **Version:** 0.5.0 · **Status:** Enterprise Beta — Controlled Pilot  
> **Last updated:** 2026-05-27

This document defines the boundaries, assumptions, and unsupported claims for
IronDome during the enterprise-beta pilot phase. Organizations evaluating
IronDome must read this before deployment.

## 1. Pilot Scope

IronDome enterprise-beta is approved for **controlled pilot deployments** only.
This means:

- Deployment in non-production or pre-production environments first
- Limited to approved tenant count (see §3)
- With monitoring and rollback capability confirmed before production use
- Not for compliance-mandated environments without explicit sign-off

## 2. Scale Limits

| Dimension | Pilot Limit | GA Target |
|-----------|-------------|-----------|
| Concurrent scan jobs | 50 | 500+ |
| Tenants | 10 | Unlimited |
| Policies per tenant | 25 | 100+ |
| Scan history retention | 30 days | Configurable (90+ days) |
| API requests/second (global) | 25 rps | 100+ rps |
| API requests/second (per-actor) | 2 rps | 10+ rps |
| Daemon replicas | 2 | 10+ (with Redis shared state) |
| Admission webhook pods | 2 | 5+ |

Exceeding these limits may cause degraded performance, increased latency,
or request rejection. Scale testing beyond pilot limits is planned for GA.

## 3. Tenancy Assumptions

- **Soft isolation:** Tenant separation is enforced at the application layer
  (API key + RBAC + separate audit chains). It is NOT enforced at the
  database, filesystem, or network level in pilot mode.
- **Shared infrastructure:** All tenants share the same Redis/SQLite backend
  and daemon process. No per-tenant resource quotas are enforced.
- **No tenant-level encryption keys:** All tenant data is encrypted at rest
  with a single key. Per-tenant key encryption (BYOK) is a GA feature.
- **Trust boundary:** Tenant operators must trust the IronDome operator.
  A compromised operator key grants access across all tenants.

## 4. Redis Requirements

Pilot mode supports two store backends:

| Backend | Pilot Support | GA Support | Tradeoffs |
|---------|---------------|------------|----------|
| JSONL (default) | ✅ Single replica only | ✅ Single replica | No shared state across replicas |
| SQLite | ✅ Single replica only | ✅ Single replica | Better query; no shared state |
| Redis | ✅ Multi-replica | ✅ Multi-replica | Requires Redis 6+; separate infra |

**Redis requirements for multi-replica pilot:**
- Redis 6.0+ or Redis 7.x (Valkey 7.x compatible)
- Minimum 256 MB allocated
- Persistence enabled (AOF or RDB)
- No AUTH required in pilot (recommended for GA)
- Network policy: allow from IronDome pods only

**Known limitation:** Redis connection failures cause graceful fallback to
in-memory JSONL store. Data written during fallback is not replicated across
other daemon replicas.

## 5. Supported Deployment Modes

| Mode | Pilot Status | Notes |
|------|-------------|-------|
| Single daemon (JSONL) | ✅ Supported | Default, simplest |
| Single daemon (SQLite) | ✅ Supported | Better query capability |
| Multi-daemon + Redis | ✅ Supported | Requires Redis infrastructure |
| Admission webhook | ✅ Supported | Requires cert-manager |
| Helm chart | ✅ Supported | Both irondome and irondome-admission charts |
| Docker Compose | ✅ Supported | For evaluation only |
| Bare metal / systemd | ⚠️ Best effort | No automated support |
| Windows | ❌ Not supported | seccomp/seatbelt Linux/macOS only |

## 6. Unsupported Compliance Claims

IronDome enterprise-beta does **NOT** claim compliance with:

- SOC 2 Type II (Type I readiness docs only)
- ISO 27001
- PCI-DSS
- HIPAA
- FedRAMP
- GDPR (data processing agreement not provided)

IronDome provides security controls and evidence artifacts that may support
a compliance program, but formal certification is a GA milestone.

Specific unsupported claims:

| Claim | Status | GA Target |
|-------|--------|-----------|
| "SOC 2 certified" | ❌ Type I readiness docs only | Type II after 6-month operating period |
| "FIPS 140-2 crypto" | ❌ Standard library crypto only | FIPS module evaluation planned |
| "Data residency controls" | ❌ No geo-fencing | Region-aware deployment planned |
| "Audit log tamper proof" | ⚠️ Hash-chained, not immutable storage | WORM storage or external notary planned |
| "Zero-trust architecture" | ❌ Token auth, not mTLS-everywhere | mTLS enforcement planned |
| "Disaster recovery SLA" | ❌ No automated failover | HA + failover planned for GA |

## 7. Known Issues and Risks

| ID | Issue | Severity | Mitigation |
|----|-------|----------|------------|
| P-1 | Sandbox escape paths not externally validated | Critical | Third-party pentest planned (see `docs/security/THIRD_PARTY_REVIEW.md`) |
| P-2 | No per-tenant encryption keys | High | BYOK planned for GA |
| P-3 | CORS wildcard in enterprise mode (warn-only) | Medium | Set `IRONDOME_CORS_ORIGINS` explicitly |
| P-4 | fork() deprecation warning in seccomp backend | Low | Future: switch to posix_spawn |
| P-5 | Redis fallback data not replicated | Medium | Monitor Redis health; plan capacity |
| P-6 | No automated capacity planning | Medium | Benchmark results planned for GA |

## 8. Operational Requirements

- **Monitoring:** Prometheus + Grafana dashboard required (see `deploy/monitoring/`)
- **Alerting:** Recommended alert rules provided (see `deploy/monitoring/irondome-alerts.yaml`)
- **Backup:** Pilot does not include automated backup. Operator must back up:
  - `~/.irondome/jobs.jsonl` (JSONL store)
  - `~/.irondome/jobs.db` (SQLite store)
  - Redis RDB/AOF (Redis store)
  - `~/.irondome/audit/` (audit logs)
- **Certificate rotation:** cert-manager required for admission webhook TLS.
  Manual rotation is error-prone and not recommended.
- **Log retention:** Default 30 days. Configure `IRONDOME_RETENTION_DAYS` for longer.

## 9. Support and Escalation

| Channel | Response Time | Scope |
|---------|--------------|-------|
| GitHub Issues | Best effort | Bug reports, feature requests |
| Security advisory | 48 hours | Vulnerability reports |
| Enterprise pilot support | 5 business days | Deployment issues, configuration |

**No SLA is provided during pilot.** GA will include defined SLAs with
uptime, latency, and support response commitments.

## 10. Graduation Criteria

IronDome graduates from enterprise-beta to enterprise-GA when:

- [ ] Full test suite completes within CI timeout (< 10 min for 3.12)
- [ ] Third-party security review completed with no critical findings
- [ ] Published scale benchmarks (100+ concurrent scans)
- [ ] Per-tenant encryption keys (BYOK) implemented
- [ ] Automated backup and restore documented
- [ ] Capacity planning guidance published
- [ ] 90-day pilot operation without critical incident
- [ ] SOC 2 Type II readiness assessment completed
- [ ] Helm values schema validation added
