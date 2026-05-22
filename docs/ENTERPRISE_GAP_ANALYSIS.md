# Iron Dome — Enterprise Readiness Gap Analysis

> **Version:** 0.3.0 · **Date:** 2026-05-22 · **Status:** Draft

## 1. Executive Summary

Iron Dome provides deterministic, offline-capable runtime sandboxing and behavioral analysis for supply-chain security. It fills the L3 (sandbox) and L4 (behavioral) layers that static scanners like PicoSentry cannot reach. This document identifies the gaps between Iron Dome's current capabilities and the requirements of enterprise deployment — particularly as a shared service behind the Shogun command center.

---

## 2. Current Strengths

| Strength | Detail |
|---|---|
| **Deterministic** | Same input → same output. No telemetry, no non-deterministic heuristics. Results are reproducible and auditable. |
| **Offline at scan time** | No network calls during sandboxing. Works in air-gapped CI and on-prem environments. |
| **Real kernel-level sandboxing** | seccomp-bpf on Linux, seatbelt on macOS, subprocess isolation as universal fallback. Not a toy sandbox. |
| **4-layer guard stack** | L1 (PicoSentry static) → L2 (PicoSentry deep) → L3 (Iron Dome sandbox) → L4 (Iron Dome behavioral). Defense in depth. |
| **Minimal runtime deps** | Pure Python core with optional libseccomp. No database, no broker, no sidecar. Low attack surface. |
| **Multi-signal behavioral detection** | Timing anomalies, data exfiltration, entropy spikes, honeypot access, baseline drift — five independent signals. |

---

## 3. Enterprise Gates

Enterprise customers evaluate software against five gates. Iron Dome's current status:

| Gate | Description | Status |
|---|---|---|
| **Shared-service access control** | Who can submit sandbox jobs? Who can read results? | ❌ Not implemented |
| **Data governance** | Where do results go? How long are they kept? Can they be deleted? | ⚠️ Local filesystem only |
| **Provenance & policy** | Who changed sandbox policy? What version was active during a scan? | ❌ Not implemented |
| **Auditability** | Can every action be traced to an identity and timestamp? | ⚠️ Partial (CLI logs) |
| **Operational readiness** | SLOs, runbooks, load testing, incident playbooks | ❌ Not implemented |

---

## 4. Gaps by Surface Area

### 4a. Daemon Mode: Auth + Authorization

**Gap:** Iron Dome is currently CLI-only. The Shogun command center needs a daemon that accepts sandbox jobs over a local socket or HTTP API, with authentication and role-based authorization.

**Impact:** Without this, Iron Dome cannot serve as a shared service for multiple teams or be orchestrated by Shogun.

**Requirements:**
- Token-based or mTLS authentication
- Role-based access control (submitter, reader, admin)
- Rate limiting and job queuing
- API versioning for backward compatibility

### 4b. Cache + Persisted State: Retention and Deletion

**Gap:** Behavioral baselines and scan results are stored on the local filesystem with no lifecycle management.

**Impact:** Enterprises need data retention policies (e.g., 90 days for scan results, 1 year for baselines) and the ability to delete data on request (GDPR, data governance).

**Requirements:**
- Configurable retention periods per data type
- Secure deletion (shred or overwrite)
- Data export API for compliance audits
- Storage quotas to prevent disk exhaustion

### 4c. Policy Provenance: Who Changed Sandbox Policy and When

**Gap:** Sandbox policies (seccomp profiles, seatbelt rules, behavioral thresholds) are static files with no versioning or authorship tracking.

**Impact:** When a policy change causes a false positive or allows a bypass, enterprises need to know who made the change and when.

**Requirements:**
- Policy versioning with author, timestamp, and change description
- Policy diff view (what changed between versions)
- Rollback to previous policy version
- Policy signing (optional: Sigstore-based)

### 4d. Audit Trail for Policy Mutations and Baseline Changes

**Gap:** No structured audit log exists. CLI output goes to stdout/stderr but is not persisted or queryable.

**Impact:** Enterprises need audit trails for compliance (SOC 2, ISO 27001) and for post-incident investigation.

**Requirements:**
- Structured audit log (JSON lines, append-only)
- Events: policy create, policy update, policy rollback, baseline create, baseline update, scan start, scan complete, scan alert
- Tamper-evident log (hash chaining or external notary)
- Query interface (filter by time, user, event type)

### 4e. Threat Model for Sandbox Escapes and L4 Bypasses

**Gap:** No formal threat model documents the attack surfaces of Iron Dome itself.

**Impact:** Enterprises need assurance that the sandbox cannot be subverted and that behavioral detection cannot be bypassed.

**Requirements:**
- Documented threat model covering: seccomp bypass, seatbelt escape, subprocess breakout, timing signal evasion, exfil channel obfuscation, entropy manipulation, honeypot detection, baseline drift poisoning
- Attack tree for each surface
- Mitigations mapped to each attack vector
- Annual threat model review process

### 4f. Operational Readiness: SLOs, Runbooks, Load Testing

**Gap:** No defined service level objectives, no runbooks, no load testing data.

**Impact:** Enterprise operations teams cannot plan capacity or respond to incidents without documented procedures.

**Requirements:**
- SLOs: scan latency (p50, p95, p99), throughput (scans/min), availability (daemon mode)
- Runbooks: common failure modes, escalation paths, rollback procedures
- Load testing: benchmark results for sandboxing throughput under various profiles
- Monitoring: health check endpoints, metrics export (Prometheus format)

---

## 5. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Sandbox escape via seccomp bypass | Medium | Critical | Kernel version pinning, syscall allowlist minimization, regular escape testing |
| R2 | Behavioral baseline poisoning | Low | High | Baseline signing, anomaly detection on baseline updates, rate-limited baseline writes |
| R3 | Policy misconfiguration allows bypass | Medium | High | Policy provenance, review gates, dry-run mode |
| R4 | Daemon auth bypass in Shogun integration | Medium | Critical | mTLS, token rotation, RBAC, audit logging |
| R5 | Disk exhaustion from unbounded scan results | High | Medium | Retention policies, storage quotas, automatic cleanup |
| R6 | Timing signal evasion by adversarial packages | Medium | Medium | Multi-signal correlation, adaptive thresholds, randomization of observation windows |
| R7 | Audit log tampering | Low | High | Hash chaining, append-only storage, external notary integration |
| R8 | Supply-chain attack on Iron Dome itself | Low | Critical | Sigstore signing, reproducible builds, dependency pinning, PicoSentry self-scan |

---

## 6. Pragmatic Roadmap

### Phase 1 — Foundation (v0.3.0 → v0.4.0)

**Goal:** Close the most critical gaps for early enterprise adopters.

- [ ] Structured audit logging (JSON lines, hash chaining)
- [ ] Policy versioning with author and timestamp
- [ ] Data retention configuration (TTL per data type)
- [ ] Threat model document (first pass)
- [ ] Health check endpoint for daemon mode
- [ ] Load testing baseline (single-node, CLI mode)

### Phase 2 — Daemon & Governance (v0.4.0 → v0.5.0)

**Goal:** Enable Shogun command center integration and compliance readiness.

- [ ] Daemon mode with HTTP API and authentication (token-based)
- [ ] RBAC (submitter, reader, admin roles)
- [ ] Policy signing (Sigstore-based)
- [ ] Secure deletion for scan results
- [ ] Metrics export (Prometheus format)
- [ ] Runbooks for top 5 failure modes
- [ ] SLO definitions and measurement

### Phase 3 — Hardening & Scale (v0.5.0 → v1.0.0)

**Goal:** Production-grade hardening for fleet-wide deployment.

- [ ] mTLS authentication for daemon mode
- [ ] Rate limiting and job queuing
- [ ] Baseline drift detection hardening
- [ ] External audit notary integration
- [ ] Storage quotas and automatic cleanup
- [ ] Comprehensive load testing (multi-node, daemon mode)
- [ ] SOC 2 Type I readiness assessment
- [ ] API versioning and backward compatibility guarantees

---

## 7. Conclusion

Iron Dome's core technology — deterministic sandboxing and behavioral analysis — is solid. The gaps are all in the enterprise operational layer: auth, audit, governance, and provenance. These are solvable problems with well-established patterns. The three-phase roadmap prioritizes the highest-impact items first (audit logging, policy versioning) and defers the more complex integration work (daemon mode, mTLS) to later phases.

The key insight: Iron Dome doesn't need to become a platform. It needs to become a **service** that Shogun can orchestrate — with clear boundaries, observable state, and auditable actions.