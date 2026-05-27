# Iron Dome — Enterprise Readiness (historical gap analysis)

> **Status:** Superseded · **Current document:** [`ENTERPRISE_GAP_ANALYSIS.md`](ENTERPRISE_GAP_ANALYSIS.md)  
> **Last updated:** 2026-05-27

This document was the original enterprise gap analysis created early in the
project lifecycle. It identified blockers for enterprise deployment and
proposed a phased roadmap. **Most gaps identified here have since been
remediated** as part of the v0.4.0 and v0.5.0 enterprise hardening releases.

For the current, maintained gap assessment with remediation status and
enterprise readiness scoring, see **[`ENTERPRISE_GAP_ANALYSIS.md`](ENTERPRISE_GAP_ANALYSIS.md)**.

---

## Historical gaps — remediation summary

| Original Gap | Status | Remediating Release | Evidence |
|---|---|---|---|
| Threat model + non-goals | ✅ Addressed | v0.3.0 | `docs/security/threat-model.md` |
| Policy model and governance | ✅ Addressed | v0.4.0–v0.5.0 | `docs/POLICY_GOVERNANCE.md`, deny-by-default policy, policy signing, approval workflow |
| Audit log / evidence retention | ✅ Addressed | v0.4.0 | Hash-chained audit log, JSONL sink, retention, SIEM export |
| Secure deployment guide | ✅ Addressed | v0.3.0–v0.5.0 | `docs/security/SANDBOX_HARDENING.md`, `deploy/` manifests, Dockerfile, Helm charts |
| Cross-platform parity and compatibility | ✅ Addressed | v0.5.0 | `docs/deploy/KUBERNETES_COMPATIBILITY.md`, 3 backends, compatibility tests |
| Release integrity and reproducible artifacts | ✅ Addressed | v0.3.0 | Sigstore signing, SLSA L3 provenance, SBOM, evidence bundle |

## Remaining external-validation gaps

These gaps cannot be resolved by development alone — they require external
engagement and are tracked in the current gap analysis:

- **Third-party security validation** — pentest/red-team by independent reviewer (see `docs/security/THIRD_PARTY_REVIEW.md`)
- **Published scale benchmarks** — performance evidence at 100+ concurrent scans
- **SOC 2 Type II** — requires 6-month operating period after Type I readiness

---

## Original document (preserved for reference)

The content below is the original gap analysis as written before remediation.

---

# Iron Dome — Enterprise readiness (gap analysis)

Iron Dome is a deterministic runtime sandbox + behavioral analyzer (companion to PicoSentry). It is already pointed at enterprise use cases, but it’s earlier-stage and needs a clearer posture around **governance, auditability, and safe deployment**.

> This document makes the enterprise blockers explicit.

## What’s already strong

- Deterministic output and CI determinism gate.
- Multi-backend execution story (Linux seccomp, macOS seatbelt, subprocess fallback).
- Clear rule catalog (L3 suspicious patterns, L4 behavioral rules).

## Enterprise gates

1) **Safe execution posture** (sandbox guarantees and limitations)
2) **Provenance & supply chain** (signed releases, SBOMs, dependency scanning)
3) **Auditability** (evidence of what ran, policy used, verdict produced)
4) **Operational readiness** (SLOs/runbooks, reproducible deploy)
5) **Policy control** (deny-by-default, allowlists, platform-specific constraints)

---

## Gaps (what’s missing)

### 1) Threat model + non-goals

**Gap:** Enterprises will ask for a threat model for each backend, especially subprocess fallback.

**Minimum viable path:**
- `docs/security/threat-model.md` describing:
  - trust boundaries
  - what seccomp/seatbelt guarantees (and what it doesn’t)
  - subprocess fallback limitations
  - recommended deployment posture

### 2) Policy model and governance

**Gap:** Need a first-class policy format (deny-by-default, allowlisted syscalls/commands, file/network constraints).

**Minimum viable path:**
- Policy schema + docs
- Policy decisions included in output evidence

### 3) Audit log / evidence retention

**Gap:** Enterprises want an append-only audit trail:
- command executed
- backend used
- policy hash
- verdict + rule hits

**Minimum viable path:**
- JSONL audit sink with rotation/retention
- export guidance for SIEM

### 4) Secure deployment guide

**Gap:** Need an opinionated “how to run this safely” guide.

**Minimum viable path:**
- container posture (non-root, read-only FS where possible)
- network posture guidance
- CI integration guidance

### 5) Cross-platform parity and compatibility matrix

**Gap:** Need explicit coverage matrix:
- which syscalls are allowed
- macOS sandbox profile constraints
- what happens on unsupported platforms

**Minimum viable path:**
- compatibility doc and tests

### 6) Release integrity and reproducible artifacts

**Gap:** PicoSentry has strong release verification narratives; Iron Dome should match.

**Minimum viable path:**
- Sigstore signing + verification docs
- SBOM in release
- self dependency vulnerability scan

---

## Risk register (top blockers)

| Risk | Severity | Likelihood | Notes |
|---|---:|---:|---|
| Subprocess fallback weaker than true sandbox | High | Medium | Must document clearly + recommend posture |
| No audit trail/retention | High | Medium | Enterprise evidence requirement |
| No policy schema/deny-by-default | High | Medium | Governance requirement |
| No release integrity story | Medium | Medium | Supply-chain review |

---

## Pragmatic roadmap

**Phase 1 (docs + posture):** threat model + secure deployment guide + policy schema v1

**Phase 2 (audit):** JSONL audit sink + retention + SIEM export guidance

**Phase 3 (release integrity):** signing, SBOMs, dependency scan

---

## How to use this

- Convert each gap into an epic with acceptance criteria.
- Avoid “enterprise-ready” claims until audit + policy + threat model are in place.
