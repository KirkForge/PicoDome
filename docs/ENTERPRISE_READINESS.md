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
