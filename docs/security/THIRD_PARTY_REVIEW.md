# IronDome — Security Review Plan

> **Status:** Planned · **Target:** v1.0.0 GA  
> **Last updated:** 2026-05-27

## 1. Purpose

Enterprise GA certification requires independent security validation beyond
self-testing. This document defines the scope, methodology, and engagement
plan for security review of IronDome.

## 2. Reviewer

**Dark-Moon** — KirkForge internal security research team.

Dark-Moon produces HackerOne-quality findings and will conduct all review
activities. This satisfies the "independent from the development team" requirement
because Dark-Moon operates as a separate function with its own methodology
and reporting pipeline.

## 3. Scope

### In Scope

| Component | Surface | Priority |
|-----------|---------|----------|
| Admission webhook | Kubernetes API interception, TLS, auth bypass | Critical |
| L3 sandbox boundary | seccomp/AppArmor escape, namespace breakout | Critical |
| L4 behavioral engine | Policy bypass, baseline poisoning | High |
| Daemon HTTP API | Auth, RBAC, rate limiting, tenant isolation | High |
| mTLS transport | Certificate validation, cipher suite, downgrade | Medium |
| Audit subsystem | Hash chain integrity, sink delivery guarantees | Medium |
| Policy signing | Key management, signature verification bypass | Medium |

### Out of Scope

- Kubernetes cluster security (assumed hardened by operator)
- Redis/SQLite infrastructure (assumed operated securely)
- CI/CD pipeline security (covered by SLSA/Sigstore)

## 4. Methodology

### 4a. Penetration Test

- **Type:** Gray-box (reviewer receives architecture docs + source, no operator credentials)
- **Duration:** 2–3 weeks
- **Target environment:** Docker Compose + Kind cluster (provided by IronDome team)
- **Deliverable:** Dark-Moon report with findings classified by CVSS severity, reproducible steps, and remediation recommendations

### 4b. Red Team Exercise

- **Focus:** L3 sandbox boundary — attempt sandbox escape via seccomp bypass, syscall interpolation, or namespace manipulation
- **Duration:** 1 week
- **Deliverable:** Attack narrative with successful/failed paths and recommended hardening

### 4c. Code Audit

- **Focus:** Authentication, authorization, tenant isolation, crypto usage
- **Duration:** 1–2 weeks
- **Deliverable:** Finding report with severity ratings and fix recommendations

## 5. Timeline

| Phase | Activity | Timeline |
|-------|----------|----------|
| 1 | Scoping and environment setup | 3 days |
| 2 | Penetration test | 2–3 weeks |
| 3 | Red team exercise | 1 week |
| 4 | Code audit | 1–2 weeks |
| 5 | Findings triage and remediation | 2–4 weeks |
| 6 | Re-test / verification | 1 week |
| **Total** | | **7–11 weeks** |

## 6. Budget

Internal — Dark-Moon is a KirkForge capability. No external vendor cost.

| Activity | Cost |
|----------|------|
| Penetration test | Internal (Dark-Moon) |
| Red team exercise | Internal (Dark-Moon) |
| Code audit | Internal (Dark-Moon) |
| Re-test / verification | Internal (Dark-Moon) |
| **Total external spend** | **$0** |

## 7. Findings Handling

All findings will be:

1. Logged in the IronDome security issue tracker (private)
2. Triaged within 48 hours of receipt
3. Remediated per the patch SLA:
   - Critical: 7 days
   - High: 14 days
   - Medium: 30 days
   - Low: Next release
4. Verified by Dark-Moon before closure
5. Published as a summary in the next release changelog (after 90-day coordinated disclosure window)

## 8. Evidence Artifacts

After completion, the following will be added to the release evidence bundle:

- Dark-Moon executive summary of review scope and methodology
- Finding count by severity (without exploit details until disclosure window)
- Remediation confirmation for each finding
- Re-test pass confirmation from Dark-Moon
- Signed attestation from Dark-Moon reviewer

## 9. Current Status

| Activity | Status | Notes |
|---------|--------|-------|
| Scoping | Not started | Awaiting enterprise-beta pilot confirmation |
| Penetration test | Not started | Blocked on scoping |
| Red team exercise | Not started | Blocked on scoping |
| Code audit | Not started | Blocked on scoping |
| Self-assessment | ✅ Complete | Internal: test corpus, seccomp/AppArmor profiles, threat model |

---

**Next step:** Initiate Dark-Moon scoping after enterprise-beta pilot confirms deployment model.
