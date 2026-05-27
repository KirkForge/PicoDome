# IronDome — Third-Party Security Review Plan

> **Status:** Planned · **Target:** v1.0.0 GA  
> **Last updated:** 2026-05-27

## 1. Purpose

Enterprise GA certification requires independent security validation beyond
self-testing. This document defines the scope, methodology, and engagement
plan for third-party security review of IronDome.

## 2. Scope

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

## 3. Methodology

### 3a. Penetration Test

- **Type:** Gray-box (reviewer receives architecture docs + source, no operator credentials)
- **Duration:** 2–3 weeks
- **Target environment:** Provided via Docker Compose + Kind cluster
- **Deliverable:** Report with findings classified by CVSS severity, reproducible steps, and remediation recommendations

### 3b. Red Team Exercise

- **Focus:** L3 sandbox boundary — attempt sandbox escape via seccomp bypass, syscall interpolation, or namespace manipulation
- **Duration:** 1 week
- **Deliverable:** Attack narrative with successful/failed paths and recommended hardening

### 3c. Code Audit

- **Focus:** Authentication, authorization, tenant isolation, crypto usage
- **Duration:** 1–2 weeks
- **Deliverable:** Finding report with severity ratings and fix recommendations

## 4. Engagement Timeline

| Phase | Activity | Timeline |
|-------|----------|----------|
| 1 | Vendor selection and scoping | 2 weeks |
| 2 | Penetration test execution | 2–3 weeks |
| 3 | Red team exercise | 1 week |
| 4 | Code audit | 1–2 weeks |
| 5 | Findings triage and remediation | 2–4 weeks |
| 6 | Re-test / verification | 1 week |
| **Total** | | **9–13 weeks** |

## 5. Vendor Requirements

The selected security firm must:

- Have Kubernetes security expertise (CKS-certified reviewers preferred)
- Have experience with admission webhook security assessments
- Provide CVSS v3.1 scoring for all findings
- Support coordinated disclosure (90-day window)
- Deliver findings in SARIF + markdown format
- Allow IronDome team to observe testing sessions

## 6. Budget Estimate

| Activity | Estimated Cost |
|----------|---------------|
| Penetration test | $15,000–$25,000 |
| Red team exercise | $10,000–$15,000 |
| Code audit | $8,000–$12,000 |
| Re-test / verification | $3,000–$5,000 |
| **Total** | **$36,000–$57,000** |

## 7. Findings Handling

All findings will be:

1. Logged in the IronDome security issue tracker (private)
2. Triaged within 48 hours of receipt
3. Remediated per the patch SLA:
   - Critical: 7 days
   - High: 14 days
   - Medium: 30 days
   - Low: Next release
4. Verified by the original reviewer before closure
5. Published as a summary in the next release changelog (after coordinated disclosure window)

## 8. Evidence Artifacts

After completion, the following will be added to the release evidence bundle:

- Executive summary of review scope and methodology
- Finding count by severity (without exploit details until disclosure window)
- Remediation confirmation for each finding
- Re-test pass confirmation from original reviewer
- Signed attestation from reviewing firm

## 9. Current Status

| Activity | Status | Notes |
|---------|--------|-------|
| Vendor selection | Not started | Awaiting enterprise-beta pilot feedback |
| Penetration test | Not started | Blocked on vendor selection |
| Red team exercise | Not started | Blocked on vendor selection |
| Code audit | Not started | Blocked on vendor selection |
| Self-assessment | ✅ Complete | Internal: test corpus, seccomp/AppArmor profiles, threat model |

---

**Next step:** Initiate vendor selection after enterprise-beta pilot confirms deployment model.
