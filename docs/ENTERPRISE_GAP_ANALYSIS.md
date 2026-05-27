# Iron Dome — Enterprise Readiness Gap Analysis

> **Version:** 0.5.0 · **Date:** 2026-05-27 · **Status:** Enterprise Beta — controlled pilot ready  
> **Enterprise readiness score:** 6.5 → 8.0 → **8.5 / 10** (enterprise-beta)

## 1. Executive Summary

Iron Dome provides deterministic, offline-capable runtime sandboxing and behavioral analysis for supply-chain security. It fills the L3 (sandbox) and L4 (behavioral) layers that static scanners like PicoSentry cannot reach.

This document tracks the gaps between IronDome's capabilities and enterprise deployment requirements, with remediation status for each area.

---

## 2. Gap Assessment (updated 2026-05-27)

| Area | Previous Score | Current Score | Gap Severity |
|---|---|---|---|
| Kubernetes deployment | 5/10 | 9/10 | Low — Helm chart complete with PDB, HPA, cert-manager, network policies |
| Admission controller lifecycle | 4/10 | 8/10 | Low — Failure policy docs, cert rotation, compatibility matrix added |
| Policy governance | 5/10 | 8/10 | Low — Approval workflow, break-glass, bundle format, migration docs |
| Runtime isolation / sandbox proof | 5/10 | 7/10 | Medium — seccomp/AppArmor profiles added; needs external validation |
| Production observability | 6/10 | 9/10 | Low — Prometheus metrics contract, Grafana dashboard, alert rules |
| Multi-tenancy / RBAC | 6/10 | 8/10 | Low — RBAC matrix, tenant model, IdP integration documented |
| Compliance evidence | 5/10 | 8/10 | Low — Evidence bundle generator, patch SLA, access review |

---

## 3. Enterprise Gates (updated status)

| Gate | Description | v0.5.0 Status | Remediated |
|---|---|---|---|
| **Shared-service access control** | Who can submit/read? | ✅ Token auth + RBAC + IdP integration | ✅ |
| **Data governance** | Where do results go? Retention? | ✅ Retention + secure deletion + export | ✅ |
| **Provenance & policy** | Who changed policy? Versioning? | ✅ Versioned + signed + approval workflow | ✅ |
| **Auditability** | Every action traceable? | ✅ Hash-chained audit log + query API | ✅ |
| **Operational readiness** | SLOs, runbooks, load testing? | ✅ SLOs + dashboards + alerts + runbooks | ✅ |
| **Production K8s lifecycle** | Helm, cert rotation, PDB, HPA? | ✅ Helm with PDB/HPA/cert-manager/network policies | ✅ |
| **Compliance evidence** | Release evidence, SBOM, SLA? | ✅ Evidence bundle + SBOM + patch SLA | ✅ |
| **Sandbox hardening proof** | seccomp/AppArmor, external audit? | ⚠️ Profiles added; external validation pending | Partial |

---

## 4. Remediated Gaps

### 4a. Kubernetes admission controller lifecycle ✅

**Previous gap:** No PDB, no HPA for admission controller, no cert-manager integration docs, no K8s compatibility matrix, no failure-policy tradeoff documentation.

**Remediation:**
- Added `PodDisruptionBudget` template to admission Helm chart (`deploy/helm/irondome-admission/templates/pdb.yaml`)
- Added HPA configuration to admission values (`autoscaling` section)
- Added `NetworkPolicy` template for admission controller
- Added cert rotation configuration in values (`certRotation` section)
- Added K8s compatibility matrix (`docs/deploy/KUBERNETES_COMPATIBILITY.md`)
- Added webhook outage runbook (`docs/runbooks/webhook-outage.md`)
- Added cert rotation runbook (`docs/runbooks/cert-rotation.md`)

### 4b. Policy governance and signing ✅

**Previous gap:** No approval workflow, no break-glass, no policy bundle format, no migration docs.

**Remediation:**
- Added policy governance document (`docs/POLICY_GOVERNANCE.md`) with:
  - Full lifecycle: Draft → Review → Approve → Sign → Deploy → Monitor → Retire
  - GitOps approval workflow examples (ArgoCD, Flux)
  - Break-glass procedure with expiring exceptions
  - Policy bundle format specification
  - Version migration and canary deployment guidance
  - Audit requirements for all policy events

### 4c. Runtime isolation and sandbox proof ⚠️ (partial)

**Previous gap:** No seccomp/AppArmor profiles, no egress controls, no malicious workload test corpus.

**Remediation:**
- Added custom seccomp profile (`deploy/security/irondome-seccomp.json`)
- Added AppArmor profile ConfigMap (`deploy/security/irondome-apparmor.yaml`)
- Added strict network policy with egress controls (`deploy/security/irondome-networkpolicy-strict.yaml`)
- Added malicious workload test corpus (`tests/test_malicious_workloads.py`)
- Added sandbox hardening guide (`docs/security/SANDBOX_HARDENING.md`)

**Remaining gap:** External pentest or red-team evidence. This requires engagement with an external security firm and cannot be fully automated.

### 4d. Production observability and SLOs ✅

**Previous gap:** No metrics contract, no Grafana dashboards, no alert rules.

**Remediation:**
- Added Prometheus metrics contract (`docs/PROMETHEUS_METRICS.md`) with 25+ metrics
- Added Grafana dashboard (`deploy/monitoring/irondome-grafana-dashboard.json`)
- Added Prometheus alert rules (`deploy/monitoring/irondome-alerts.yaml`) covering:
  - SLO burn rate alerts (availability, latency, throughput)
  - Admission controller alerts (down, high denial, latency spike)
  - Certificate expiry alerts (30-day warning, 7-day critical)
  - Security alerts (audit chain broken, policy verification failure)
  - Infrastructure alerts (crash looping, storage quota, webhook failures)

### 4e. Multi-tenancy and RBAC ✅

**Previous gap:** No RBAC matrix docs, no tenant model documentation, no IdP integration.

**Remediation:**
- Added RBAC matrix document (`docs/RBAC_MATRIX.md`) with:
  - Three built-in roles: viewer, submitter, admin
  - Detailed permission table per endpoint
  - Kubernetes RBAC mapping
  - Token-to-role mapping format
  - Cross-tenant access prevention documentation
- Added identity provider integration guide (`docs/IDENTITY_PROVIDER.md`) with:
  - OIDC configuration (Okta, Azure AD, GitHub)
  - SAML via dex proxy
  - Group-to-role mapping examples
  - Token rotation guidance

### 4f. Compliance evidence ✅

**Previous gap:** Docs exist but no automated evidence generation, no patch SLA, no access review.

**Remediation:**
- Added release evidence bundle generator (`scripts/generate_evidence_bundle.py`)
- Added vulnerability management and patch SLA document (`docs/compliance/VULNERABILITY_MANAGEMENT.md`)
- Defined patch SLA: Critical 7 days, High 14 days, Medium 30 days, Low next release
- Added access review schedule: tokens 90d, keys 180d, service accounts 90d, certs automated

---

## 5. Remaining Gaps

### 5a. External security validation (Medium)

**Status:** Not automated. Requires external engagement.

**Recommendation:**
- Engage a security firm for penetration testing of the admission webhook
- Conduct red-team exercise targeting the L3 sandbox boundary
- Publish results (or summary) as part of compliance evidence

### 5b. Performance and latency benchmarks at scale (Low)

**Status:** Load test script exists (`scripts/load_test.py`). No published results at cluster scale.

**Recommendation:**
- Publish benchmark results for 100+ concurrent scans
- Document cluster scale assumptions (nodes, pods, resource limits)
- Add capacity planning guidance

### 5c. Helm chart schema validation (Low)

**Status:** Helm values exist but no `values.schema.json`.

**Recommendation:**
- Add JSON Schema for values to catch misconfiguration at install time

### 5d. Test-suite reliability evidence ✅ (remediated)

**Previous gap:** Full test suite did not complete within CI timeout. No machine-readable test summary.

**Remediation:**
- Added `pytest-timeout` (120s per test, thread method) to both CI and release workflows
- Added `generate_test_summary.py` script producing JSON evidence (total, passed, failed, skipped, duration, coverage, slow tests)
- CI now uploads `test-summary-py{version}.json` as artifact (30-day retention)
- Test suite: 1158 passed, 12 skipped (sandbox-dependent), 0 failed, ~55s wall-clock

### 5e. Release artifact packaging hygiene ✅ (remediated)

**Previous gap:** Release zips could include `__pycache__/` directories and `.pyc` files.

**Remediation:**
- Added `global-exclude __pycache__` and `global-exclude *.pyc` to `MANIFEST.in`
- Cleaned all local `__pycache__` directories from the repository
- Verified: wheel and sdist builds contain zero `.pyc` or `__pycache__` entries

### 5f. Release evidence bundle per version ✅ (remediated)

**Previous gap:** Evidence artifacts existed as scripts but were not wired into the release workflow.

**Remediation:**
- Added `evidence` job to release workflow (after sign + provenance)
- Evidence bundle tarball (`irondome-evidence-bundle.tar.gz`) attached to every GitHub release
- Release body updated to reference evidence bundle

### 5g. Enterprise pilot limitations ✅ (remediated)

**Previous gap:** No documented scope limits, tenancy assumptions, unsupported compliance claims.

**Remediation:**
- Added `docs/ENTERPRISE_PILOT_LIMITATIONS.md` with scale limits, tenancy assumptions, Redis requirements, supported deployment modes, unsupported compliance claims, known issues, graduation criteria

### 5h. Third-party security review plan ✅ (remediated)

**Previous gap:** External pentest needed but no plan or budget.

**Remediation:**
- Added `docs/security/THIRD_PARTY_REVIEW.md` with scope, methodology, timeline, budget, vendor requirements, findings handling

---

## 6. Risk Register (updated)

| ID | Risk | Severity | Likelihood | Status |
|---|---|---|---|---|
| R1 | Admission webhook outage blocks deployments | Critical | Low | ✅ Mitigated: runbook, PDB, failure policy docs |
| R2 | Certificate expiry/rotation failure | High | Low | ✅ Mitigated: cert-manager, rotation runbook, alerts |
| R3 | Sandbox boundary weaker than assumed | Critical | Medium | ⚠️ Partial: profiles added, pentest plan documented (THIRD_PARTY_REVIEW.md) |
| R4 | Policy signing lifecycle incomplete | High | Low | ✅ Mitigated: governance docs, approval workflow, audit |
| R5 | Missing production scale evidence | High | Medium | ⚠️ Partial: test summary generated per CI run, scale benchmarks pending |
| R6 | No observability/alerting | High | Low | ✅ Mitigated: metrics contract, dashboards, alert rules |
| R7 | Compliance evidence gaps | Medium | Low | ✅ Mitigated: evidence bundle, patch SLA, access review |
| R8 | Multi-tenant data leakage | High | Low | ✅ Mitigated: RBAC matrix, tenant isolation, IdP docs |
