# Policy Governance

IronDome's policy governance covers the lifecycle of sandbox policies, security rules, and behavioral detection thresholds. This document defines the approval process, signing requirements, break-glass procedures, and migration guidance.

## Policy lifecycle

```
Draft → Review → Approve → Sign → Deploy → Monitor → Retire
```

### 1. Draft

Policies are YAML files in the repository under `src/irondome/l3/policy/` and `src/irondome/l4/rules/`.

- Each policy has a `name`, `description`, and `version` field
- Policies must be accompanied by a `CHANGELOG` entry describing the change
- New rules should include test cases in `tests/`

### 2. Review

All policy changes require:

- **Code review** by at least one other contributor
- **Security review** for changes that modify enforcement behavior
- **Impact analysis**: What workloads will be affected?

### 3. Approve

Policy changes are approved through the standard PR process:

- Minor changes (threshold adjustments, new detection rules): Single reviewer
- Major changes (new deny rules, policy restructuring): Two reviewers including security-focused
- Emergency changes: See [Break-glass procedure](#break-glass-procedure)

### 4. Sign

Policies are signed using HMAC-SHA256 with a key managed via Kubernetes Secrets.

```bash
# Sign a policy file
python -m irondome policy-sign --key-file /etc/irondome/keys/key --key-id production policy.yaml

# Verify a policy file
python -m irondome policy-verify --key-file /etc/irondome/keys/key policy.yaml
```

The signing module (`irondome.policy_versioned.signing`) supports:

- **Inline signatures**: Appended to the policy YAML file
- **Companion signatures**: Separate `.sig` file alongside the policy
- **Key rotation**: Multiple key IDs supported via `key_id` field

### 5. Deploy

Policies are deployed through:

- **GitOps**: Policy files in the Helm chart's ConfigMap, applied via ArgoCD/Flux
- **Daemon API**: `POST /api/v1/policies` with signed policy payload
- **ConfigMap mount**: Policies loaded from a mounted ConfigMap volume

### 6. Monitor

After deployment:

- Monitor audit log for policy-related events
- Watch for false positives (denied workloads that should be allowed)
- Track baseline drift if behavioral thresholds changed

### 7. Retire

When a policy version is superseded:

- The versioned policy store retains the old version
- Rollback is available via `irondome policy-versions rollback --version N`
- Retired policies are marked `status: retired` and excluded from enforcement

## Policy bundle format

A policy bundle is a directory or tarball containing:

```
policy-bundle/
├── policies/
│   ├── l3-default.yaml          # Sandbox policy
│   ├── l3-default.yaml.sig      # Companion signature
│   ├── l4-rules/
│   │   ├── timing.yaml
│   │   ├── timing.yaml.sig
│   │   ├── entropy.yaml
│   │   └── entropy.yaml.sig
│   └── ...
├── bundle.yaml                  # Bundle metadata
└── CHANGELOG.md
```

The `bundle.yaml` contains:

```yaml
apiVersion: irondome.kirkforge.dev/v1
kind: PolicyBundle
metadata:
  name: production-v2
  version: "2.0.0"
  created: "2026-05-27T00:00:00Z"
  author: "security-team"
  signingKeyId: "production"
spec:
  policies:
    - name: l3-default
      file: policies/l3-default.yaml
      signature: policies/l3-default.yaml.sig
    - name: l4-timing
      file: policies/l4-rules/timing.yaml
      signature: policies/l4-rules/timing.yaml.sig
```

## GitOps approval workflow

### ArgoCD example

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: irondome-policies
  annotations:
    notifications.argoproj.io/subscribe.on-policy-sync.slack: security-alerts
spec:
  source:
    repoURL: https://github.com/org/irondome-policies.git
    path: policies
    targetRevision: main
  syncPolicy:
    automated:
      prune: false
      selfHeal: true
    syncOptions:
      - CreateNamespace=false
    retry:
      limit: 3
```

### Flux example

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: irondome-policies
spec:
  interval: 5m
  path: ./policies
  prune: false
  sourceRef:
    kind: GitRepository
    name: irondome-policies
  validation: client
  healthChecks:
    - apiVersion: apps/v1
      kind: Deployment
      name: irondome
      namespace: irondome
```

## Break-glass procedure

When a policy change is needed urgently (e.g., production-blocking false positive):

1. **Create emergency PR** with `urgency: critical` label
2. **Single-reviewer approval** (security lead or on-call)
3. **Sign and deploy** immediately
4. **Post-incident review** within 24 hours
5. **Backfill** second review within 48 hours

The audit log records all policy changes including emergency ones. Break-glass usage is tracked and reported in compliance evidence.

### Expiring exceptions

If a policy needs a temporary exception:

```yaml
apiVersion: irondome.kirkforge.dev/v1
kind: PolicyException
metadata:
  name: allow-legacy-tool
spec:
  policy: l3-default
  rule: deny-shells
  reason: "Legacy build tool requires shell access during migration (JIRA-1234)"
  owner: "platform-team"
  expires: "2026-07-01T00:00:00Z"
  conditions:
    namespace: build-system
    image: "registry.internal/legacy-builder:*"
```

Expired exceptions are automatically removed by the retention manager and flagged in audit logs.

## Policy version migration

When upgrading policies between major versions:

1. **Review the changelog** for breaking changes
2. **Run in dry-run mode** to identify affected workloads:
   ```bash
   irondome scan --policy new-policy.yaml --dry-run <test-workload>
   ```
3. **Deploy in canary mode** to a subset of namespaces:
   ```yaml
   # In values.yaml:
   webhook:
     namespaceSelector:
       matchExpressions:
         - key: irondome-policy-tier
           operator: In
           values: ["canary"]
   ```
4. **Monitor** for 24 hours in canary namespaces
5. **Roll out** to remaining namespaces
6. **Rollback** if false positive rate exceeds threshold:
   ```bash
   irondome policy-versions rollback --version <previous-version>
   ```

### Version compatibility matrix

| Policy version | IronDome version | Notes |
|---|---|---|
| v1 | 0.3.x–0.4.x | Original policy format |
| v2 | 0.5.x | Added signing, key rotation, companion sigs |
| v3 (planned) | 1.0.x | Bundle format, policy exceptions, approval workflow |

## Audit requirements

Every policy decision and policy update must be auditable:

| Event | Audit fields | Retention |
|---|---|---|
| Policy create | actor, policy_name, version, timestamp | 365 days |
| Policy update | actor, policy_name, old_version, new_version, diff | 365 days |
| Policy rollback | actor, policy_name, target_version, reason | 365 days |
| Policy sign | key_id, algorithm, timestamp | 365 days |
| Policy exception create | actor, rule, reason, expires | 365 days |
| Policy exception expire | rule, owner, timestamp | 365 days |
| Enforcement decision | policy_version, rule, verdict, workload | 90 days |

All audit events are recorded in the hash-chained audit log and queryable via `GET /api/v1/audit`.
