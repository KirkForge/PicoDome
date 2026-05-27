# Sandbox Hardening Guide

## Overview

IronDome's L3 sandbox provides kernel-level isolation for running untrusted commands. This document describes the security boundaries, hardening options, and what IronDome does **not** protect against.

## Security boundary

```
┌─────────────────────────────────────────────┐
│              IronDome Sandbox                │
│                                             │
│  seccomp-bpf ──► Syscall filter (deny-by-default)  │
│  seatbelt    ──► macOS sandbox-exec         │
│  subprocess  ──► Process monitoring fallback │
│                                             │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
│  │ Network │  │Filesystem│  │  Process   │  │
│  │  filter │  │  filter  │  │  filter    │  │
│  └─────────┘  └──────────┘  └───────────┘  │
└─────────────────────────────────────────────┘
```

## Hardening layers

### Layer 1: Seccomp profiles

IronDome ships a default seccomp profile (`deploy/security/irondome-seccomp.json`) that:

- **Default action**: `SCMP_ACT_ERRNO` (deny-by-default)
- **Allowed syscalls**: Only the minimum required for Python runtime, networking, and file I/O
- **Denied syscalls**: `ptrace`, `mount`, `umount2`, `reboot`, `clock_settime`, `module_load`, `pivot_root`, `clone` with `CLONE_NEW*` flags

To use the custom profile in Kubernetes:

```yaml
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: irondome/irondome-seccomp.json
```

Install the profile on nodes via DaemonSet or node initialization scripts.

### Layer 2: AppArmor profiles

IronDome ships an AppArmor profile (`deploy/security/irondome-apparmor.yaml`) that:

- Restricts file access to IronDome data directories
- Allows only TCP/UDP networking
- Denies dangerous capabilities (`sys_admin`, `sys_ptrace`, `net_admin`)
- Denies ptrace (anti-debugging)

To use in Kubernetes:

```yaml
spec:
  securityContext:
    appArmorProfile:
      type: Localhost
      localhostProfile: irondome
```

### Layer 3: Network policies

IronDome ships a strict network policy (`deploy/security/irondome-networkpolicy-strict.yaml`) that:

- Restricts ingress to only kube-system and monitoring namespaces
- Restricts egress to DNS (53), HTTPS (443), and same-namespace
- Prevents lateral movement to other workloads

### Layer 4: Container security context

The Helm chart enforces:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

## Threat assumptions

IronDome's sandbox **assumes**:

1. The host kernel is not compromised (seccomp is a kernel feature)
2. The Kubernetes node is not compromised (node-level access bypasses container isolation)
3. The operator correctly configures security contexts and network policies
4. cert-manager or manual TLS rotation prevents MITM on the webhook
5. The policy signing key is not compromised

IronDome's sandbox **does not protect against**:

1. Kernel exploits that bypass seccomp (0-days in the kernel)
2. Node-level compromise (container escape via container runtime bugs)
3. Side-channel attacks (Spectre/Meltdown class)
4. Supply-chain attacks on IronDome itself (mitigated by SLSA/Sigstore)
5. Misconfigured cluster permissions (admin access to IronDome namespace)

## Recommended hardening checklist

For production deployment:

- [ ] Install custom seccomp profile on all worker nodes
- [ ] Install AppArmor profile on all worker nodes
- [ ] Apply strict network policies
- [ ] Enable mTLS for daemon communication
- [ ] Enable policy signing with Kubernetes Secret-mounted key
- [ ] Set `enterprise.enabled: true` in Helm values
- [ ] Configure `webhook.failurePolicy: Fail` in production
- [ ] Set resource requests and limits on all containers
- [ ] Enable PodDisruptionBudget with `minAvailable: 1`
- [ ] Configure HPA for production load
- [ ] Set up Prometheus alerting for certificate expiry
- [ ] Restrict RBAC to minimum required permissions
- [ ] Run the malicious workload test corpus (`IRONDOME_SANDBOX_TESTS=1 pytest tests/test_malicious_workloads.py`)

## External security validation

IronDome recommends the following for enterprise deployments:

1. **External penetration test** of the admission webhook and sandbox
2. **Red team exercise** targeting the L3 sandbox boundary
3. **Kernel CVE monitoring** for seccomp-bpf and container runtime
4. **Regular audit** of policy changes and enforcement decisions

## Filesystem restrictions

IronDome containers run with `readOnlyRootFilesystem: true`. Writable paths are:

| Path | Purpose | Backed by |
|---|---|---|
| `/home/irondome/.irondome` | Scan results, audit logs | PVC |
| `/tmp` | Temporary files (if needed) | tmpfs (emptyDir) |
| `/tls` | TLS certificates | Secret mount (readOnly) |
| `/etc/irondome/keys` | Policy signing keys | Secret mount (readOnly) |
