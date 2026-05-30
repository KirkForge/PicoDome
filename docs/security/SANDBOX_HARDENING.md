# Sandbox Hardening Guide

## Overview

PicoDome's L3 sandbox provides **syscall policy enforcement** for running untrusted commands. This document describes the security boundaries, hardening options, and what PicoDome does **not** protect against.

> **Important:** PicoDome's seccomp-bpf backend is a **syscall policy harness**, not a full containment boundary. It filters syscalls at the kernel level (real enforcement), but does not provide namespace/mount/filesystem isolation, privilege dropping, or resource limits. See §Seccomp limitations for details.

## Security boundary

```
┌─────────────────────────────────────────────┐
│              PicoDome Sandbox                │
│                                             │
│  seccomp-bpf ──► Syscall policy (deny-by-default)   │
│  seatbelt    ──► macOS sandbox-exec         │
│  subprocess  ──► Process monitoring fallback │
│                                             │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
│  │ Network │  │Filesystem│  │  Process   │  │
│  │  filter │  │  filter  │  │  filter    │  │
│  └─────────┘  └──────────┘  └───────────┘  │
│                                             │
│  NOT provided:                              │
│  ✗ Namespace/mount isolation                 │
│  ✗ PR_SET_NO_NEW_PRIVS                      │
│  ✗ setrlimit / cgroups                      │
│  ✗ Chroot / pivot_root                      │
└─────────────────────────────────────────────┘
```

## Seccomp-bpf limitations

The seccomp-bpf backend provides real kernel-level syscall filtering, but it has important boundaries:

1. **No filesystem isolation**: A process with `open`/`write` in the safe set can read `~/.ssh/id_*`, `~/.aws/credentials`, `.npmrc` tokens, and write anywhere the invoking user can. Seccomp filters syscalls, not paths. Use `bubblewrap`/`gVisor` for filesystem containment.

2. **No namespace isolation**: No mount, PID, network, or user namespaces. The sandboxed process shares the host's filesystem tree and network stack.

3. **No `PR_SET_NO_NEW_PRIVS`**: The seccomp filter is installed without `prctl(PR_SET_NO_NEW_PRIVS)`, so the filter is not guaranteed to survive `execve` in all kernel configurations.

4. **No resource limits**: No `setrlimit` or `cgroups` integration. A fork bomb, memory bomb, or file descriptor exhaustion in the sandbox affects the host.

5. **Default-deny kills silently**: Processes killed by `SIGSYS` (seccomp violation) produce no diagnostic. For actionable error messages, use `SCMP_ACT_ERRNO(EPERM)` for non-fatal denials. PicoDome defines `SCMP_ACT_ERRNO_EPERM` as a constant for this purpose, but default-deny policies still use `KILL_PROCESS`.

6. **Safe set omits process-spawning syscalls**: `_SAFE_SYSCALLS` does not include `clone`, `clone3`, `fork`, `vfork`, `wait4`, or `socket`. Default-deny policies will kill `npm install`, `pip install`, and most package managers on their first `clone3` call. Use `--allow-runtime node` or per-runtime profiles for these workloads.

### Composing with full containment

For safe execution of truly untrusted packages, compose PicoDome with:

- **User namespaces + `bubblewrap`**: Filesystem, PID, and network isolation
- **`gVisor`**: Kernel-level sandboxing with comprehensive syscall filtering
- **Container runtimes (Docker/Podman)**: Mount and PID isolation with resource limits
- **`setrlimit` / `cgroups`**: Memory, CPU, and file descriptor limits

Example: PicoDome + bubblewrap:
```bash
bwrap --unshare-all --dev /dev --ro-bind /usr /usr --tmpfs /tmp \
  -- picodome pipeline --allow-runtime node npm install some-package
```

## Hardening layers

### Layer 1: Seccomp profiles

PicoDome ships a default seccomp profile (`deploy/security/picodome-seccomp.json`) that:

- **Default action**: `SCMP_ACT_ERRNO` (deny-by-default)
- **Allowed syscalls**: Only the minimum required for Python runtime, networking, and file I/O
- **Denied syscalls**: `ptrace`, `mount`, `umount2`, `reboot`, `clock_settime`, `module_load`, `pivot_root`, `clone` with `CLONE_NEW*` flags

To use the custom profile in Kubernetes:

```yaml
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: picodome/picodome-seccomp.json
```

Install the profile on nodes via DaemonSet or node initialization scripts.

### Layer 2: AppArmor profiles

PicoDome ships an AppArmor profile (`deploy/security/picodome-apparmor.yaml`) that:

- Restricts file access to PicoDome data directories
- Allows only TCP/UDP networking
- Denies dangerous capabilities (`sys_admin`, `sys_ptrace`, `net_admin`)
- Denies ptrace (anti-debugging)

To use in Kubernetes:

```yaml
spec:
  securityContext:
    appArmorProfile:
      type: Localhost
      localhostProfile: picodome
```

### Layer 3: Network policies

PicoDome ships a strict network policy (`deploy/security/picodome-networkpolicy-strict.yaml`) that:

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

PicoDome's sandbox **assumes**:

1. The host kernel is not compromised (seccomp is a kernel feature)
2. The Kubernetes node is not compromised (node-level access bypasses container isolation)
3. The operator correctly configures security contexts and network policies
4. cert-manager or manual TLS rotation prevents MITM on the webhook
5. The policy signing key is not compromised

PicoDome's sandbox **does not protect against**:

1. Kernel exploits that bypass seccomp (0-days in the kernel)
2. Node-level compromise (container escape via container runtime bugs)
3. Side-channel attacks (Spectre/Meltdown class)
4. Host filesystem access by processes with `open`/`write` in the safe set
5. Resource exhaustion (fork bombs, memory bombs) without external `setrlimit`/`cgroups`
6. Misconfigured cluster permissions (admin access to PicoDome namespace)

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
- [ ] **Compose with `bubblewrap` or `gVisor` for full containment** when executing truly untrusted packages
- [ ] **Use `--allow-runtime node` or per-runtime profiles** for default-deny policies with package managers

## External security validation

PicoDome recommends the following for enterprise deployments:

1. **External penetration test** of the admission webhook and sandbox
2. **Red team exercise** targeting the L3 sandbox boundary
3. **Kernel CVE monitoring** for seccomp-bpf and container runtime
4. **Regular audit** of policy changes and enforcement decisions
5. **Containment assessment** — verify that composed isolation (seccomp + bwrap/gVisor) actually contains test payloads before relying on it

## Filesystem restrictions

PicoDome containers run with `readOnlyRootFilesystem: true`. Writable paths are:

| Path | Purpose | Backed by |
|---|---|---|
| `/home/picodome/.picodome` | Scan results, audit logs | PVC |
| `/tmp` | Temporary files (if needed) | tmpfs (emptyDir) |
| `/tls` | TLS certificates | Secret mount (readOnly) |
| `/etc/picodome/keys` | Policy signing keys | Secret mount (readOnly) |
