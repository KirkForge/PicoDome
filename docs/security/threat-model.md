# Security: Threat Model

## Overview

Iron Dome is a deterministic runtime sandbox and behavioral analysis tool for supply-chain security. It executes commands under kernel-level **syscall policy** (L3) and then profiles the behavior (L4) to detect malicious activity that static analysis misses.

> **Important scope note:** Iron Dome's seccomp-bpf backend is a **syscall policy harness**, not a full containment boundary. It filters syscalls at the kernel level (real enforcement), but does not provide namespace/mount/filesystem isolation, `prctl(PR_SET_NO_NEW_PRIVS)`, privilege dropping, or `setrlimit`. For safe execution of untrusted packages, compose with user namespaces, `bubblewrap`, or `gVisor`.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     Iron Dome Architecture                    │
│                                                              │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  CLI/API  │───▶│  L3 Sandbox  │───▶│  L4 Behavioral   │  │
│  │  (input)  │    │  (seccomp/   │    │  (profiler +     │  │
│  │           │    │   seatbelt/   │    │   detector rules)│  │
│  │           │    │   subprocess) │    │                  │  │
│  └──────────┘    └──────────────┘    └──────────────────┘  │
│       │                  │                     │             │
│       ▼                  ▼                     ▼             │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Config   │    │  Policy      │    │  Baselines       │  │
│  │ (.yml)   │    │  (deny-by-   │    │  (shipped JSON)  │  │
│  │          │    │   default)    │    │                  │  │
│  └──────────┘    └──────────────┘    └──────────────────┘  │
│                                                              │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Formatters│    │  Guard Stack │    │  License Module   │  │
│  │ (6 output│    │  (4 layers)  │    │  (personal/comm) │  │
│  │  formats)│    │              │    │                  │  │
│  └──────────┘    └──────────────┘    └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## L3 Isolation Levels (Honest Assessment)

| Backend | Isolation Level | Enforcement | What It Prevents | What It Does NOT Prevent |
|---------|----------------|-------------|-----------------|-------------------------|
| **seccomp-bpf** | `syscall_policy` | `moderate` | Syscalls not in the allow-list (kernel kills or errors the process) | Filesystem access to host files (open/write allowed in safe set), namespace escape, privilege escalation, resource exhaustion |
| **seatbelt** | `os_policy_enforced` | `hard` | macOS sandbox-exec policy violations | Host access via allowed paths, network access via allowed protocols |
| **subprocess** | `observational_only` | `best_effort` | Nothing (detection only) | Everything — this backend observes patterns, it does not enforce |

### Seccomp-bpf Specific Limitations

The seccomp-bpf backend provides real kernel-level syscall filtering, but it is important to understand its boundaries:

- **No filesystem isolation**: A process with `open`/`write` in the safe set can read `~/.ssh/id_*`, `~/.aws/credentials`, `.npmrc` tokens, and write anywhere the invoking user can. Seccomp filters syscalls, not paths.
- **No namespace isolation**: No mount, PID, network, or user namespaces. A sandboxed process shares the host's filesystem tree and network stack.
- **No `PR_SET_NO_NEW_PRIVS`**: The seccomp filter is installed without `prctl(PR_SET_NO_NEW_PRIVS)`, meaning the filter is not guaranteed to survive `execve` in all configurations.
- **No `setrlimit`**: No memory, CPU, or file descriptor limits. A fork bomb or memory bomb in the sandbox affects the host.
- **Default-deny kills silently**: Processes killed by `SIGSYS` (seccomp violation) produce no diagnostic. Use `SCMP_ACT_ERRNO(EPERM)` for non-fatal denials to get actionable error messages.
- **Safe set omits common syscalls**: `_SAFE_SYSCALLS` does not include `clone`, `clone3`, `fork`, `vfork`, `wait4`, or `socket`. Default-deny policies will kill `npm install`, `pip install`, and most package managers on their first `clone3` call.

**For full containment**, compose IronDome with:
- User namespaces + `bubblewrap` for filesystem/PID/network isolation
- `gVisor` for kernel-level sandboxing
- Container runtimes (Docker/Podman) for mount/PID isolation
- `setrlimit` / `cgroups` for resource limits

## Attack Surfaces

### 1. L3 Sandbox Escape

**Risk:** A sandboxed command escapes the kernel-level policy.

**Mitigations:**
- seccomp-bpf: Kernel-enforced syscall filtering, process killed on violation (SIGSYS) or errno(EPERM)
- seatbelt: macOS sandbox-exec, kernel-enforced
- subprocess: Pattern analysis fallback (no kernel enforcement)
- Default policy: deny-by-default with explicit allows

**Residual risk:** The seccomp-bpf backend filters syscalls but does not contain the process. A sandboxed process with allowed file I/O syscalls can access host files. Kernel vulnerabilities in seccomp-bpf implementation are outside Iron Dome's control.

### 2. L4 Behavioral Analysis Bypass

**Risk:** Malicious behavior that doesn't trigger any L4 detector rule.

**Mitigations:**
- 5 detector rules covering timing, exfiltration, entropy, honeypot, and baseline drift
- Baseline comparison catches unknown-but-anomalous patterns
- Regular rule additions expand coverage

**Residual risk:** Novel attack patterns not covered by existing rules. L4 is a heuristic layer, not a complete solution.

### 3. Determinism Violation

**Risk:** Non-deterministic output makes results unreproducible.

**Mitigations:**
- 4-layer guard stack (models → guard → diff → CI gate)
- `--verify-determinism` runs twice and compares SHA-256
- `DeterministicGuard` validates invariants after each scan
- CI determinism gate fails on any hash mismatch

**Residual risk:** Timing-dependent behavior in subprocess execution (rare, detected by guard).

### 4. Policy Tampering

**Risk:** Malicious actor modifies the sandbox policy to allow dangerous operations.

**Mitigations:**
- Default policy is deny-by-default
- Policy files are loaded from disk (not network)
- `--policy` flag requires explicit path

**Residual risk:** Local filesystem compromise. Use file integrity monitoring on policy files.

### 5. Baseline Poisoning

**Risk:** Shipped baselines are modified to allow malicious behavior.

**Mitigations:**
- Baselines are shipped with the package (not downloaded)
- JSON format is human-readable and auditable
- Custom baselines require explicit `--baseline` flag

**Residual risk:** Supply-chain attack on Iron Dome itself. Mitigated by Sigstore signing and SLSA provenance.

## Non-Goals

Iron Dome is **not**:
- A full container runtime (use Docker/Podman for full isolation)
- A malware sandbox (use Cuckoo/CAPE for malware analysis)
- A network firewall (use iptables/nftables for network policy)
- A replacement for static analysis (use PicoSentry for static scanning)

Iron Dome **is**:
- A syscall policy harness for supply-chain verification
- A behavioral profiler for post-execution analysis
- A companion to PicoSentry (static scan → runtime sandbox)
- A CI/CD gate for automated security verification

## Per-Backend Compatibility & Coverage

| Backend | Platform | Kernel enforcement | Network filtering | File filtering | Recommended posture |
|---------|----------|-------------------|-------------------|---------------|-------------------|
| seccomp-bpf | Linux | ✅ BPF filter, SIGSYS/EPERM on violation | ✅ connect/accept/socket | ✅ open/openat/write | Production with awareness of limitations |
| seatbelt | macOS | ✅ sandbox-exec, kernel-enforced | ✅ network deny | ✅ file-read/file-write | Production default |
| subprocess | Any | ❌ Pattern analysis only | ⚠️ Observed via output | ⚠️ Observed via output | Last resort / CI detection-only |

**Recommended safe-by-default posture:**

1. Use seccomp (Linux) or seatbelt (macOS) as the primary backend.
2. Treat subprocess fallback as **detection-only** — it cannot prevent violations, only observe them.
3. In enterprise mode, the daemon rejects `observational_only` backends by default.
4. Deny-by-default policy with explicit allows is the only supported policy mode in enterprise.
5. For default-deny policies with package managers, use `--allow-runtime node` or per-runtime profiles to avoid SIGSYS kills on `clone3`/`wait4`.
