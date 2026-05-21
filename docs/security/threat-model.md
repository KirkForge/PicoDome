# Threat model — Iron Dome

Iron Dome is a deterministic runtime sandbox and behavioral analyzer for supply-chain security.

It supports multiple **L3 execution backends**:
- **Linux seccomp** (kernel syscall filtering via libseccomp)
- **macOS seatbelt** (sandbox-exec profile)
- **subprocess fallback** (universal runner + post-hoc detectors)

Enterprise users need clarity on what each backend **guarantees**, what it **does not**, and the recommended safe posture.

## Non-goals

- Iron Dome does **not** claim to fully isolate a malicious process from a compromised host kernel.
- Iron Dome is **not** a VM-based isolation boundary.
- Iron Dome does **not** attempt to safely execute arbitrary malware samples in hostile environments.
- Iron Dome is not intended to be exposed directly to the public internet as a shared multi-tenant service.

## Assets to protect

- Integrity of the **verdict** and evidence (deterministic output).
- Host confidentiality (sensitive files, environment variables, credentials).
- Host integrity (avoid destructive commands, privilege escalation).
- Auditability (prove what ran, with what policy, and what happened).

## Actors

- **Operator**: runs Iron Dome in CI/CD or on a build host.
- **Developer**: submits packages/commands to execute under policy.
- **Attacker**: attempts to exfiltrate secrets, tamper with evidence, or break isolation.

## Trust boundaries

```
┌──────────────────────────────┐
│ Operator / CI workflow       │
│ - chooses command + policy   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Iron Dome runner             │
│ - selects backend            │
│ - applies policy             │
│ - collects evidence          │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Target process               │
│ - untrusted code             │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Host OS / filesystem / net   │
└──────────────────────────────┘
```

**Key boundary:** Iron Dome is a **policy enforcement layer** and evidence collector. The host OS is still in the trust base.

---

## Threats and mitigations

### 1) Secret exfiltration

**Threat:** Untrusted code reads environment variables, SSH keys, config files, or cloud credentials.

**Mitigations:**
- Run with a minimal environment (avoid passing secrets).
- Use least-privilege filesystem mounts; avoid home directory mounts.
- Prefer true enforcement backends (seccomp/seatbelt) where possible.
- Add policy allowlists for paths/commands and deny by default.

### 2) Host tampering / destructive actions

**Threat:** Untrusted code attempts `rm -rf`, modifies dotfiles, changes permissions, or writes to sensitive paths.

**Mitigations:**
- Read-only filesystem where possible.
- Restricted writable directories (tmp/workspace only).
- Policy denies destructive patterns.
- Prefer running in a container/isolated user account.

### 3) Network misuse

**Threat:** Untrusted code performs network calls to exfiltrate data or fetch payloads.

**Mitigations:**
- Run in environments where outbound network is restricted (recommended).
- In subprocess backend, detect common network tooling and flag.
- Document network posture and recommend “network off” for CI runs.

### 4) Evidence tampering / nondeterminism

**Threat:** Output includes timestamps/random IDs or evidence differs run-to-run.

**Mitigations:**
- Frozen models and deterministic sorting.
- CI determinism gate.
- Include policy hash and backend identity in outputs.

---

## Backend-specific guarantees

### A) Linux seccomp backend

**What it gives:**
- Kernel-enforced syscall filtering for the target process.

**Limitations:**
- Does not sandbox filesystem or network by itself.
- Policy quality matters: allow too much, and the process can still do harmful work.

**Recommended posture:**
- Run as non-root.
- Combine with containerization / restricted mounts.

### B) macOS seatbelt backend

**What it gives:**
- OS-level sandbox profile enforcement.

**Limitations:**
- Profiles can be subtle; must test and document the profile model.
- macOS sandbox constraints differ from Linux.

**Recommended posture:**
- Keep profiles minimal and deny-by-default.
- Maintain a compatibility matrix.

### C) Subprocess fallback backend

**What it gives:**
- Universal runner; does not require platform features.
- Post-hoc suspicious pattern detection.

**Limitations:**
- Not a strong isolation boundary.
- Detection is heuristic; cannot prevent syscalls.

**Recommended posture:**
- Treat as a **last resort**.
- Use on locked-down hosts only; do not run with secrets.
- Document that it is detection-only, not enforcement.

---

## Compatibility / coverage matrix (starter)

| Capability | seccomp (Linux) | seatbelt (macOS) | subprocess |
|---|---:|---:|---:|
| Syscall enforcement | ✅ | ✅ | ❌ |
| Filesystem policy | ⚠️ (external) | ⚠️ (profile) | ❌ |
| Network restriction | ⚠️ (external) | ⚠️ (profile) | ❌ |
| Deterministic evidence | ✅ | ✅ | ✅ |

⚠️ = possible but requires additional configuration.

## Recommended safe-by-default posture

- Run Iron Dome on hardened CI runners.
- Do not pass secrets into the sandboxed process.
- Prefer seccomp/seatbelt; use subprocess only as fallback.
- Use deny-by-default policy files and include policy hash in outputs.
- Enable audit logging when running in shared environments.
