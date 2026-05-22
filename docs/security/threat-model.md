# Security: Threat Model

## Overview

Iron Dome is a deterministic runtime sandbox and behavioral analysis tool for supply-chain security. It executes commands under kernel-level policy (L3) and then profiles the behavior (L4) to detect malicious activity that static analysis misses.

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

## Attack Surfaces

### 1. L3 Sandbox Escape

**Risk:** A sandboxed command escapes the kernel-level policy.

**Mitigations:**
- seccomp-bpf: Kernel-enforced, process killed on violation (SIGSYS)
- seatbelt: macOS sandbox-exec, kernel-enforced
- subprocess: Pattern analysis fallback (no kernel enforcement)
- Default policy: deny-by-default with explicit allows

**Residual risk:** Kernel vulnerabilities in seccomp-bpf implementation. This is outside Iron Dome's control and should be reported to the Linux kernel security team.

### 2. L4 Behavioral Analysis Bypass

**Risk:** Malicious behavior that doesn't trigger any L4 detector rule.

**Mitigations:**
- 5 detector rules covering timing, exfiltration, entropy, honeypot, and baseline drift
- Baseline comparison catches unknown-but-anomalous patterns
- Regular rule additions expand coverage

**Residual risk:** Novel attack patterns not covered by existing rules. This is expected — L4 is a heuristic layer, not a complete solution.

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
- A deterministic runtime sandbox for supply-chain verification
- A behavioral profiler for post-execution analysis
- A companion to PicoSentry (static scan → runtime sandbox)
- A CI/CD gate for automated security verification