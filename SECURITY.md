# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

IronDome is pre-1.0. Only the latest release receives security fixes.

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, open a private vulnerability report on GitHub:
https://github.com/KirkForge/IronDome/security/advisories/new

Include:
- IronDome version (`irondome version`)
- Python version and OS
- Sandbox backend in use (`seccomp-bpf`, `seatbelt`, or `subprocess`)
- Description of the vulnerability
- Steps to reproduce
- Potential impact (e.g., "could allow L3 sandbox escape via seccomp bypass")

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix or mitigation**: depends on severity

### Disclosure Policy

- **Coordinated disclosure**: we ask for 90 days before public disclosure
- **Credit**: researchers receive credit in the changelog and advisory unless they request anonymity
- **Advisories**: published as GitHub Security Advisories and in CHANGELOG.md

## Determinism Vulnerabilities

IronDome's core thesis is deterministic sandboxing: **same command + same policy = same output, every time**.

If you find a case where IronDome produces different results on identical inputs (same command, same policy, same target — without any code or corpus changes), that is a **high-severity bug**, even if no security finding is missed. Report it through the same channel.

Verify determinism with:
```bash
irondome sandbox python3 -c "print('hello')" --format json -o a.json
irondome sandbox python3 -c "print('hello')" --format json -o b.json
irondome diff a.json b.json
# Should output: "✓ Results are IDENTICAL — determinism verified"
```

Or use the built-in verification:
```bash
irondome sandbox python3 -c "print('hello')" --verify-determinism
# Should output: "✓ DETERMINISM VERIFIED — results are deterministic"
```

## L3 Sandbox Escape Reporting

IronDome's L3 sandbox provides kernel-level enforcement on Linux (seccomp-bpf) and macOS (seatbelt), with a universal subprocess fallback. If you discover a way to **escape the sandbox policy** — i.e., a sandboxed command performs an action that should have been denied — report it immediately.

Include in your report:
- Which backend was active (`seccomp-bpf`, `seatbelt`, or `subprocess`)
- The policy in use (default, strict, node, python, or custom JSON)
- The exact command that escaped
- The action that should have been denied (network call, file write, process spawn, etc.)
- Sandbox output showing the escape (`--format json` preferred)

Known limitations:
- **Subprocess backend**: post-hoc pattern analysis only — cannot prevent violations, only detect them. This is by design and documented. Use `seccomp-bpf` or `seatbelt` for real enforcement.
- **seccomp-bpf**: kernel-level enforcement, but syscalls not in the filter are allowed by default allowlist. New Linux kernel syscalls may not be covered.
- **seatbelt**: macOS sandbox-exec profiles have known edge cases around `/tmp` and inherited file descriptors.

## L4 Behavioral Analysis Bypass Reporting

L4 detectors analyze behavioral profiles for anomalies. If you find a way to **evade detection** by any of the 5 built-in L4 rules, report it:

| Rule | What It Detects | Bypass Example |
|------|----------------|----------------|
| L4-TIME | Anomalous timing, no-ops, busy-wait | Legitimate fast execution that triggers false positive |
| L4-EXFIL | Data exfiltration, suspicious DNS, credential theft | Exfiltration via allowed domains or timing channels |
| L4-ENTROPY | High-entropy filenames, DGA domains | Encoded payloads below entropy threshold |
| L4-HONEY | Honeypot path access, priv-esc binaries | Access via symlinks or indirect paths |
| L4-BASE | Baseline drift from known-good profiles | Gradual drift below detection threshold |

Include in your report:
- Which L4 rule was bypassed
- The behavioral profile that evaded detection
- The expected finding vs. actual result
- Suggested detection improvement (if any)

## Release Integrity

Every IronDome release is signed with Sigstore. Verify any release artifact:

```bash
./scripts/verify_release.sh v0.3.0
```

This confirms the artifact was built in CI by the `release.yml` workflow and has not been tampered with.

## Supply Chain

IronDome has **zero hard runtime dependencies**. The only dependencies are:
- `libseccomp` (optional — Linux seccomp-bpf backend, loaded via ctypes at runtime)
- `pytest` / `pytest-cov` / `mypy` / `ruff` (dev only)

The Python standard library provides everything else. This minimal attack surface is by design. We will not add runtime dependencies without strong justification.

## Threat Model Summary

### What IronDome Protects Against

| Threat | L3 Sandbox | L4 Behavioral | Example |
|--------|------------|---------------|---------|
| Malicious post-install scripts | ✅ Block network/file/spawn | ✅ Detect exfiltration | `npm install` with data theft |
| Dependency confusion with dynamic payloads | ✅ Block outbound network | ✅ Detect DNS exfiltration | Package phones home after install |
| Obfuscated eval chains | ✅ Detect in post-hoc output | ✅ Detect timing anomalies | `eval(atob(...))` in postinstall |
| Supply-chain worms | ✅ Block network/spawn | ✅ Detect propagation patterns | Self-replicating malicious package |
| Credential theft | ✅ Block sensitive file access | ✅ Detect honeypot touches | Reading `~/.ssh/id_rsa` |
| Crypto mining | ⚠️ Hard to block (CPU-bound) | ✅ Detect timing anomalies | Infinite loop / busy-wait patterns |

### What IronDome Does NOT Protect Against

| Threat | Why | Mitigation |
|--------|-----|------------|
| Kernel exploits | Sandbox runs in same kernel | Use VMs or containers for isolation |
| Side-channel attacks | Timing, cache, etc. beyond scope | Hardware-level mitigations |
| Subprocess backend evasion | Post-hoc only, no prevention | Use seccomp-bpf or seatbelt backend |
| Supply-chain attacks on IronDome itself | Self-referential | Verify with Sigstore + SLSA |
| Zero-day runtime exploits | Unknown vulnerabilities | Defense in depth with PicoSentry |

### Trust Boundaries

```
┌──────────────────────────────────────┐
│  IronDome User (Trusted)             │
│  - Defines sandbox policy            │
│  - Chooses backend & L4 rules        │
├──────────────────────────────────────┤
│  IronDome (Trusted Computing Base)    │
│  - L3 engine + backends              │
│  - L4 engine + detector rules        │
│  - Deterministic guard stack          │
│  - Sigstore-verified release          │
├──────────────────────────────────────┤
│  Target Command (Untrusted)           │
│  - Runs under sandbox policy          │
│  - Profiled by L4 detectors          │
│  - Cannot influence IronDome output   │
└──────────────────────────────────────┘
```

## SCAAT Attestation

[SCAAT.md](SCAAT.md) provides a full mapping of L3 and L4 detection rules to supply-chain attack vectors and MITRE ATT&CK techniques. If you believe a rule has a false negative, include the SCAAT vector reference in your report.