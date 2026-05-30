# SCAAT — Supply Chain Attacks and Threats Attestation

**Project:** PicoDome v0.5.0  
**Date:** 2026-05-22  
**Format:** [SCAAT v1.0](https://github.com/ossf/scaat)  
**Attested by:** KirkForge  

---

## Overview

PicoDome attests to detecting **27 rule types** across **L3 sandbox enforcement** and **L4 behavioral analysis**, covering supply-chain attack vectors in npm/Python ecosystems. This document maps each rule to the attack vector it addresses, the MITRE ATT&CK technique, the supply-chain vector, and the detection method.

---

## L3 Sandbox Enforcement Rules

### L3-SUS-001: Dynamic Code Execution

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-001 |
| **Rule Name** | Dynamic Code Execution |
| **MITRE ATT&CK Tactic** | Execution |
| **MITRE ATT&CK Technique** | T1059 — Command and Scripting Interpreter |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — obfuscated eval/exec chains |
| **Detection Method** | Regex pattern matching on stdout/stderr for `eval()`, `exec()`, `compile()` |

Detects dynamic code execution patterns that indicate a package is interpreting strings as code at runtime — a common technique in malicious post-install scripts.

---

### L3-SUS-002: Shell Execution

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-002 |
| **Rule Name** | Shell Execution |
| **MITRE ATT&CK Tactic** | Execution |
| **MITRE ATT&CK Technique** | T1059.004 — Command and Scripting Interpreter: Unix Shell |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — subprocess/os.system spawning |
| **Detection Method** | Regex pattern matching for `subprocess`, `os.system`, `os.popen`, `commands.getoutput` |

Detects shell command execution that may be used to download and run additional payloads or perform system modifications.

---

### L3-SUS-003: Sensitive File Access

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-003 |
| **Rule Name** | Sensitive File Access |
| **MITRE ATT&CK Tactic** | Credential Access |
| **MITRE ATT&CK Technique** | T1003 — OS Credential Dumping; T1552 — Unsecured Credentials |
| **Supply-chain Vector** | AV-11: Credential/Secret Exposure — reading `/etc/passwd`, `/etc/shadow` |
| **Detection Method** | Regex pattern matching for `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` |

Detects attempts to read system credential files — a strong indicator of credential theft or reconnaissance.

---

### L3-SUS-004: Network Tool Usage

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-004 |
| **Rule Name** | Network Tool Usage |
| **MITRE ATT&CK Tactic** | Command and Control |
| **MITRE ATT&CK Technique** | T1071 — Application Layer Protocol; T1105 — Ingress Tool Transfer |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — downloading additional payloads |
| **Detection Method** | Regex pattern matching for `curl`, `wget`, `nc`, `netcat`, `telnet` |

Detects use of network download tools that may be used to fetch additional malicious payloads or establish C2 channels.

---

### L3-SUS-005: Permission Escalation

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-005 |
| **Rule Name** | Permission Escalation |
| **MITRE ATT&CK Tactic** | Privilege Escalation |
| **MITRE ATT&CK Technique** | T1548 — Abuse Elevation Control Mechanism |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — chmod +x or chmod 777 |
| **Detection Method** | Regex pattern matching for `chmod +x`, `chmod 777` |

Detects file permission modifications that indicate an attempt to make files executable or world-writable.

---

### L3-SUS-006: Base64 Decoding

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-006 |
| **Rule Name** | Base64 Decoding |
| **MITRE ATT&CK Tactic** | Defense Evasion |
| **MITRE ATT&CK Technique** | T1140 — Deobfuscate/Decode Files or Information |
| **Supply-chain Vector** | AV-04: Code Obfuscation — base64-encoded payloads decoded at runtime |
| **Detection Method** | Regex pattern matching for `base64 ... decode`, `base64 -d` |

Detects base64 decoding that may be used to deobfuscate hidden payloads — a common technique in obfuscated malicious scripts.

---

### L3-SUS-007: Destructive Commands

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-007 |
| **Rule Name** | Destructive Commands |
| **MITRE ATT&CK Tactic** | Impact |
| **MITRE ATT&CK Technique** | T1485 — Data Destruction; T1561 — Disk Wipe |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — destructive payload execution |
| **Detection Method** | Regex pattern matching for `rm -rf /`, `dd if=/dev` |

Detects destructive commands that could wipe data or filesystems. Triggers `KILL` verdict (process termination).

---

### L3-SUS-008: Process Introspection

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-008 |
| **Rule Name** | Process Introspection |
| **MITRE ATT&CK Tactic** | Discovery |
| **MITRE ATT&CK Technique** | T1082 — System Information Discovery; T1057 — Process Discovery |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — sandbox/environment detection |
| **Detection Method** | Regex pattern matching for `/proc/self`, `ptrace`, `process_vm_readv` |

Detects process introspection that may be used to discover the sandbox environment or read process memory.

---

### L3-SUS-009: SSH Key Access

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-009 |
| **Rule Name** | SSH Key Access |
| **MITRE ATT&CK Tactic** | Credential Access |
| **MITRE ATT&CK Technique** | T1552.004 — Unsecured Credentials: Private Keys |
| **Supply-chain Vector** | AV-11: Credential/Secret Exposure — reading SSH private keys |
| **Detection Method** | Regex pattern matching for `.ssh/`, `id_rsa`, `id_ed25519`, `authorized_keys` |

Detects attempts to access SSH keys and credentials — a primary target for supply-chain credential theft.

---

### L3-SUS-010: Dotfile Access

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SUS-010 |
| **Rule Name** | Dotfile Access |
| **MITRE ATT&CK Tactic** | Credential Access; Discovery |
| **MITRE ATT&CK Technique** | T1552 — Unsecured Credentials; T1083 — File and Directory Discovery |
| **Supply-chain Vector** | AV-11: Credential/Secret Exposure — reading user dotfiles for credentials |
| **Detection Method** | Regex pattern matching for `/root/`, `/home/*/.*` patterns |

Detects access to user dotfiles that may contain credentials, configuration secrets, or environment variables.

---

### L3-SECCOMP-KILL: Seccomp Syscall Violation

| Field | Value |
|-------|-------|
| **Rule ID** | L3-SECCOMP-KILL |
| **Rule Name** | Seccomp Syscall Violation |
| **MITRE ATT&CK Tactic** | Execution; Defense Evasion |
| **MITRE ATT&CK Technique** | T1106 — Native API; T1562 — Impair Defenses |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — attempted syscall that violates sandbox policy |
| **Detection Method** | Kernel-level seccomp-bpf enforcement (Linux only). Process is killed by SIGSYS. |

Detects processes that attempt blocked syscalls under seccomp-bpf enforcement. This is real kernel-level enforcement, not pattern matching — the process is terminated by the kernel.

---

### L3-TIMEOUT-001: Process Timeout

| Field | Value |
|-------|-------|
| **Rule ID** | L3-TIMEOUT-001 |
| **Rule Name** | Process Timeout |
| **MITRE ATT&CK Tactic** | Impact |
| **MITRE ATT&CK Technique** | T1499 — Endpoint Denial of Service |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — infinite loops, crypto mining, resource exhaustion |
| **Detection Method** | Wall-time timeout enforcement across all backends |

Detects processes that exceed the configured wall-time limit. Triggers `KILL` verdict (process termination).

---

## L4 Behavioral Analysis Rules

### L4-TIME: Timing Anomaly Detection

| Field | Value |
|-------|-------|
| **Rule ID** | L4-TIME (001/002/003) |
| **Rule Name** | Timing Anomaly Detection |
| **MITRE ATT&CK Tactic** | Defense Evasion; Impact |
| **MITRE ATT&CK Technique** | T1497.003 — Time-Based Evasion; T1499 — Endpoint Denial of Service |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — crypto mining, sleep-based evasion, busy-wait |
| **Detection Method** | Behavioral profiling — compares execution timing against expected baselines. Detects no-ops (<5ms), busy-waits (>60s), and timing drift from baselines. |

Sub-rules:
- **L4-TIME-001** (MEDIUM): Execution completed in <5ms — possible no-op or sandbox escape
- **L4-TIME-002** (MEDIUM): Single timing point >60s — potential busy-wait or sleep
- **L4-TIME-003** (HIGH): Timing drift from known baseline — behavioral deviation

---

### L4-EXFIL: Data Exfiltration Detection

| Field | Value |
|-------|-------|
| **Rule ID** | L4-EXFIL (001/002/003/004/005) |
| **Rule Name** | Data Exfiltration Detection |
| **MITRE ATT&CK Tactic** | Exfiltration; Command and Control |
| **MITRE ATT&CK Technique** | T1041 — Exfiltration Over C2 Channel; T1071 — Application Layer Protocol; T1567 — Exfiltration Over Web Service |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — data exfiltration, DNS tunneling, credential theft |
| **Detection Method** | Behavioral profiling — monitors network calls, DNS queries, and file operations. Detects suspicious TLDs, non-standard ports, large outbound transfers, suspicious DNS, and credential exfiltration patterns. |

Sub-rules:
- **L4-EXFIL-001** (HIGH): Network call to suspicious TLD (.xyz, .tk, .ml, .cf, .top, .pw, .cc)
- **L4-EXFIL-002** (MEDIUM): Network call to non-standard port on external IP
- **L4-EXFIL-003** (HIGH): Large outbound data transfer (>1MB)
- **L4-EXFIL-004** (MEDIUM): DNS query to suspicious domain
- **L4-EXFIL-005** (CRITICAL): Sensitive file reads followed by network calls — credential exfiltration

---

### L4-ENTROPY: Entropy Anomaly Detection

| Field | Value |
|-------|-------|
| **Rule ID** | L4-ENTROPY (001/002) |
| **Rule Name** | Entropy Anomaly Detection |
| **MITRE ATT&CK Tactic** | Command and Control; Defense Evasion |
| **MITRE ATT&CK Technique** | T1071.004 — DNS; T1027 — Obfuscated Files or Information |
| **Supply-chain Vector** | AV-04: Code Obfuscation — DGA domains, encoded payloads, random filenames |
| **Detection Method** | Shannon entropy calculation on filenames and DNS hostnames. Detects high-entropy strings indicative of encoded/encrypted payloads or DGA-based C2. |

Sub-rules:
- **L4-ENTROPY-001** (MEDIUM): High-entropy filename (>4.5 bits, >10 chars) — possible encoded payload
- **L4-ENTROPY-002** (HIGH): High-entropy DNS query (>3.5 bits, >20 char subdomain) — possible DGA or encoded C2

---

### L4-HONEY: Honeypot Touch Detection

| Field | Value |
|-------|-------|
| **Rule ID** | L4-HONEY (001/002) |
| **Rule Name** | Honeypot Touch Detection |
| **MITRE ATT&CK Tactic** | Credential Access; Privilege Escalation |
| **MITRE ATT&CK Technique** | T1552 — Unsecured Credentials; T1548 — Abuse Elevation Control Mechanism |
| **Supply-chain Vector** | AV-03: Malicious Post-Install Scripts — accessing files no package should touch |
| **Detection Method** | Behavioral profiling — monitors filesystem operations and process spawns. Detects access to honeypot paths (sensitive system files) and privilege escalation binaries (sudo, su, pkexec, doas). |

Sub-rules:
- **L4-HONEY-001** (CRITICAL): Honeypot path accessed (e.g., `/etc/passwd`, `/etc/shadow`, `/root/.ssh`, `/etc/ssl/private`)
- **L4-HONEY-002** (CRITICAL): Privilege escalation binary spawned (sudo, su, pkexec, doas, chown, chmod)

---

### L4-BASE: Baseline Drift Detection

| Field | Value |
|-------|-------|
| **Rule ID** | L4-BASE (001/002/003) |
| **Rule Name** | Baseline Drift Detection |
| **MITRE ATT&CK Tactic** | Multiple (depends on drift type) |
| **MITRE ATT&CK Technique** | Multiple — detects behavioral deviation from known-good profiles |
| **Supply-chain Vector** | All vectors — detects any behavioral deviation from established baselines |
| **Detection Method** | Behavioral profiling — compares observed behavior against shipped baselines (`npm-install`, `python-pip-install`, `node-script`, `python-script`, `curl-wget`). Scores network, DNS, filesystem, spawn, and timing drift. |

Sub-rules:
- **L4-BASE-001** (INFO): No baseline match found for package
- **L4-BASE-002** (CRITICAL): Severe baseline drift (≥80%) from known-good profile
- **L4-BASE-003** (MEDIUM): Moderate baseline drift (≥40%) from known-good profile

---

## Coverage Summary

### By Attack Vector

| Attack Vector | L3 Rules | L4 Rules | Max Severity |
|--------------|----------|----------|-------------|
| AV-03: Malicious Post-Install Scripts | SUS-001, SUS-002, SUS-005, SUS-007, SUS-008 | TIME, EXFIL, HONEY, BASE | CRITICAL |
| AV-04: Code Obfuscation | SUS-006 | ENTROPY | HIGH |
| AV-11: Credential/Secret Exposure | SUS-003, SUS-009, SUS-010 | EXFIL, HONEY | CRITICAL |
| AV-02: Dependency Confusion | — | EXFIL, BASE | HIGH |
| C2: Command and Control | SUS-004 | EXFIL, ENTROPY | CRITICAL |
| Impact: Resource Exhaustion | TIMEOUT | TIME | HIGH |
| Defense Evasion | SECCOMP-KILL | TIME, ENTROPY | CRITICAL |
| Privilege Escalation | SUS-005 | HONEY | CRITICAL |

### By MITRE ATT&CK Tactic

| Tactic | L3 Rules | L4 Rules |
|--------|----------|----------|
| Execution | SUS-001, SUS-002, SECCOMP-KILL | — |
| Credential Access | SUS-003, SUS-009, SUS-010 | EXFIL, HONEY |
| Command and Control | SUS-004 | EXFIL, ENTROPY |
| Defense Evasion | SUS-006, SECCOMP-KILL | TIME, ENTROPY |
| Privilege Escalation | SUS-005 | HONEY |
| Discovery | SUS-008, SUS-010 | — |
| Impact | SUS-007, TIMEOUT | TIME |
| Exfiltration | — | EXFIL |

### By L3 Backend

| Rule | seccomp-bpf (Linux) | seatbelt (macOS) | subprocess (Universal) |
|------|---------------------|-------------------|------------------------|
| SUS-001 through SUS-010 | ✅ Post-hoc + kernel | ✅ Post-hoc + kernel | ✅ Post-hoc only |
| SECCOMP-KILL | ✅ Kernel enforcement | — | — |
| TIMEOUT | ✅ Kill process | ✅ Kill process | ✅ Kill process |

> **Note:** The subprocess backend can only *detect* suspicious patterns in output, not *prevent* them. For real enforcement, use seccomp-bpf (Linux) or seatbelt (macOS).

---

## Attestation Statement

PicoDome v0.5.0 attests to detecting the supply-chain attack vectors listed above with the stated severity levels. L3 sandbox enforcement is deterministic (same command + same policy = same events, every time) on the subprocess backend. L4 behavioral analysis is deterministic (same profile + same baselines = same findings, every time). The seccomp-bpf and seatbelt backends provide real kernel-level enforcement; the subprocess backend provides post-hoc detection only.

All detections are behavioral and deterministic. No network calls during analysis. Same inputs + same policy/baselines = same output, every time.

This attestation is regenerated for each release. The SCAAT format (v1.0) maps rules → attack vectors → evidence, enabling enterprise security teams to evaluate coverage against their threat model.

```
Signed: KirkForge
Date:   2026-05-22
Version: picodome@0.5.0
Hash:   sha256 of this file committed to the repo
```