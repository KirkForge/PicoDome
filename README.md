![PicoDome Banner](docs/banner.png)

# PicoDome 🛡️

**Deterministic runtime sandbox and behavioral analysis for supply-chain security — protecting machines (especially LLMs) from injection attacks.**

[![CI](https://github.com/KirkForge/PicoDome/actions/workflows/ci.yml/badge.svg)](https://github.com/KirkForge/PicoDome/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/picodome)](https://pypi.org/project/picodome/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-1435%20passing-brightgreen)](https://github.com/KirkForge/PicoDome)
[![Deterministic](https://img.shields.io/badge/deterministic-sha256%20verified-brightgreen)](SCAAT.md)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue)](LICENSE)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support%20my%20hardware-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/kirkforge)

PicoDome is a two-layer defense system for npm/Python supply chains. Companion to [PicoSentry](https://github.com/KirkForge/PicoSentry) — static scan → runtime sandbox. It's designed to protect machines — especially LLMs — from injection attacks embedded in dependencies.

- **L3 Execution Sandbox** — Run any command under kernel-level policy. Real seccomp-bpf (Linux), Seatbelt/sandbox-exec (macOS), or universal subprocess backend.
- **L4 Behavioral Analysis** — Post-execution profiling. Detect exfiltration, timing anomalies, honeypot touches, entropy spikes, and baseline drift.

## Why PicoDome?

Static scanners (PicoSentry, Socket.dev, Snyk) inspect code before it runs. PicoDome **executes** it safely, catching what static analysis misses: dependency confusion with dynamic payloads, post-install data exfiltration, obfuscated eval chains, and supply-chain worms. Especially critical for LLM tool-use pipelines where a malicious dependency can inject prompts, exfiltrate context, or hijack agent behavior.

## Pico Security Series

| Product | Layer | What It Does |
|---------|-------|--------------|
| [PicoSentry](https://github.com/KirkForge/PicoSentry) | L2 | Static supply-chain scanner (21 rules, 1401 tests) |
| **PicoDome** | L3+L4 | Runtime sandbox + behavioral analysis |
| PicoWatch | L5-L7 | LLM prompt/output defense + telemetry |
| PicoShogun | — | Command centre / dashboard |

## Quick Start

```bash
pip install picodome

# L3: Sandbox a command
picodome sandbox python3 -c "print('hello')"

# L3+L4: Full pipeline (auto-detects runtime)
picodome pipeline npm install some-package

# L3+L4: Explicit runtime policy
picodome pipeline --allow-runtime node npm install some-package
picodome sandbox --allow-runtime python pip install some-package

# Analyze existing sandbox output
picodome sandbox --format json npm test > sandbox.json
picodome analyze --input sandbox.json

# List detector rules
picodome rules

# Verify determinism (run twice, compare SHA-256)
picodome sandbox --verify-determinism echo test

# Compare two saved results
picodome diff result_a.json result_b.json

# Workspace scanning (monorepos)
picodome pipeline --workspace /path/to/monorepo
```

> The `picodome` CLI alias still works for backward compatibility.

## L3 Backends

PicoDome auto-detects the best available backend:

| Backend | Platform | Mechanism | Isolation Level | Enforcement |
|---------|----------|-----------|-----------------|-------------|
| **seccomp-bpf** | Linux | Kernel syscall filtering via libseccomp (ctypes), fork+exec | syscall_policy | moderate |
| **seatbelt** | macOS | sandbox-exec with generated profile DSL | os_policy_enforced | hard |
| **subprocess** | Universal | Process isolation with post-hoc pattern analysis | observational_only | best_effort |

**Important**: The subprocess backend is **observational only** — it detects suspicious patterns in output but does not prevent syscalls. It is not a true sandbox.

**Important**: The seccomp-bpf backend is a **syscall policy harness**, not a full containment boundary. It filters syscalls at the kernel level (real enforcement), but does not provide namespace/mount/filesystem isolation, `prctl(PR_SET_NO_NEW_PRIVS)`, privilege dropping, or `setrlimit`. For safe execution of untrusted packages, compose with user namespaces, `bubblewrap`, or `gVisor`. Default-deny policies will kill processes on missing syscalls. Use `--allow-runtime node` or `--allow-runtime python` to select a runtime-appropriate policy, or use `--policy node`/`--policy python` for explicit control. The `pipeline` command auto-detects runtimes (npm/node → node policy, pip/python → python policy).

Use `--backend seccomp-bpf` (or `PICODOME_SANDBOX_BACKEND=seccomp-bpf`) to require a specific backend. If the requested backend is unavailable, PicoDome **fails closed** by default. Use `--allow-degraded` (or `PICODOME_ALLOW_DEGRADED=1`) to opt into subprocess fallback explicitly.

## L3 Suspicious Pattern Detectors

| Rule | Detects |
|------|----------|
| L3-SUS-001 | Dynamic code execution (eval, exec, compile) |
| L3-SUS-002 | Shell execution (subprocess, os.system, os.popen) |
| L3-SUS-003 | Sensitive file access (/etc/passwd, /etc/shadow) |
| L3-SUS-004 | Network tool usage (curl, wget, nc, telnet) |
| L3-SUS-005 | Permission escalation (chmod +x, chmod 777) |
| L3-SUS-006 | Base64 decoding |
| L3-SUS-007 | Destructive commands (rm -rf /, dd if=/dev) |
| L3-SUS-008 | Process introspection (/proc/self, ptrace) |
| L3-SUS-009 | SSH key access (.ssh/, id_rsa, id_ed25519) |
| L3-SUS-010 | Dotfile access (/root/, /home/*/.) |

## L4 Behavioral Detector Rules

| Rule | Detects | Severity |
|------|---------|----------|
| L4-TIME | Anomalous timing, no-op, busy-wait | MEDIUM/HIGH |
| L4-EXFIL | Data exfiltration, suspicious DNS, credential theft | CRITICAL/HIGH/MEDIUM |
| L4-ENTROPY | High-entropy filenames, DGA domains | MEDIUM/HIGH |
| L4-HONEY | Honeypot path access, priv-esc binaries | CRITICAL |
| L4-BASE | Baseline drift from known-good profiles | CRITICAL/MEDIUM/INFO |
| L4-ENV | .env access, env-dump commands, secret var exfiltration | HIGH/CRITICAL |
| L4-PROC | Shell spawning, reverse shells, excessive spawns | HIGH/CRITICAL/MEDIUM |
| L4-FS | Protected path writes, path traversal, critical deletes | CRITICAL/HIGH/MEDIUM |
| L4-NET | Suspicious ports, DNS tunneling, suspicious TLDs | HIGH/MEDIUM |
| L4-SC | Obfuscated payloads, remote code exec, DNS exfiltration | CRITICAL/HIGH |
| L4-PRIVESC | Sudoers/shadow writes, setuid chmod, cap manipulation, cron abuse | CRITICAL/HIGH |
| L4-PERSIST | Crontab/systemd/SSH persistence, launch agents, shell profiles | CRITICAL/HIGH/MEDIUM |
| L4-CRYPTO | Mining pool connections, mining binaries, crypto config, resource abuse | CRITICAL/HIGH/MEDIUM |
| L4-CONTAINER | Container escape probes, docker socket, cloud metadata, namespace escape | CRITICAL/HIGH/MEDIUM |
| L4-DEP | Dependency confusion, registry overrides, publish during install | CRITICAL/HIGH/MEDIUM |

## Shipped Baselines

- `npm-install` — npm install/publish behavior
- `python-pip-install` — pip install behavior
- `node-script` — Node.js script execution
- `python-script` — Python script execution
- `curl-wget` — Download utilities

Custom baselines can be loaded from JSON files.

## Output Formats

| Format | Use Case |
|--------|----------|
| **Table** | Human-readable terminal output with verdict icons |
| **JSON** | Machine-readable, deterministic (sha256 repeatable) |
| **SARIF 2.1.0** | GitHub code scanning, VS Code, CI integration |
| **ML Context** | Token-budgeted context for LLM pipelines |
| **GitHub** | GitHub Actions annotation format |
| **CycloneDX** | SBOM and vulnerability format for compliance |

## Determinism Guarantee

`sha256(scan_a) == sha256(scan_b)` on identical inputs. No random IDs in findings, no timestamps in evidence, frozen dataclasses throughout. Enforced by a 4-layer guard stack:

```
┌─────────────────────────────────────────┐
│  Layer 4: CI Gate                       │
│  --verify-determinism (CLI)             │
│  Runs scan twice, asserts SHA-256 match │
├─────────────────────────────────────────┤
│  Layer 3: Diff                          │
│  picodome diff a.json b.json            │
│  Compare two saved scans field-by-field │
├─────────────────────────────────────────┤
│  Layer 2: Guard (runtime)               │
│  Validates invariants after each scan:  │
│  - No uuid4/random in findings          │
│  - No timestamps in findings            │
│  - Findings sorted by sort_key()        │
│  - run_id is deterministic (empty)      │
├─────────────────────────────────────────┤
│  Layer 1: Models (structural)           │
│  Finding(frozen=True), sorted keys,     │
│  no random IDs, no prose in output      │
└─────────────────────────────────────────┘
```

## Configuration

PicoDome reads `.picodome.yml` or `.picodome.yaml` from the target directory:

```yaml
version: 1
format: json
fail_on: high
deterministic_output: true
timeout: 30.0
severity_overrides:
  L4-TIME: low
  L4-ENTROPY: info
```

Environment variables (`PICODOME_*`) override config, and CLI flags override everything. The `PICODOME_*` env vars still work for backward compatibility.

## Security

- **Determinism vulnerability reporting**: See [SECURITY.md](SECURITY.md)
- **Threat model**: See [docs/security/threat-model.md](docs/security/threat-model.md)
- **Release integrity**: Sigstore-signed releases. See [SLSA.md](SLSA.md)
- **Zero hard runtime dependencies**: Only `pyyaml` (optional) and `libseccomp` (optional, system library)

## Documentation

- [SECURITY.md](SECURITY.md) — Vulnerability reporting and security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development guide and rule requirements
- [SLSA.md](SLSA.md) — Supply-chain Levels attestation
- [SCAAT.md](SCAAT.md) — Supply-chain attack vector mapping
- [STATE.md](STATE.md) — Honest project status
- [CHANGELOG.md](CHANGELOG.md) — Version history
- [docs/runbooks/](docs/runbooks/) — Operational runbooks
- [docs/security/](docs/security/) — Security documentation

## Development

```bash
pip install -e ".[dev]"
python -m pytest -v              # 1406 tests
picodome sandbox echo ci-test   # Quick self-test
bash scripts/ci.sh              # Full CI: mypy, ruff, pytest, determinism
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development guide.

## License

Business Source License 1.1 (BUSL-1.1) — source-available; production use allowed except for competitive offerings. Commercial use that competes with KirkForge's paid products requires a separate commercial license. After 3 years, converts to Apache-2.0. See [LICENSE](LICENSE), [LICENSE-SUMMARY.md](LICENSE-SUMMARY.md), and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

## Related

- [PicoSentry](https://github.com/KirkForge/PicoSentry) — Deterministic npm/pnpm supply-chain scanner (L2, 21 rules, 1401+ tests)
- [PicoWatch](https://github.com/KirkForge/PicoWatch) — Prompt and output guard plugin
