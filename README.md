# Iron Dome 🛡️

**Deterministic runtime sandbox and behavioral analysis for supply-chain security.**

[![CI](https://github.com/KirkForge/IronDome/actions/workflows/ci.yml/badge.svg)](https://github.com/KirkForge/IronDome/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Iron Dome is a two-layer defense system for npm/Python supply chains. Companion to [PicoSentry](https://github.com/KirkForge/PicoSentry) — static scan → runtime sandbox.

- **L3 Execution Sandbox** — Run any command under kernel-level policy. Real seccomp-bpf (Linux), Seatbelt/sandbox-exec (macOS), or universal subprocess backend.
- **L4 Behavioral Analysis** — Post-execution profiling. Detect exfiltration, timing anomalies, honeypot touches, entropy spikes, and baseline drift.

## Quick Start

```bash
pip install irondome

# L3: Sandbox a command
irondome sandbox python3 -c "print('hello')"

# L3+L4: Full pipeline
irondome pipeline npm install some-package

# Analyze existing sandbox output
irondome sandbox --format json npm test > sandbox.json
irondome analyze --input sandbox.json

# List detector rules
irondome rules
```

## L3 Backends

Iron Dome auto-detects the best available backend:

| Backend | Platform | Mechanism | Deterministic |
|---------|----------|-----------|---------------|
| **seccomp-bpf** | Linux | Kernel syscall filtering via libseccomp (ctypes), fork+exec | ✅ |
| **seatbelt** | macOS | sandbox-exec with generated profile DSL | ✅ |
| **subprocess** | Universal | Process isolation with post-hoc pattern analysis | ✅ |

The subprocess backend is the universal fallback. It applies policy by analyzing stdout/stderr for 10 suspicious pattern categories. The seccomp and seatbelt backends provide real kernel-level enforcement.

## L3 Suspicious Pattern Detectors

| Rule | Detects |
|------|---------|
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

## Shipped Baselines

- `npm-install` — npm install/publish behavior
- `python-pip-install` — pip install behavior
- `node-script` — Node.js script execution
- `python-script` — Python script execution
- `curl-wget` — Download utilities

Custom baselines can be loaded from JSON files.

## Output Formats

- **Table** — Human-readable terminal output with verdict icons
- **JSON** — Machine-readable, deterministic (sha256 repeatable)
- **SARIF 2.1.0** — GitHub code scanning, VS Code, CI integration

## Determinism Guarantee

`sha256(scan_a) == sha256(scan_b)` on identical inputs. No random IDs in findings, no timestamps in evidence, frozen dataclasses throughout. Enforced by CI gate.

## Why Iron Dome?

Static scanners (PicoSentry, Socket.dev, Snyk) inspect code. Iron Dome **executes** it safely, catching what static analysis misses: dependency confusion with dynamic payloads, post-install data exfiltration, obfuscated eval chains, and supply-chain worms.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -v          # 33 tests
irondome sandbox echo ci     # Quick self-test
```

## License

MIT — free for personal use, commercial licensing available.

## Related

- [PicoSentry](https://github.com/KirkForge/PicoSentry) — Deterministic npm/pnpm supply-chain scanner (19 rules, 369 tests)
- [55NDeep](https://github.com/KirkForge/55NDeep-plugin) — Codex verification and delegation plugin
