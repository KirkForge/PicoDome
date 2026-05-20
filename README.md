# Iron Dome 🛡️

**Deterministic runtime sandbox and behavioral analysis for supply-chain security.**

[![CI](https://github.com/KirkForge/IronDome/actions/workflows/ci.yml/badge.svg)](https://github.com/KirkForge/IronDome/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Iron Dome is a two-layer defense system for npm/Python supply chains:

- **L3 Execution Sandbox** — Run any command under policy. Seccomp (Linux), Seatbelt (macOS), or subprocess (universal). Produces deterministic SARIF/JSON verdicts.
- **L4 Behavioral Analysis** — Post-execution profiling. Detect exfiltration, timing anomalies, honeypot touches, entropy spikes, and baseline drift.

Companion to [PicoSentry](https://github.com/KirkForge/PicoSentry) (static scan → runtime sandbox).

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

## Why Iron Dome?

Static scanners (PicoSentry, Socket.dev, Snyk) inspect code. Iron Dome **executes** it safely:

| Layer | What | How |
|-------|------|-----|
| **L3 Sandbox** | Run under policy | Seccomp-bpf syscall filtering, network deny, filesystem restrictions, timeout enforcement |
| **L4 Behavioral** | Analyze what happened | Profiling (network, DNS, FS, spawns), entropy analysis, honeypot detection, baseline drift |

Together they catch what static analysis misses: dependency confusion with dynamic payloads, post-install data exfiltration, obfuscated eval chains, and supply-chain worms.

## Output Formats

- **Table** — Human-readable terminal output
- **JSON** — Machine-readable, deterministic (sha256 repeatable)
- **SARIF 2.1.0** — GitHub code scanning, VS Code, CI integration

## Determinism Guarantee

`sha256(scan_a) == sha256(scan_b)` on identical inputs. No random IDs in findings, no timestamps, frozen dataclasses. Enforced by CI gate.

## CLI Commands

| Command | Description |
|---------|-------------|
| `irondome sandbox <cmd>` | Run under L3 policy |
| `irondome analyze --input <file>` | L4 analysis on sandbox output |
| `irondome pipeline <cmd>` | Full L3+L4 pipeline |
| `irondome rules` | List L4 detector rules |

## L4 Detector Rules

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

## Development

```bash
pip install -e ".[dev]"
python -m pytest -v
```

## License

MIT — free for personal use, commercial licensing available.

## Related

- [PicoSentry](https://github.com/KirkForge/PicoSentry) — Deterministic npm/pnpm supply-chain scanner
- 55NDeep — Codex verification and delegation plugin
