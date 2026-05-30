# PicoDome — Project State

> **Version:** 0.5.0 · **Maturity:** pre-1.0 beta · **Updated:** 2026-05-30

## What PicoDome IS

A deterministic runtime sandbox and behavioral analysis engine for supply-chain security. It runs code safely and detects malicious behavior that static scanners miss.

- ✅ L3 sandbox: seccomp-bpf (Linux), seatbelt (macOS), subprocess (universal) — 1406+ tests
- ✅ L4 behavioral analysis: 15 detector rules
- ✅ 10 L3 suspicious pattern detectors
- ✅ Deterministic output (SHA-256 reproducible, 4-layer guard stack)
- ✅ CLI: sandbox, analyze, pipeline, rules, diff, verify-determinism
- ✅ 6 output formats (table, JSON, SARIF, ML Context, GitHub, CycloneDX)
- ✅ 5 shipped baselines (npm-install, python-pip-install, node-script, python-script, curl-wget)
- ✅ Zero hard runtime dependencies (pyyaml and libseccomp optional)
- ✅ Daemon mode: HTTP API, token auth, rate limiting, health checks
- ✅ Audit logging: hash-chained append-only log
- ✅ Policy versioning with content hashing and rollback
- ✅ Data retention with secure deletion

## What PicoDome is NOT

- ❌ A Kubernetes admission controller in production — Helm charts and admission webhook code exist, but have zero deployment evidence
- ❌ SOC 2 Type I certified or audited
- ❌ An enterprise platform with proven multi-tenancy
- ❌ A full containment boundary — seccomp-bpf is a syscall policy harness, not a VM

## What's Scaffolded (code exists, no production deployment)

- 🔶 Multi-tenant API endpoints (tests pass, no real deployment)
- 🔶 Kubernetes Helm charts and admission webhook
- 🔶 gRPC transport (code + tests exist, not deployed)
- 🔶 mTLS certificate rotation (code + tests, no production CA)
- 🔶 Redis-backed rate limiting and baseline storage (requires external Redis)
- 🔶 Cluster manager / fleet deployment
- 🔶 Prometheus metrics endpoint (scrapable, no dashboards proven in prod)
- 🔶 Sigstore/Rekor notary integration (code exists, not in release pipeline)

## Pico Security Series

| Product | Layer | Status |
|---------|-------|--------|
| [PicoSentry](https://github.com/KirkForge/PicoSentry) | L2 | ✅ production (21 rules, 1390 tests) |
| **PicoDome** | L3+L4 | ✅ core / 🔶 daemon / 🔶 K8s |
| PicoWatch | L5 | in development |
| PicoShogun | — | in development |

## L4 Detector Rules (15 rules)

| Rule ID | Detector | Detects | Severity |
|---------|----------|---------|----------|
| L4-TIME | Timing | Anomalous timing, no-op, busy-wait | MEDIUM/HIGH |
| L4-EXFIL | Exfiltration | Data exfil, suspicious DNS, credential theft | CRITICAL/HIGH/MEDIUM |
| L4-ENTROPY | Entropy | High-entropy filenames, DGA domains | MEDIUM/HIGH |
| L4-HONEY | Honeypot | Honeypot path access, priv-esc binaries | CRITICAL |
| L4-BASE | Baseline drift | Drift from known-good profiles | CRITICAL/MEDIUM/INFO |
| L4-ENV | Env leak | .env access, env-dump commands, secret var exfil | HIGH/CRITICAL |
| L4-PROC | Process anomaly | Shell spawning, reverse shells, excessive spawns | HIGH/CRITICAL/MEDIUM |
| L4-FS | Filesystem | Protected path writes, path traversal, critical deletes | CRITICAL/HIGH/MEDIUM |
| L4-NET | Network | Suspicious ports, DNS tunneling, suspicious TLDs | HIGH/MEDIUM |
| L4-SC | Supply chain | Obfuscated payloads, remote code exec, DNS exfiltration | CRITICAL/HIGH |
| L4-PRIVESC | Privilege escalation | Sudoers/shadow writes, setuid chmod, cap manipulation, cron abuse | CRITICAL/HIGH |
| L4-PERSIST | Persistence | Crontab/systemd/SSH persistence, launch agents, shell profiles | CRITICAL/HIGH/MEDIUM |
| L4-CRYPTO | Crypto mining | Mining pool connections, mining binaries, crypto config, resource abuse | CRITICAL/HIGH/MEDIUM |
| L4-CONTAINER | Container escape | Container escape probes, docker socket, cloud metadata, namespace escape | CRITICAL/HIGH/MEDIUM/INFO |
| L4-DEP | Dependency confusion | Registry overrides, publish during install, suspicious URLs, config tampering | CRITICAL/HIGH/MEDIUM/LOW |

## Test Status

- **1406+ tests passing**, 12 skipped (sandbox-dependent tests, need `PICODOME_SANDBOX_TESTS=1`)
- mypy strict: clean
- ruff: clean

## Known Issues

- GitHub Actions billing exhausted — CI will resume when billing resets
- SLSA L3 provenance generated but hermetic builds not yet achieved

## Recent Changes (2026-05-30)

- Added 5 new L4 detector rules (PRIVESC, PERSIST, CRYPTO, CONTAINER, DEP) — 10 → 15 total
- **Fixed critical blocker**: added wait4/waitid/waitpid to seccomp _PROCESS_SYSCALLS and _SAFE_SYSCALLS — child-reaping was denied under default-deny, killing npm/pip subprocesses
- Added `--allow-runtime {node,python}` CLI flag — selects appropriate named policy
- Pipeline command now auto-detects runtime (npm/node → node policy, pip/python → python policy)
- Improved seccomp SIGSYS diagnostic — now shows denied syscall categories and remediation suggestions
- Renamed all policy names from `iron-dome-*` to `picodome-*`
- Added 5 new L4 detector rules (ENV, PROC, FS, NET, SC)
- Fixed CORS default from wildcard to deny-by-default
- Fixed subprocess backend env inheritance from `os.environ.copy()` to explicit allowlist
- Fixed daemon docstring example from `0.0.0.0` to `127.0.0.1`
- Updated README L4 rule table with all 15 rules
