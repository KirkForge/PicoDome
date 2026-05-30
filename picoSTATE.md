# PicoDome — Project State

> **Version:** 0.5.0 · **Maturity:** beta · **Updated:** 2026-05-30 · **Publish-ready**

## What PicoDome IS

A deterministic runtime sandbox and behavioral analysis engine for supply-chain security. It runs code safely and detects malicious behavior that static scanners miss.

- ✅ L3 sandbox: seccomp-bpf (Linux), seatbelt (macOS), subprocess (universal)
- ✅ L4 behavioral analysis: 15 detector rules
- ✅ 10 L3 suspicious pattern detectors
- ✅ Deterministic output (SHA-256 reproducible, 4-layer guard stack)
- ✅ CLI: sandbox, analyze, pipeline, rules, diff, verify-determinism, sign-policy
- ✅ `--allow-runtime {node,python}` CLI flag with auto-detection in pipeline
- ✅ 6 output formats (table, JSON, SARIF, ML Context, GitHub, CycloneDX)
- ✅ 5 shipped baselines (npm-install, python-pip-install, node-script, python-script, curl-wget)
- ✅ Zero hard runtime dependencies (pyyaml and libseccomp optional)
- ✅ Daemon mode: HTTP API, token auth, rate limiting, health checks
- ✅ Audit logging: hash-chained append-only log
- ✅ Policy versioning with content hashing and rollback
- ✅ Data retention with secure deletion
- ✅ **npm install and pip install verified end-to-end under seccomp sandbox**
- ✅ Three external code reviews passed (Opus 4.8 ×3 rounds, GPT 5.5)

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

- **1459 tests passing**, 12 skipped (sandbox-dependent tests, need `PICODOME_SANDBOX_TESTS=1`)
- mypy strict: clean
- ruff: clean
- compileall: clean
- wheel build: ✅ picodome-0.5.0-py3-none-any.whl

## Publish Readiness

**Publish-ready for beta.** Core L3+L4 product is solid, three external reviews closed, headline use cases verified end-to-end.

**Remaining honest gaps (not blocking):**
- License gate accepts any `shogun-` prefixed key (placeholder until Shogun ships real verification)
- SLSA L3 provenance generated but hermetic builds not yet achieved
- GitHub Actions billing resets June 1 — pre-push gate passes (gitleaks + trufflehog)
- Scaffolded features (K8s, gRPC, mTLS, Redis, cluster, Sigstore) have zero production deployment evidence — honestly documented

## Security Fixes (2026-05-30)

### Opus 4.8 review (round 1)
- **CRITICAL**: Added wait4/waitid/waitpid to seccomp _PROCESS_SYSCALLS and _SAFE_SYSCALLS — default-deny killed child-reaping, breaking npm/pip (exit 31, no diagnostic)
- **CRITICAL**: Implemented `--allow-runtime {node,python}` CLI flag (was documented but missing from CLI)
- Pipeline auto-detects runtime from argv[0] (npm/node → node policy, pip/python → python policy)
- SIGSYS diagnostic now shows denied syscall categories and remediation suggestions
- Daemon docstring example: `0.0.0.0` → `127.0.0.1`

### Opus 4.8 review (round 2)
- **CRITICAL**: Added close_range, kill, setsid, sigprocmask to _SAFE_SYSCALLS and _PROCESS_SYSCALLS — CPython subprocess.run uses close_range() in the fork/exec child path; without it, spawned children die with SIGSYS while the parent exits 0 (silent ALLOW masking child death)
- Added subprocess child-survival integration tests (assert child returncode, not just parent verdict)

### Opus 4.8 review (round 3)
- Verified all round-2 fixes: child processes survive, enforcement still works (network KILL still kills)
- **Runtime syscall coverage**: Added statx, getppid, umask, fadvise64, fsync, io_uring_setup, io_uring_enter, sched_getparam, sched_getscheduler to _SAFE_SYSCALLS — required by modern node.js/libuv and pip runtimes
- Changed node/python policies: network_bind → allow (npm/pip need NETLINK bind for DNS resolution)
- npm install and pip install verified end-to-end under seccomp sandbox

### GPT 5.5 review
- Cluster shutdown hang: heartbeat/health threads use `stop_event.wait()` instead of `time.sleep()`, so `stop()` wakes them immediately
- `SeccompBackend.is_available()` now tests both permissive and fail-closed filter creation (catches containers that allow SCMP_ACT_ALLOW but reject SCMP_ACT_KILL_PROCESS)
- `sandbox_run(allow_degraded=True)` was silently ignored — now passes through to `_detect_backend()`
- `/ready` endpoint now reports `degraded: true` when running on subprocess backend
- Removed unused `import re` and `combined` variable from env_leak rule

### CI/Docs cleanup
- Fixed Ruff I001 import sort in l4/engine.py
- Fixed Mypy dict typing (`dict[str, object]`) in /ready handler
- Updated rule docs: 5 → 15 L4 rules
- Updated SCAAT.md: 17 → 27 rule types
- Updated version refs: 0.3.0 → 0.5.0 (SECURITY.md, release-integrity.md, verify_release.sh)
- Made seccomp tests portable (allow_degraded=True for non-seccomp environments)

## Other Changes (2026-05-30)

- Added 5 new L4 detector rules (PRIVESC, PERSIST, CRYPTO, CONTAINER, DEP) — 10 → 15 total
- Added 5 new L4 detector rules (ENV, PROC, FS, NET, SC)
- Renamed all policy names from `iron-dome-*` to `picodome-*`
- Fixed CORS default from wildcard to deny-by-default
- Fixed subprocess backend env inheritance from `os.environ.copy()` to explicit allowlist
- Updated README L4 rule table with all 15 rules
