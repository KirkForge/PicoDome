# Iron Dome Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2026-05-27

### Added
- **`create_app()` factory** in `daemon/server.py` — programmatic daemon creation for testing and orchestration
- **`generate_test_summary.py`** — machine-readable test evidence (total, passed, failed, skipped, duration, coverage, slow tests)
- **Test summary step in CI** — every CI run uploads `test-summary-py{version}.json` artifact with 30-day retention
- **Evidence bundle in release workflow** — `evidence` job generates and attaches `irondome-evidence-bundle.tar.gz` to GitHub releases
- **Enterprise pilot limitations** — `docs/ENTERPRISE_PILOT_LIMITATIONS.md` with scale limits, tenancy assumptions, Redis requirements, deployment modes, unsupported compliance claims, graduation criteria
- **Third-party security review plan** — `docs/security/THIRD_PARTY_REVIEW.md` with scope, methodology, timeline, budget, vendor requirements

### Changed
- **CI test job** — time-bounded with `--timeout=120 --timeout-method=thread -m "not network"`, JUnit XML + JSON coverage output
- **Release test job** — same time-bounded pytest configuration as CI
- **Gap analysis score** — 8.0 → 8.5 / 10 (enterprise-beta)
- **Status** — Active development → Enterprise Beta — controlled pilot ready

### Fixed
- **Collection error** — `irondome.daemon.__init__` imported non-existent `create_app`; 4 test modules could not be collected (`test_audit_coverage`, `test_redis_store`, `test_sqlite_store`, `test_sqlite_integration`)
- **Packaging hygiene** — `MANIFEST.in` now has `global-exclude __pycache__` and `global-exclude *.pyc`; verified clean wheel/sdist builds
- **Local cache cleanup** — removed all `__pycache__/` directories and `.pyc` files from the repository

## [0.5.0] - 2026-05-25

### Added
- **Request ID middleware** — every daemon response includes `X-Request-ID` header for distributed traceability; clients may provide their own via `X-Request-ID` request header
- **CORS headers** — all daemon responses include CORS headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`); configurable via `IRONDOME_CORS_ORIGINS` env var (default: `*`)
- **CORS preflight** — `OPTIONS` requests are handled automatically with proper CORS headers
- **Graceful shutdown** — `IronDomeDaemon.install_signal_handlers()` registers SIGTERM, SIGINT, and SIGHUP handlers for clean shutdown; in-flight requests are drained before stopping
- **Security response headers** — `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` on all daemon responses
- **Version bump** — package version updated from 0.3.0 to 0.5.0 to reflect completed Phase 2 and Phase 3 enterprise work

### Changed
- **OpenAPI spec** updated to v0.5.0 with `/api/v1/tenants` endpoint, request tracing, and CORS documentation
- **Daemon module docstring** updated with signal handler usage

### Fixed
- Version mismatch between code (0.3.0) and documentation (0.4.0) resolved

## [0.4.0] - 2026-05-22

### Added
- **gRPC transport** (PR-21) — optional high-throughput transport for daemon mode
  - `src/irondome/grpc_transport/` package with server, client, servicer, and proto
  - `irondome.proto` — protobuf schema with Scan, Health, GetPolicy, QueryAudit RPCs
  - `IronDomeGRPCServer` — wraps existing scan engine, serves on configurable port (default 50051)
  - `IronDomeGRPCClient` — sync/async scan methods, TLS/mTLS support, retry logic
  - `irondome daemon --transport grpc` — start daemon with gRPC transport
  - `irondome scan-grpc <target>` — scan via gRPC client
  - Dependency injection so module degrades gracefully without grpcio
  - All gRPC calls audit-logged
  - 37 tests (module availability, server, client, servicer, scan engine, CLI, proto)

### Changed
- **SOC 2 Type I readiness assessment** — comprehensive mapping of Trust Services Criteria (CC6.1–CC8.1, A1.1, C1.1, PI1.1, PI1.3) to IronDome controls
- **SOC 2 evidence matrix** — detailed mapping of controls to source code, tests, and documentation with gap analysis
- **Structured audit logging** — hash-chained append-only JSON-lines log with 14 event types, query API, rotation
- **Policy versioning** — author, timestamp, change description, content hashing, diff, rollback, integrity verification
- **Data retention** — configurable TTL (90/365/∞ days), secure deletion (overwrite+random+truncate+unlink), storage quotas, compliance export
- **Health and readiness checks** — backend, audit chain, and storage status endpoints
- **Daemon mode** — HTTP API server (12 endpoints), token-based authentication, RBAC (3 roles), Prometheus metrics
- **mTLS transport security** — TLS 1.2+ minimum, strong cipher suites, client cert verification, dev self-signed mode
- **Rate limiting** — token-bucket per-actor limiting with configurable burst, global RPS cap, priority job queuing
- **Webhook notifications** — HMAC-SHA256 signed payloads, severity filtering, retry with exponential backoff
- **Baseline hardening** — HMAC signing, update rate limiting (2/hour), drift detection (50% threshold), audit logging
- **API versioning** — URL path, Accept header, and custom header negotiation with deprecation notices
- **SLO tracking** — 7 service-level objectives (availability 99.9%, latency p50/p95/p99, throughput, error rate, determinism)
- **Kubernetes deployment** — Deployment, Service, PVC, RBAC, ServiceAccount, health probes, Prometheus annotations
- **Helm chart** — configurable replicas, mTLS, rate limiting, webhooks, retention, SLOs, monitoring

## [0.3.0] - 2026-05-22

### Added
- **SECURITY.md** — vulnerability reporting policy and security contacts
- **CONTRIBUTING.md** — contributor guidelines, code of conduct, PR process
- **SLSA.md** — Supply-chain Levels for Software Artifacts compliance documentation
- **SCAAT.md** — Supply Chain Artifact Attestation policy
- **CITATION.cff** — citation metadata for academic referencing
- **Dockerfile** — reproducible container build for CI and local testing
- **.pre-commit-hooks.yaml** — pre-commit integration for automated scanning
- **MANIFEST.in** — source distribution inclusion rules
- **mypy.ini** — type-checking configuration for strict analysis
- **.editorconfig** — consistent coding style across editors and IDEs
- **.gitattributes** — language statistics and line-ending normalization
- **Enterprise gap analysis** — comprehensive audit of enterprise readiness
- **JSON schemas** for all output formats (JSON, SARIF, CycloneDX, table)
- **CI scripts**: `ci.sh`, `verify_release.sh`, `generate_sbom.py`
- **Release pipeline** with Sigstore signing + SLSA L3 provenance
- **Expanded pyproject.toml** metadata (authors, maintainers, classifiers, URLs, tool configs)
- **[tool.pytest.ini_options]** — pythonpath, addopts, timeout, markers (slow, network)
- **[tool.mypy]** — strict-ish type checking config
- **[tool.ruff.format]** — quote-style, indent-style, trailing-comma settings
- **[tool.coverage.run/report]** — source paths, omit patterns, fail_under gate
- **[project.optional-dependencies]** — dev, sigstore, all groups

### Changed
- **Enterprise-grade CI pipeline** — coverage, mypy, ruff, determinism gate, self-test
- **Expanded test suite** from 33 to 295 tests
- **pyproject.toml** upgraded with full enterprise metadata and tool configurations

## [0.2.0] - 2026-05-20

### L3 Backends
- **SeccompBackend**: Real kernel-level syscall filtering via libseccomp ctypes
  - Uses `os.fork()` + `os.execve()` for reliable child process sandboxing
  - Comprehensive safe syscall whitelist for binary execution
  - Falls back to subprocess on seccomp_init failure
- **SeatbeltBackend**: Real macOS sandbox-exec with generated profiles
  - Translates Iron Dome Policy to seatbelt profile DSL
  - Supports file, network, process, and DNS rule targets
  - Falls back to subprocess when not on macOS
- **SubprocessBackend**: Added 10 suspicious pattern detectors (L3-SUS-001 through L3-SUS-010)

### Tests
- 33 tests total (5 new seccomp-specific tests)
- Seccomp: echo, python, network block, file write block, command not found
- All L4 tests passing unchanged

### Docs
- Updated README with backend comparison table and L3 pattern detector reference
- Added STATE.md with architecture overview and backend status

## [0.1.0] - 2026-05-20

### Initial Release
- L3 Execution Sandbox: subprocess backend, policy engine, 3 backends (shells)
- L4 Behavioral Analysis: profiler, differ, 5 detector rules, 5 baselines
- CLI: `irondome sandbox|analyze|pipeline|rules`
- Formatters: JSON, SARIF 2.1.0, table
- 28 tests, CI workflow with determinism gate