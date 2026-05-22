# Iron Dome Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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