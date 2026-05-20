# Iron Dome Changelog

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
