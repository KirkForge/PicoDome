# Iron Dome — State & Status

**Version:** 0.2.0 | **Repo:** https://github.com/KirkForge/IronDome
**Tests:** 33/33 passing | **Backends:** 3 (seccomp, seatbelt, subprocess)
**Status:** Active development

---

## Architecture

```
CLI (cli.py)
  → L3 Engine (l3/engine.py) — auto-detects backend
     → SeccompBackend (l3/backends/seccomp_backend.py) — libseccomp via ctypes
     → SeatbeltBackend (l3/backends/seatbelt_backend.py) — sandbox-exec profile gen
     → SubprocessBackend (l3/backends/subprocess_backend.py) — universal fallback
  → L4 Engine (l4/engine.py) — behavioral analysis pipeline
     → Profiler (l4/profiler.py) — extract profile from sandbox output
     → Differ (l4/differ.py) — compare profile against baselines
     → Rules (l4/rules/*.py) — 5 detector rules
     → Baselines (l4/baseline.py) — 5 shipped baselines
  → Formatters (formatters/*.py) — json, sarif, table
  → Models (models.py) — frozen dataclasses, determinism by design
```

## Backend Status

| Backend | Platform | Implementation | Syscall Filtering | Post-hoc Analysis |
|---------|----------|----------------|-------------------|-------------------|
| seccomp-bpf | Linux | libseccomp ctypes + fork/exec | ✅ Real BPF filter | ✅ Suspicious patterns |
| seatbelt | macOS | sandbox-exec + profile DSL | ✅ Generated profiles | ✅ Suspicious patterns |
| subprocess | Universal | Popen + regex analysis | ❌ (process-level only) | ✅ 10 pattern categories |

## L3 Default Policy

The built-in policy (`iron-dome-default`) is deny-by-default with explicit allows:

- **Allowed:** File reads (system libs, Python packages, project files), DNS resolution, writes to /tmp and stdio
- **Blocked:** Outbound network, inbound network, process spawning, network bind/listen
- **Detected:** 10 suspicious output patterns (eval, curl, chmod, base64, etc.)

## L4 Detector Details

| Rule ID | Rule | Detection Method | Baseline-Aware |
|---------|------|-----------------|----------------|
| L4-TIME | Timing anomalies | Runtime thresholds, baseline comparison | Yes |
| L4-EXFIL | Data exfiltration | Suspicious TLDs, non-standard ports, large transfers, credential reads + network | No |
| L4-ENTROPY | Entropy anomalies | Shannon entropy on filenames and DNS hostnames | No |
| L4-HONEY | Honeypot touches | Known-suspicious paths, priv-esc binary spawns | No |
| L4-BASE | Baseline drift | Compare profile metrics against shipped baselines | Yes |

## Version History

- v0.2.0 — Real seccomp backend (libseccomp ctypes + fork/exec), real seatbelt backend (sandbox-exec), 33 tests
- v0.1.0 — Initial release: L3 sandbox, L4 behavioral analysis, CLI, formatters, 28 tests
