# Contributing to PicoDome

Thanks for your interest in PicoDome! This guide covers how to contribute effectively.

## Quick Start

```bash
git clone https://github.com/KirkForge/PicoDome.git
cd PicoDome
python3 -m pip install -e ".[dev]"   # Required: CLI tests need the package importable
python3 -m pytest
```

> **Important:** You must install the package in editable mode before running tests.
> CLI integration tests use `subprocess` to invoke `picodome`, which requires the
> package to be importable. Raw `pytest` from a clean checkout will fail at CLI tests
> without `pip install -e ".[dev]"`.

## Development

### Running Tests

```bash
python3 -m pytest                              # All tests
python3 -m pytest tests/test_l3_sandbox.py      # L3 sandbox tests only
python3 -m pytest tests/test_l4_behavioral.py   # L4 behavioral tests only
python3 -m pytest tests/test_guards.py          # Determinism guard tests
python3 -m pytest -x                            # Stop on first failure
python3 -m pytest -m "not slow"                 # Skip slow tests
python3 -m pytest -m "not network"              # Skip network-dependent tests
```

### Linting & Type Checking

```bash
ruff check src/ tests/                     # Lint
ruff format --check src/ tests/            # Format check
mypy src/picodome --strict                 # Type check
```

### Pre-push CI Script

```bash
bash scripts/ci.sh                         # Run all checks: mypy, ruff, pytest, determinism
```

## Adding a New L3 Backend

PicoDome supports multiple sandbox backends (seccomp-bpf, seatbelt, subprocess). Adding a new backend follows this pattern:

### Step-by-Step

1. **Create the backend module** in `src/picodome/l3/backends/` (e.g., `zone_backend.py`):

```python
"""Zone sandbox backend (Solaris only)."""

from typing import List, Optional
from picodome.l3.backends.base import SandboxBackend
from picodome.l3.models import Policy, SandboxResult

class ZoneBackend(SandboxBackend):
    @property
    def name(self) -> str:
        return "zone"

    def is_available(self) -> bool:
        # Check if zones are available on this system
        ...

    def run(
        self,
        command: List[str],
        policy: Policy,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> SandboxResult:
        # Implement sandbox execution
        ...
```

2. **Register in the auto-detection** — update `src/picodome/l3/engine.py` `_detect_backend()`:

```python
elif system == "SunOS":
    try:
        from picodome.l3.backends.zone_backend import ZoneBackend
        backend = ZoneBackend()
        if backend.is_available():
            logger.info("Using zone backend (Solaris)")
            return backend
    except ImportError:
        pass
```

3. **Write tests** in `tests/test_zone_backend.py`:

```python
import pytest
from picodome.l3.backends.zone_backend import ZoneBackend

def test_zone_backend_is_available():
    backend = ZoneBackend()
    # Should return True on Solaris, False elsewhere
    assert isinstance(backend.is_available(), bool)

def test_zone_backend_run_hello():
    backend = ZoneBackend()
    result = backend.run(["echo", "hello"], default_policy())
    assert result.exit_code == 0
    assert "hello" in result.stdout
```

4. **Add suspicious pattern detection** — if your backend captures output, delegate to the subprocess backend's pattern checker:

```python
from picodome.l3.backends.subprocess_backend import SubprocessBackend
sb = SubprocessBackend()
events.extend(sb._check_suspicious_patterns(stdout, stderr))
```

5. **Update `SCAAT.md`** with the new backend's coverage.

6. **Run `python3 -m pytest`** and verify all tests pass.

## Adding a New L4 Detector Rule

L4 detector rules are pure functions that take a `BehavioralProfile` and return a list of `Finding` objects.

### Step-by-Step

1. **Create the detector module** in `src/picodome/l4/rules/` (e.g., `dns_tunnel.py`):

```python
"""L4 DNS tunneling detector."""

from typing import Dict, List, Optional
from picodome.l4.models import BehavioralProfile, Baseline, Finding
from picodome.models import Severity

def detect_dns_tunneling(
    profile: BehavioralProfile,
    baselines: Optional[Dict[str, Baseline]] = None,
) -> List[Finding]:
    """Detect DNS tunneling patterns in behavioral profiles."""
    findings: List[Finding] = []

    for dns in profile.dns_queries:
        # Detection logic here
        ...

    return findings
```

2. **Register in the engine** — update `src/picodome/l4/engine.py` `create_default_engine()`:

```python
from picodome.l4.rules.dns_tunnel import detect_dns_tunneling

engine.register("L4-DNS", detect_dns_tunneling)
```

3. **Write tests** in `tests/test_dns_tunnel.py`:

```python
from picodome.l4.rules.dns_tunnel import detect_dns_tunneling
from picodome.l4.models import BehavioralProfile, DnsQuery

def test_dns_tunnel_detects_long_subdomain():
    profile = BehavioralProfile(
        package="test-pkg",
        dns_queries=[
            DnsQuery(hostname="a1b2c3d4e5f6.data.exfil.example.com"),
        ],
    )
    findings = detect_dns_tunneling(profile)
    assert len(findings) == 1
    assert findings[0].rule_id == "L4-DNS-001"
```

4. **Create rule doc** in `src/picodome/docs/rules/L4-DNS-001.md`.

5. **Update `SCAAT.md`** with the new attack vector coverage.

6. **Run `python3 -m pytest`** and verify all tests pass.

### Rule Requirements

Every L4 detector rule **must** be deterministic:
- Same profile + same baselines = same findings, every time
- No network calls at analysis time
- No `uuid4()`, `random()`, or timestamps in findings
- Findings sorted by `(rule_id, location, message)`
- Use `Severity` enum for severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)

Every L3 suspicious pattern detector **must** be deterministic:
- Same stdout + stderr + policy = same events, every time
- Pattern matching must be regex-based (no fuzzy/random matching)
- Events must use consistent `rule_id` and `operation` strings

## Adding a New Output Formatter

PicoDome supports multiple output formats (table, JSON, SARIF). Adding a new formatter:

1. **Create the formatter module** in `src/picodome/formatters/` (e.g., `junit.py`):

```python
"""JUnit XML output formatter."""

from typing import Union
from picodome.l3.models import SandboxResult
from picodome.l4.models import AnalysisResult

def format_junit(
    result: Union[SandboxResult, AnalysisResult],
    deterministic: bool = True,
) -> str:
    """Format result as JUnit XML."""
    ...
```

2. **Register in CLI** — update `src/picodome/cli.py` to add the `--format junit` option.

3. **Write tests** in `tests/test_junit_formatter.py`.

4. **Update `SCAAT.md`** if the format has security implications.

5. **Run `python3 -m pytest`** and verify all tests pass.

## Code Style

- **Type hints** on all public functions
- **Docstrings** on all public functions and classes
- `dataclass(frozen=True)` for immutable data (`Finding`, `SandboxResult`, `AnalysisResult`, `Policy`, `PolicyRule`, etc.)
- Sorted keys in all JSON output
- 120-char line limit (ruff enforced)
- No `uuid4()` or `random()` in deterministic paths
- All model classes use `to_dict(deterministic=True)` for reproducible output

## Project Structure

```
src/picodome/
├── cli.py               # CLI entry point — all subcommands
├── config.py            # .picodome.yml loader
├── guards.py            # Determinism enforcement (4-layer guard stack)
├── license.py           # License management
├── logging.py           # Structured JSON logging
├── models.py            # Shared frozen dataclasses (Finding, Severity, Verdict)
├── workspace.py         # Monorepo scanning
├── l3/                  # L3 Execution Sandbox
│   ├── engine.py        # SandboxEngine — auto-detect backend, run command
│   ├── models.py        # L3 models (SandboxResult, Policy, PolicyRule, SandboxEvent)
│   ├── policy.py        # Policy loading, validation, defaults, import/export
│   ├── backends/
│   │   ├── base.py      # SandboxBackend ABC
│   │   ├── seccomp_backend.py   # Linux seccomp-bpf (libseccomp via ctypes)
│   │   ├── seatbelt_backend.py  # macOS sandbox-exec
│   │   └── subprocess_backend.py # Universal fallback
│   └── docs/rules/      # L3 rule documentation
├── l4/                  # L4 Behavioral Analysis
│   ├── engine.py        # L4Engine — register rules, analyze profiles
│   ├── models.py        # L4 models (BehavioralProfile, AnalysisResult, Baseline)
│   ├── baseline.py      # Shipped baselines + custom baseline loading
│   ├── differ.py        # Baseline comparison and drift scoring
│   ├── profiler.py      # SandboxResult → BehavioralProfile conversion
│   └── rules/
│       ├── timing.py            # L4-TIME (anomalous timing)
│       ├── exfil.py             # L4-EXFIL (data exfiltration)
│       ├── entropy.py           # L4-ENTROPY (high-entropy strings)
│       ├── honeypot.py          # L4-HONEY (honeypot path access)
│       └── baseline_drift.py   # L4-BASE (baseline drift)
└── formatters/          # Output formatters
    ├── table.py         # Human-readable terminal output
    ├── json_fmt.py      # Deterministic JSON
    ├── sarif.py         # SARIF 2.1.0
    ├── github.py        # GitHub Actions annotation
    ├── ml_context.py    # ML training context
    └── cyclonedx.py     # CycloneDX SBOM
```

## Determinism Verification

After any sandbox or analysis logic change, verify determinism:

```bash
# Run two sandbox executions and compare (byte-identical output)
picodome sandbox python3 -c "print('hello')" --format json --deterministic-output -o scan_a.json
picodome sandbox python3 -c "print('hello')" --format json --deterministic-output -o scan_b.json
diff scan_a.json scan_b.json  # should produce no output

# Or use built-in verification (runs twice, compares SHA-256)
picodome sandbox python3 -c "print('hello')" --verify-determinism
# Should output: "✓ DETERMINISM VERIFIED — results are deterministic"

# Compare two saved result files
picodome diff scan_a.json scan_b.json
# Should output: "✓ Results are IDENTICAL — determinism verified"

# Note: without --deterministic-output, JSON includes timestamps and timing.
# The --verify-determinism flag automatically enables deterministic output mode.
```

The 4-layer determinism guard stack:

```
┌─────────────────────────────────────────┐
│  Layer 4: CI Gate                       │
│  --verify-determinism (CLI)             │
│  Runs twice, asserts SHA-256 match      │
├─────────────────────────────────────────┤
│  Layer 3: Diff                          │
│  picodome diff a.json b.json            │
│  Compare two saved results field-by-field│
├─────────────────────────────────────────┤
│  Layer 2: Guard (runtime)               │
│  Validates invariants after each scan:  │
│  - No uuid4/random in findings          │
│  - No timestamps in findings            │
│  - Findings sorted by sort_key()        │
│  - run_id is deterministic (empty)      │
├─────────────────────────────────────────┤
│  Layer 1: Models (structural)           │
│  Finding(frozen=True), sorted keys,    │
│  no random IDs, no prose in output      │
└─────────────────────────────────────────┘
```

## Commit Messages

Format: `type: description`

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

Examples:
- `feat: L4-EXFIL-005 sensitive file read + network exfiltration detector`
- `feat: seccomp-bpf backend with fork+exec and syscall filtering`
- `fix: determinism guard now checks L3 SandboxResult events for UUIDs`
- `docs: add SECURITY.md and SCAAT.md`
- `test: add baseline drift detection tests`

## Reporting Issues

- Include: PicoDome version, Python version, OS, sandbox backend in use
- Include: `picodome version` output
- Include: `--verbose` output if possible
- For sandbox issues: include the policy and command that triggered the bug
- For behavioral analysis issues: include the profile and expected vs. actual findings

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting policy.

## AI-Assisted Development

PicoDome is developed with AI assistance. All AI-generated contributions are
reviewed, tested, and approved by a human maintainer before merge.

