# Runbook: CI Pipeline Failures

## Severity: MEDIUM (blocks deployment)

## Common Failures

### 1. Test Failures

```bash
python -m pytest -v
```

- Check that `pip install -e ".[dev]"` was run first
- Ensure Python 3.10+ is available
- Look for import errors (missing dependencies)

### 2. Ruff Lint Failures

```bash
ruff check src/ tests/
ruff format --check src/ tests/
```

- Auto-fix: `ruff check --fix src/ tests/`
- Auto-format: `ruff format src/ tests/`

### 3. MyPy Type Check Failures

```bash
mypy src/picodome
```

- Common: missing type hints on public functions
- Common: `Any` type inference in frozen dataclasses
- Run with `--strict` to see all issues

### 4. Determinism Gate Failure

```bash
RUN1=$(python -m picodome sandbox --format json echo deterministic 2>/dev/null | sha256sum)
RUN2=$(python -m picodome sandbox --format json echo deterministic 2>/dev/null | sha256sum)
diff <(echo "$RUN1") <(echo "$RUN2")
```

- See [determinism-failure.md](determinism-failure.md) for detailed troubleshooting

### 5. Self-Test Failure

```bash
python -m picodome sandbox echo "ci-test"
```

- Ensure the subprocess backend is working
- On Linux: check that libseccomp is available for the seccomp backend
- On macOS: check that sandbox-exec is available for the seatbelt backend

### 6. Coverage Below Threshold

```bash
python -m pytest --cov=picodome --cov-report=term-missing
```

- Add tests for uncovered code paths
- Current threshold: 42%

## Quick Fix: Run Full CI Locally

```bash
bash scripts/ci.sh
```

This runs all checks: mypy, ruff, pytest, determinism verification, and self-test.