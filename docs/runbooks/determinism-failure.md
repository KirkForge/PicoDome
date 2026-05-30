# Runbook: Determinism Verification Failure

## Severity: HIGH (core thesis violation)

## Symptoms

- `--verify-determinism` flag reports hash mismatch
- `picodome diff a.json b.json` reports different results
- CI determinism gate fails

## Investigation Steps

1. **Reproduce the failure:**
   ```bash
   picodome sandbox --format json --deterministic-output --verify-determinism <command>
   ```

2. **Compare two runs:**
   ```bash
   picodome sandbox --format json --deterministic-output <command> > run_a.json
   picodome sandbox --format json --deterministic-output <command> > run_b.json
   picodome diff run_a.json run_b.json --verbose
   ```

3. **Check for common causes:**
   - **Non-deterministic sorting:** Findings or events not sorted by sort_key()
   - **Random IDs:** uuid4() or random values leaking into findings
   - **Timestamps:** ISO timestamps or duration_ms in deterministic output
   - **Network calls:** DNS resolution or HTTP requests during scan time
   - **Filesystem ordering:** os.listdir() results vary across runs
   - **Process timing:** Race conditions in subprocess output capture

4. **Run the determinism guard:**
   ```python
   from picodome.guards import DeterministicGuard
   guard = DeterministicGuard()
   violations = guard.check(result)
   for v in violations:
       print(f"VIOLATION: {v}")
   ```

## Root Cause Analysis

The determinism guarantee is: **same command + same policy = same output, every time.**

If this is violated, one of these is leaking in:

| Source | Detection | Fix |
|--------|-----------|-----|
| UUID in finding_id | Guard check | Use empty string in deterministic mode |
| Timestamp in message | Guard check | Remove timestamps from deterministic output |
| Unsorted dict keys | Guard check | Use `sort_keys=True` in JSON dumps |
| Floating point timing | Hash mismatch | Exclude duration_ms from deterministic hash |
| os.listdir() ordering | Hash mismatch | Sort directory listings |
| Thread race | Intermittent | Use deterministic test fixtures |

## Fix

1. Add the non-deterministic value to the exclusion list in `to_dict(deterministic=True)`
2. Ensure `DeterministicGuard` catches the pattern
3. Add a test case that verifies determinism for the affected code path
4. Run `python -m pytest tests/test_guards.py -v`

## Prevention

- Always use `--deterministic-output` in CI pipelines
- Always use `--verify-determinism` before releases
- The determinism gate in CI runs the scan twice and compares hashes