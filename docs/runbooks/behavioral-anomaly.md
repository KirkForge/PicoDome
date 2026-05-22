# Runbook: L4 Behavioral Anomaly Response

## Severity: HIGH to CRITICAL (varies by rule)

## Symptoms

- L4 analysis reports `MALICIOUS` or `SUSPICIOUS` verdict
- Specific L4 rules trigger findings:
  - L4-TIME: Anomalous timing (no-op, busy-wait, unusual delays)
  - L4-EXFIL: Data exfiltration (suspicious DNS, credential reads + network)
  - L4-ENTROPY: High-entropy filenames or DGA domains
  - L4-HONEY: Honeypot path access or priv-esc binary spawns
  - L4-BASE: Baseline drift from known-good profiles

## Investigation Steps

1. **Run full pipeline:**
   ```bash
   irondome pipeline --format json --verbose <command> > pipeline_result.json
   ```

2. **Examine findings:**
   ```bash
   # Extract findings by severity
   cat pipeline_result.json | python3 -c "
   import json, sys
   data = json.load(sys.stdin)
   for f in data.get('analysis', {}).get('findings', []):
       if f['severity'] in ('CRITICAL', 'HIGH'):
           print(f'{f[\"rule_id\"]}: {f[\"message\"]}')" 
   ```

3. **Compare against baseline:**
   ```bash
   irondome sandbox --format json npm install > baseline.json
   irondome analyze --input baseline.json
   ```
   Check if the observed behavior matches a shipped baseline.

4. **Check for false positives:**
   - L4-TIME: Is the command inherently slow? Try with a longer timeout.
   - L4-EXFIL: Is the DNS query to a known CDN? Check against allowlist.
   - L4-ENTROPY: Is the high-entropy name a legitimate hash (e.g., webpack chunk)?
   - L4-HONEY: Did the command legitimately need to access the flagged path?
   - L4-BASE: Is the baseline outdated? Consider updating it.

## Mitigation

- **Severity overrides:** Use `.irondome.yml` config to adjust severity:
  ```yaml
  severity_overrides:
    L4-TIME: low
    L4-ENTROPY: info
  ```

- **Custom baselines:** Create a baseline for the specific command pattern:
  ```bash
  irondome sandbox --format json <command> > custom_baseline.json
  ```

- **Policy tuning:** Adjust the L3 policy to be more restrictive for known-safe operations.

## Escalation

If findings indicate genuine supply-chain compromise:
1. Stop using the affected package immediately
2. Document all findings with `--format sarif` for GitHub integration
3. Report to the package maintainer and security advisory databases