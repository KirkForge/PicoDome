# Runbook: Sandbox Escape Response

## Severity: CRITICAL

## Symptoms

- L3 sandbox reports `KILL` verdict from seccomp-bpf
- Process exits with signal 31 (SIGSYS) on Linux
- Seatbelt denies operation on macOS
- Unexpected `L3-SECCOMP-KILL` events in sandbox output

## Investigation Steps

1. **Capture the event:**
   ```bash
   irondome sandbox --format json <command> > sandbox_result.json
   ```

2. **Examine denied syscalls:**
   Look for `L3-SECCOMP-KILL` events in the JSON output.
   Check `detail` and `operation` fields for the blocked syscall.

3. **Check policy:**
   ```bash
   irondome sandbox --format json --policy <policy_file> <command>
   ```
   Verify the policy is deny-by-default and only allows necessary operations.

4. **Test with permissive policy:**
   Temporarily switch to a more permissive policy to confirm the escape vector.

## Mitigation

- **Immediate:** The seccomp-bpf filter already killed the process — the escape was prevented.
- **Follow-up:** Update the default policy to block the specific syscall pattern.
- **Report:** File a security advisory at https://github.com/KirkForge/IronDome/security/advisories/new

## Escalation

If a process bypasses the seccomp-bpf filter entirely, this is a kernel-level vulnerability:
1. Document the exact kernel version and seccomp filter configuration
2. File a security advisory immediately
3. Consider the subprocess backend as a fallback (it uses pattern analysis, not kernel enforcement)