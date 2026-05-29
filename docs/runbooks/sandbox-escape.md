# Runbook: Sandbox Escape Response

## Severity: CRITICAL

## Symptoms

- L3 sandbox reports `KILL` verdict from seccomp-bpf
- Process exits with signal 31 (SIGSYS) on Linux
- Process exits with `EPERM` from seccomp-bpf (non-fatal denial)
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

3. **Distinguish fatal vs non-fatal denials:**
   - `SIGSYS` (exit 31): The process was killed by seccomp. This means the syscall is not in the allow-list and the policy uses `KILL_PROCESS`.
   - `EPERM` (Operation not permitted): The syscall was denied but the process received an error instead of being killed. This is `SCMP_ACT_ERRNO(EPERM)`.

4. **Check policy:**
   ```bash
   irondome sandbox --format json --policy <policy_file> <command>
   ```
   Verify the policy is deny-by-default and only allows necessary operations.

5. **Test with permissive policy:**
   Temporarily switch to a more permissive policy to confirm the escape vector.

6. **Check for missing runtime syscalls:**
   Default-deny policies omit `clone`, `clone3`, `fork`, `vfork`, `wait4`, and `socket` from the safe set. Package managers like `npm` and `pip` need process-spawning syscalls. Use `--allow-runtime node` or `--allow-runtime python` to add them.

## Understanding the Sandbox Boundary

> **IronDome's seccomp-bpf backend is a syscall policy harness, not a full containment boundary.**

The seccomp filter prevents syscalls that are not in the allow-list, but it does **not** provide:

- **Filesystem isolation**: Processes with `open`/`write` in the safe set can access host files
- **Namespace isolation**: No mount, PID, network, or user namespaces
- **Resource limits**: No `setrlimit` or `cgroups`; fork bombs affect the host
- **`PR_SET_NO_NEW_PRIVS`**: Not set explicitly; filter may not survive `execve` in all configurations

If a sandboxed process needs true containment, compose IronDome with `bubblewrap`, `gVisor`, or a container runtime.

## Mitigation

- **Immediate:** The seccomp-bpf filter already denied the syscall — the escape was prevented at the syscall level.
- **Follow-up:** Update the default policy to block the specific syscall pattern.
- **Containment:** If the process had `open`/`write` in its safe set, it could still access host files. Compose with `bubblewrap` or `gVisor` for filesystem containment.
- **Report:** File a security advisory at https://github.com/KirkForge/IronDome/security/advisories/new

## Escalation

If a process bypasses the seccomp-bpf filter entirely, this is a kernel-level vulnerability:
1. Document the exact kernel version and seccomp filter configuration
2. File a security advisory immediately
3. Consider the subprocess backend as a fallback (it uses pattern analysis, not kernel enforcement)

If a process accesses host files while under seccomp policy, this is expected behavior (seccomp filters syscalls, not paths):
1. Add `bubblewrap` or `gVisor` for filesystem isolation
2. Consider reducing the safe syscall set to remove `open`/`write` if not needed
3. Use `--allow-runtime` profiles for common package managers instead of manual policy construction
