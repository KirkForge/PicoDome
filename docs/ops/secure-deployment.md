# Secure deployment guide (starter)

PicoDome executes untrusted code under policy. Enterprise safety depends heavily on *how you deploy it*.

This guide provides an opinionated “safe posture” for CI and build hosts.

## Recommended posture (default)

- Run on dedicated CI runners / build hosts.
- Run as **non-root**.
- Do **not** pass secrets into the sandboxed process.
- Prefer **seccomp (Linux)** or **seatbelt (macOS)** backends.
- Treat **subprocess fallback** as detection-only and last resort.

---

## A) Host and container posture

### A1) User permissions

- Create a dedicated user (no sudo) to run PicoDome.
- Ensure workspace directories have least privilege.

### A2) Filesystem

- Prefer read-only filesystem for the runner container.
- Mount a single writable workspace directory.
- Avoid mounting `$HOME` or credential directories.

### A3) Network

- Recommended: **restrict outbound network** for sandboxed runs.
- If network is required, scope allowlists to known package registries.

---

## B) Backend selection

PicoDome auto-detects the strongest available backend.

Recommended:
- Linux: seccomp
- macOS: seatbelt
- Other: subprocess (last resort)

Document the actual backend used in outputs and logs.

---

## C) Policy posture

- Use **deny-by-default** policies.
- Keep policies versioned in repo.
- Include policy hash/version in output evidence.

---

## D) CI integration

### D1) Determinism

- Keep determinism gate enabled.
- Avoid timestamps/random IDs in evidence.

### D2) Artifacts

- Persist JSON/SARIF outputs as artifacts.
- Persist audit logs if enabled.

---

## E) Deployment checklist

- [ ] Runs as non-root
- [ ] Secrets not injected into sandboxed env
- [ ] Restricted mounts (workspace only)
- [ ] Network restricted or allowlisted
- [ ] Prefer seccomp/seatbelt, subprocess only as fallback
- [ ] Policy is deny-by-default and versioned
- [ ] Determinism gate enabled
- [ ] Outputs archived (JSON/SARIF)
- [ ] Audit logs enabled for shared use

## F) Audit log forwarding

PicoDome ships three audit sink types:

| Sink | Use case |
|------|----------|
| `FileSink` | Local append-only JSONL with hash-chain integrity and rotation |
| `SyslogSink` | RFC 5424 UDP forwarding to syslog / SIEM collectors |
| `WebhookSink` | HTTP POST to external systems (Slack, PagerDuty, custom) |

To forward audit events to a central log system:

1. **Syslog/CEF**: Point `SyslogSink` at your log aggregator (rsyslog, syslog-ng, Splunk).
2. **HTTP webhooks**: Configure `WebhookSink` with your endpoint URL and secret.
3. **File + shipper**: Use `FileSink` and tail the JSONL with Filebeat/Fluentd/Fluent Bit.

Set `IRONDOME_AUDIT_SINK` to `file`, `syslog`, `webhook`, or a comma-separated combination.

This is a starter guide intended to evolve into a hardened reference deployment.
