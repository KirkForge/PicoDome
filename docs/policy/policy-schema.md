# Policy schema v1 (starter)

PicoDome is a runtime sandbox. Enterprise deployments require a first-class, **deny-by-default** policy model.

This document defines a *starter* policy schema and semantics. It is designed to be:
- deterministic
- easy to audit
- backend-aware (seccomp/seatbelt/subprocess)

> Note: This schema is a proposal until enforced by code.

## Goals

- Make allowed behavior explicit.
- Make denied behavior explicit.
- Produce a stable **policy hash** for evidence.

## File format

YAML is recommended (`.yml`). TOML could be supported later.

## Top-level structure

```yaml
version: 1
name: deny-by-default
mode: deny

# Optional: human description
description: "Default enterprise posture: deny everything not explicitly allowed"

# Backend constraints
backends:
  linux_seccomp: true
  macos_seatbelt: true
  subprocess: true

# Execution controls
exec:
  allowlist:
    - "python3"
    - "node"
  denylist:
    - "curl"
    - "wget"

# Filesystem controls (logical)
fs:
  read_allowlist:
    - "./"          # workspace
    - "/usr/lib/"    # runtime libs
  write_allowlist:
    - "./"          # workspace only
    - "/tmp/"

# Network controls (logical)
network:
  mode: deny         # deny|allow
  allowlist:
    - "registry.npmjs.org"

# Environment controls
env:
  pass_through:
    - "PATH"
    - "HOME"
  denylist:
    - "AWS_.*"
    - "GITHUB_TOKEN"

# Resource limits
limits:
  cpu_seconds: 30
  wall_seconds: 60
  memory_mb: 512

# Evidence controls
evidence:
  include_policy_hash: true
  include_backend: true
```

## Semantics

### mode

- `deny`: deny-by-default. Anything not explicitly allowed is blocked (or flagged for subprocess).
- `allow`: allow-by-default. Generally not recommended for enterprise.

### exec.allowlist / exec.denylist

- Logical command allowlist. For true enforcement backends, this may map to path restrictions; for subprocess, it is enforced by pre-checks.

### fs controls

- `read_allowlist` and `write_allowlist` define logical path constraints.
- For seccomp, filesystem restrictions require external controls (container mounts, user permissions). For seatbelt, it can map into profile rules.

### network controls

- `network.mode: deny` is recommended.
- For Linux seccomp alone, network requires external controls; for seatbelt, it can be part of profile; for subprocess, it is best-effort detection.

### env controls

- `pass_through` defines which environment variables are forwarded.
- `denylist` supports regex-like patterns.

### limits

- Used to configure timeouts and memory caps where supported.

### evidence

- Enables embedding policy hash/version and backend identity into JSON/SARIF outputs.

## Policy hash

Canonical policy hash recommendation:

1) Normalize YAML (stable key ordering) or parse into a canonical JSON structure.
2) Compute `sha256(canonical_bytes)`.

The **policy hash** should be included in every output and audit event.

## Examples

- `examples/policies/deny-by-default.yml`
- `examples/policies/npm-install.yml`
- `examples/policies/python-pip-install.yml`

## Compatibility notes

This schema is backend-aware:

- **seccomp**: syscall enforcement; fs/network need external controls.
- **seatbelt**: maps well to path + network restrictions.
- **subprocess**: detection-only; must be clearly labeled.

The schema should be implemented incrementally:
- v1: exec/env/limits/evidence
- v2: deeper filesystem/network mapping + per-rule allowlists
