# PicoDome — Gaps and Priorities

> **Maturity:** pre-1.0 beta · **Updated:** 2026-05-30

This document lists real gaps between PicoDome's current state and production readiness. No scores, no percentages — just honest assessments.

## Core Product (✅ works, tested)

- L3 sandbox backends: seccomp-bpf, seatbelt, subprocess — all functional
- L4 behavioral analysis: 5 detector rules — all functional
- 10 L3 suspicious pattern detectors — all functional
- CLI: sandbox, analyze, pipeline, rules, diff, verify-determinism — all functional
- 6 output formats — all functional
- Deterministic output guarantee — enforced by 4-layer guard stack
- Daemon mode with HTTP API, token auth, rate limiting — tests pass

## Gaps by Priority

### P0 — Must-fix before 1.0

- **No production deployment evidence** — daemon, K8s admission webhook, gRPC transport have tests but zero real-world usage
- **No independent security review** — threat model exists but no external audit
- **seccomp-bpf is not a containment boundary** — documented, but users may still over-trust it. Composition guide with bubblewrap/gVisor needs more visibility

### P1 — Important for production use

- **K8s admission webhook** — Helm chart + code exist, but untested outside unit tests. Needs real cluster testing.
- **gRPC transport** — code + tests exist, not deployed anywhere
- **Multi-tenancy** — tenant store/API tests pass, but no multi-tenant deployment exists
- **mTLS cert rotation** — code + tests, but no production CA integration
- **Redis-backed features** — rate limiting and baseline storage require external Redis, untested at scale

### P2 — Nice to have

- **Sigstore/Rekor notary integration** — code exists but not in release pipeline
- **Cluster manager / fleet deployment** — code exists, zero deployment
- **Prometheus metrics** — endpoint is scrapable, no proven dashboards
- **Hermetic builds** — pip still pulls from PyPI during build
- **Byte-for-byte reproducible Python wheels** — not yet achieved

### P3 — Future work

- **Web UI dashboard** — no code exists
- **Large-scale perf data** — no benchmarks above single-machine scale
- **SLSA L3 end-to-end verification** — provenance generated, not yet verified in a production pipeline
