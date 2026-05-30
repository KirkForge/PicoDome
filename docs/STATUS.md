# PicoDome — CI and Project Status

> **Updated:** 2026-05-30

## CI Status

- **GitHub Actions billing exhausted** — CI runs will fail until billing resets
- **Local CI**: 1406 tests passing, mypy clean, ruff clean
- **Pre-push**: `ci-cleandev` hooks run locally before push

## Recent Changes

- Renamed from PicoDome to PicoDome (branding, package name `picodome`)
- Honest STATE.md replaces enterprise readiness docs
- Honest GAPS.md replaces inflated gap analysis
- Removed: ENTERPRISE_GAP_ANALYSIS.md, ENTERPRISE_READINESS.md, ENTERPRISE_ROADMAP.md, ENTERPRISE_PILOT_LIMITATIONS.md, SOC2_TYPE_I.md, EVIDENCE_MATRIX.md

## Known Issues

- GitHub Actions billing exhausted (resets in ~2 days)
- `picodome` CLI alias still works for backward compat; `picodome` is primary
- SLSA L3 provenance generated but hermetic builds not yet achieved
- compliance/ directory still has VULNERABILITY_MANAGEMENT.md — needs review
