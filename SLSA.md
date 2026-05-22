# SLSA — Supply-chain Levels for Software Artifacts

**Project:** IronDome v0.3.0  
**Target Level:** SLSA Build Level 3 (L3)  
**Date:** 2026-05-22  

---

## Current Status

IronDome is working toward **SLSA Build L3** compliance. Current security measures:

| SLSA Requirement | Status | Implementation |
|-----------------|--------|---------------|
| Scripted Build | ✅ | `.github/workflows/release.yml` — fully automated |
| Build as Code | ✅ | `pyproject.toml` — declarative build config |
| Ephemeral Environment | ✅ | GitHub Actions `ubuntu-latest` runners |
| Isolated Build | ✅ | `python -m build` in clean venv |
| Parameterless | ✅ | No user-controlled build params (only version tag) |
| Hermetic | ⚠️ | `pip install` pulls from PyPI (no offline mirror yet) |
| Reproducible | ✅ | Deterministic sandbox output (SHA-256 repeatable on identical inputs). Python wheel builds not yet byte-for-byte reproducible. |
| Provenance Generation | ✅ | `slsa-github-generator` v2.0.0 integrated in `release.yml`. SLSA L3 provenance generated on every tag push. |
| Verification | ✅ | `scripts/verify-slsa.sh` for SLSA L3 verification + `scripts/verify_release.sh` for Sigstore. CI job `slsa-verify` runs on every release. |

---

## Build Pipeline (release.yml)

```
git tag v0.3.0 → push → CI triggers:
  1. Quality Gates (tests + mypy + ruff, Python 3.10–3.13)
  2. Determinism Gate (verify-determinism on sample sandbox runs)
  3. Build (python -m build + twine check)
  4. Sigstore Signing (OIDC identity: release.yml workflow)
  5. GitHub Release (auto-generated notes + assets)
  6. PyPI Publish (Trusted Publishing via OIDC, attestations enabled)
  7. Sigstore signatures attached to GitHub Release + PyPI
  8. SLSA L3 provenance generated (slsa-github-generator)
  9. SLSA provenance verified end-to-end (slsa-verifier CI job)
```

---

## Verification

### Sigstore (Current)

```bash
python -m sigstore verify identity \
  --cert-identity "https://github.com/KirkForge/IronDome/.github/workflows/release.yml@refs/tags/v0.3.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  irondome-0.3.0-py3-none-any.whl
```

### SLSA L3 (Active)

SLSA L3 provenance is generated and verified on every tagged release. Verification runs automatically in CI via the `slsa-verify` job.

```bash
slsa-verifier verify-artifact \
  --source-uri github.com/KirkForge/IronDome \
  --source-tag v0.3.0 \
  irondome-0.3.0-py3-none-any.whl
```

### Determinism Verification (IronDome-specific)

In addition to SLSA provenance, IronDome verifies that the *tool itself* produces deterministic output:

```bash
# Verify IronDome produces identical output on identical inputs
irondome sandbox python3 -c "print('hello')" --verify-determinism
# Expected: "✓ DETERMINISM VERIFIED — results are deterministic"

# Compare two saved result files
irondome diff result_a.json result_b.json
# Expected: "✓ Results are IDENTICAL — determinism verified"
```

This is a stronger guarantee than SLSA alone: not only can you verify *where* the build came from, but you can verify *what* it does is reproducible.

---

## Roadmap to SLSA L3

1. ✅ **slsa-github-generator** integration for non-forgeable provenance
2. ✅ **SLSA L3 verification** in CI (slsa-verify job)
3. ✅ **Sigstore signing** via OIDC with Trusted Publishing
4. ✅ **Determinism gate** in CI (verify-determinism step)
5. **Offline mirror** for pip dependencies (hermetic builds)
6. **Reproducible builds** via pinned dependency hashes and SOURCE_DATE_EPOCH
7. **Verification CLI** shipped with the package (`irondome verify --slsa`)

---

## Attestation

```
Project:  KirkForge/IronDome
Version:  v0.3.0
Build:    GitHub Actions (release.yml)
Signer:   Sigstore (OIDC via GitHub Actions)
Rekor:    https://rekor.sigstore.dev
Target:   SLSA Build L3
Status:   Active — Sigstore signing + SLSA L3 provenance generated and verified
Extra:    Determinism verification gate in CI (SHA-256 identical output on identical inputs)
```