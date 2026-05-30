# Security: Release Integrity

## Sigstore Signing

Every PicoDome release is signed with Sigstore using OIDC identity from GitHub Actions. This provides non-forgeable proof that the release was built in CI.

### Verifying a Release

```bash
# Install sigstore
pip install sigstore

# Verify a wheel
python -m sigstore verify identity \
  --cert-identity "https://github.com/KirkForge/PicoDome/.github/workflows/release.yml@refs/tags/v0.3.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  picodome-0.5.0-py3-none-any.whl
```

### SLSA L3 Provenance

SLSA provenance is generated on every tagged release using `slsa-github-generator`.

```bash
# Verify SLSA provenance
slsa-verifier verify-artifact \
  --source-uri github.com/KirkForge/PicoDome \
  --source-tag v0.3.0 \
  picodome-0.5.0-py3-none-any.whl
```

## Supply Chain

PicoDome has **zero hard runtime dependencies**. The only dependencies are:
- `pyyaml>=6.0` (optional, for .picodome.yml config files)
- `libseccomp` (optional, system library for Linux seccomp-bpf backend)
- Dev dependencies: pytest, mypy, ruff, build, twine, sigstore

This minimal attack surface is by design. We will not add runtime dependencies without strong justification.

## Determinism Guarantee

PicoDome's core thesis: **same command + same policy = same output, every time.**

If you find a case where PicoDome produces different results on identical inputs (without policy changes), that is a **high-severity bug**. Report it through private GitHub advisories.

Verify determinism with:
```bash
picodome sandbox --format json --deterministic-output --verify-determinism <command>
# Should output: "✓ Determinism verified: <hash>"

# Or compare two saved results:
picodome sandbox --format json <command> > a.json
picodome sandbox --format json <command> > b.json
picodome diff a.json b.json
# Should output: "✓ Results are IDENTICAL"
```