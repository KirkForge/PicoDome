# Security: Release Integrity

## Sigstore Signing

Every Iron Dome release is signed with Sigstore using OIDC identity from GitHub Actions. This provides non-forgeable proof that the release was built in CI.

### Verifying a Release

```bash
# Install sigstore
pip install sigstore

# Verify a wheel
python -m sigstore verify identity \
  --cert-identity "https://github.com/KirkForge/IronDome/.github/workflows/release.yml@refs/tags/v0.3.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  irondome-0.3.0-py3-none-any.whl
```

### SLSA L3 Provenance

SLSA provenance is generated on every tagged release using `slsa-github-generator`.

```bash
# Verify SLSA provenance
slsa-verifier verify-artifact \
  --source-uri github.com/KirkForge/IronDome \
  --source-tag v0.3.0 \
  irondome-0.3.0-py3-none-any.whl
```

## Supply Chain

Iron Dome has **zero hard runtime dependencies**. The only dependencies are:
- `pyyaml>=6.0` (optional, for .irondome.yml config files)
- `libseccomp` (optional, system library for Linux seccomp-bpf backend)
- Dev dependencies: pytest, mypy, ruff, build, twine, sigstore

This minimal attack surface is by design. We will not add runtime dependencies without strong justification.

## Determinism Guarantee

Iron Dome's core thesis: **same command + same policy = same output, every time.**

If you find a case where IronDome produces different results on identical inputs (without policy changes), that is a **high-severity bug**. Report it through private GitHub advisories.

Verify determinism with:
```bash
irondome sandbox --format json --deterministic-output --verify-determinism <command>
# Should output: "✓ Determinism verified: <hash>"

# Or compare two saved results:
irondome sandbox --format json <command> > a.json
irondome sandbox --format json <command> > b.json
irondome diff a.json b.json
# Should output: "✓ Results are IDENTICAL"
```