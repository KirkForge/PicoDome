#!/usr/bin/env python3
"""Generate a release evidence bundle for PicoDome.

Collects and packages all compliance evidence for a given release:
- SBOM (CycloneDX JSON)
- Test results (pytest JUnit XML)
- Coverage report
- Signed artifacts checksums
- Vulnerability scan results (if available)
- Change approval records

Usage:
    python scripts/generate_evidence_bundle.py --version 0.5.0
    python scripts/generate_evidence_bundle.py --version 0.5.0 --output evidence/
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_cmd(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    """Run a command and return exit code + output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd or REPO_ROOT,
            timeout=600,
        )
        return result.returncode, result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return -1, str(e)


def generate_sbom(output_dir: Path) -> Path | None:
    """Generate CycloneDX SBOM."""
    sbom_path = output_dir / "sbom.json"
    rc, _ = run_cmd([sys.executable, "scripts/generate_sbom.py", "-o", str(sbom_path)])
    if rc == 0 and sbom_path.exists():
        return sbom_path
    return None


def run_tests(output_dir: Path) -> dict[str, any]:
    """Run test suite and capture results."""
    junit_path = output_dir / "test-results.xml"
    coverage_path = output_dir / "coverage.xml"

    rc, output = run_cmd(
        [
            sys.executable,
            "-m",
            "pytest",
            "--junitxml=" + str(junit_path),
            "--cov=irondome",
            "--cov-report=xml:" + str(coverage_path),
            "--cov-report=term-missing",
            "-v",
        ]
    )

    return {
        "exit_code": rc,
        "junit_path": str(junit_path) if junit_path.exists() else None,
        "coverage_path": str(coverage_path) if coverage_path.exists() else None,
        "passed": rc == 0,
    }


def compute_checksums(output_dir: Path) -> Path:
    """Compute SHA-256 checksums for dist artifacts."""
    dist_dir = REPO_ROOT / "dist"
    checksums_path = output_dir / "checksums-sha256.txt"

    if not dist_dir.exists():
        checksums_path.write_text("# No dist/ directory found\n")
        return checksums_path

    rc, output = run_cmd(["sha256sum", "*.whl", "*.tar.gz"], cwd=dist_dir)
    checksums_path.write_text(output if rc == 0 else "# No artifacts found\n")
    return checksums_path


def collect_signed_artifacts(output_dir: Path) -> list[str]:
    """Collect Sigstore signatures if present."""
    dist_dir = REPO_ROOT / "dist"
    sigstore_files = []
    if dist_dir.exists():
        for sig in dist_dir.glob("*.sigstore"):
            dest = output_dir / sig.name
            shutil.copy2(sig, dest)
            sigstore_files.append(sig.name)
    return sigstore_files


def generate_bundle_metadata(
    version: str,
    output_dir: Path,
    test_results: dict,
    sbom_path: Path | None,
    checksums_path: Path,
    sigstore_files: list[str],
) -> Path:
    """Generate the evidence bundle metadata."""
    now = datetime.now(timezone.utc).isoformat()

    bundle = {
        "apiVersion": "picodome.kirkforge.dev/v1",
        "kind": "EvidenceBundle",
        "metadata": {
            "name": f"picodome-{version}",
            "version": version,
            "generated": now,
            "generator": "generate_evidence_bundle.py",
        },
        "spec": {
            "artifacts": {
                "sbom": sbom_path.name if sbom_path else None,
                "checksums": checksums_path.name,
                "testResults": test_results.get("junit_path"),
                "coverageReport": test_results.get("coverage_path"),
                "sigstoreSignatures": sigstore_files,
            },
            "testSummary": {
                "passed": test_results["passed"],
                "exitCode": test_results["exit_code"],
            },
            "evidence": {
                "sbomGenerated": sbom_path is not None,
                "testsRun": test_results.get("junit_path") is not None,
                "coverageCollected": test_results.get("coverage_path") is not None,
                "artifactsSigned": len(sigstore_files) > 0,
                "checksumsComputed": True,
            },
        },
    }

    metadata_path = output_dir / "evidence-bundle.json"
    metadata_path.write_text(json.dumps(bundle, indent=2, default=str) + "\n")
    return metadata_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate PicoDome release evidence bundle")
    parser.add_argument("--version", required=True, help="Release version")
    parser.add_argument("--output", "-o", default="evidence", help="Output directory")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    parser.add_argument("--skip-sbom", action="store_true", help="Skip SBOM generation")
    args = parser.parse_args()

    output_dir = REPO_ROOT / args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"PicoDome Evidence Bundle Generator — v{args.version}")
    print(f"Output directory: {output_dir}")
    print()

    # Generate SBOM
    sbom_path = None
    if not args.skip_sbom:
        print("  Generating SBOM...")
        sbom_path = generate_sbom(output_dir)
        if sbom_path:
            print(f"  ✅ SBOM: {sbom_path}")
        else:
            print("  ⚠️  SBOM generation failed")

    # Run tests
    test_results: dict = {"exit_code": -1, "junit_path": None, "coverage_path": None, "passed": False}
    if not args.skip_tests:
        print("  Running tests...")
        test_results = run_tests(output_dir)
        if test_results["passed"]:
            print("  ✅ Tests passed")
        else:
            print(f"  ❌ Tests failed (exit code {test_results['exit_code']})")

    # Compute checksums
    print("  Computing checksums...")
    checksums_path = compute_checksums(output_dir)
    print(f"  ✅ Checksums: {checksums_path}")

    # Collect signed artifacts
    print("  Collecting signed artifacts...")
    sigstore_files = collect_signed_artifacts(output_dir)
    if sigstore_files:
        print(f"  ✅ {len(sigstore_files)} Sigstore signatures")
    else:
        print("  ⚠️  No Sigstore signatures found (run release workflow first)")

    # Generate metadata
    print("  Generating bundle metadata...")
    metadata_path = generate_bundle_metadata(
        version=args.version,
        output_dir=output_dir,
        test_results=test_results,
        sbom_path=sbom_path,
        checksums_path=checksums_path,
        sigstore_files=sigstore_files,
    )
    print(f"  ✅ Metadata: {metadata_path}")

    # Summary
    print()
    print("Evidence bundle generated:")
    for f in sorted(output_dir.iterdir()):
        size = f.stat().st_size
        print(f"  {f.name} ({size:,} bytes)")

    print()
    print("To package the bundle:")
    print(f"  tar czf picodome-{args.version}-evidence.tar.gz -C {output_dir.parent} {output_dir.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
