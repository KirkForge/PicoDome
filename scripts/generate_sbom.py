#!/usr/bin/env python3
"""Generate CycloneDX SBOM for IronDome.

Produces a CycloneDX JSON SBOM from installed packages,
including IronDome version, Python version, and dependencies.

Usage:
    python scripts/generate_sbom.py                  # stdout
    python scripts/generate_sbom.py -o sbom.json     # write to file
    python scripts/generate_sbom.py --pretty          # pretty-printed JSON
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── IronDome version ───────────────────────────────────────────────
try:
    from irondome import __version__ as IRONDOME_VERSION
except ImportError:
    IRONDOME_VERSION = "unknown"


def get_installed_packages() -> list[dict[str, Any]]:
    """Get list of installed Python packages via pip."""
    import subprocess

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True,
        )
        packages = json.loads(result.stdout)
        return [
            {
                "name": pkg["name"],
                "version": pkg["version"],
            }
            for pkg in packages
        ]
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return []


def get_irondome_dependencies() -> list[dict[str, Any]]:
    """Get IronDome's declared dependencies from importlib.metadata."""
    try:
        from importlib.metadata import requires

        deps = requires("irondome") or []
        components: list[dict[str, Any]] = []
        for dep in deps:
            # Remove extras markers for clean display
            name = dep.split(">=")[0].split("==")[0].split("<")[0].split(">")[0].split("[")[0].split(";")[0].strip()
            components.append({"name": name, "version": "(runtime)"})
        return components
    except Exception:
        return []


def generate_sbom(output: str | None = None, pretty: bool = True) -> str:
    """Generate a CycloneDX SBOM.

    Args:
        output: Output file path (None = stdout).
        pretty: Pretty-print JSON.

    Returns:
        SBOM as JSON string.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Get installed packages
    installed = get_installed_packages()

    # Build package lookup
    pkg_versions: dict[str, str] = {pkg["name"].lower(): pkg["version"] for pkg in installed}

    # IronDome dependencies from pyproject.toml
    irondome_deps = [
        "pytest",
        "pytest-cov",
        "pyyaml",
    ]

    # Build components list
    components: list[dict[str, Any]] = []

    # Add IronDome itself as the main component
    components.append(
        {
            "type": "application",
            "name": "irondome",
            "version": IRONDOME_VERSION,
            "description": "Iron Dome — deterministic runtime sandbox and behavioral analysis for supply-chain security",
            "purl": f"pkg:pypi/irondome@{IRONDOME_VERSION}",
            "properties": [
                {"name": "python:version", "value": platform.python_version()},
                {"name": "python:implementation", "value": platform.python_implementation()},
                {"name": "system:platform", "value": platform.platform()},
                {"name": "system:os", "value": platform.system()},
                {"name": "system:arch", "value": platform.machine()},
            ],
        }
    )

    # Add IronDome dependencies
    for dep_name in irondome_deps:
        dep_lower = dep_name.lower()
        version = pkg_versions.get(dep_lower, "unknown")
        components.append(
            {
                "type": "library",
                "name": dep_name,
                "version": version,
                "purl": f"pkg:pypi/{dep_name}@{version}" if version != "unknown" else f"pkg:pypi/{dep_name}",
            }
        )

    # Add all installed packages as dependencies
    for pkg in installed:
        name_lower = pkg["name"].lower()
        if name_lower not in {d.lower() for d in irondome_deps} and name_lower != "irondome":
            components.append(
                {
                    "type": "library",
                    "name": pkg["name"],
                    "version": pkg["version"],
                    "purl": f"pkg:pypi/{pkg['name']}@{pkg['version']}",
                    "scope": "required",
                }
            )

    # Build SBOM
    sbom: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.5.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{os.urandom(16).hex()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "component": {
                "type": "application",
                "name": "irondome",
                "version": IRONDOME_VERSION,
                "description": "Iron Dome — deterministic runtime sandbox and behavioral analysis for supply-chain security",
                "purl": f"pkg:pypi/irondome@{IRONDOME_VERSION}",
            },
            "tools": [
                {
                    "vendor": "KirkForge",
                    "name": "irondome-sbom-generator",
                    "version": "1.0.0",
                }
            ],
            "authors": [
                {
                    "name": "KirkForge",
                }
            ],
        },
        "components": components,
        "dependencies": [
            {
                "ref": f"pkg:pypi/irondome@{IRONDOME_VERSION}",
                "dependsOn": [f"pkg:pypi/{dep}@{pkg_versions.get(dep.lower(), 'unknown')}" for dep in irondome_deps],
            }
        ],
    }

    indent = 2 if pretty else None
    sbom_json = json.dumps(sbom, indent=indent, sort_keys=False, default=str)

    if output:
        Path(output).write_text(sbom_json + "\n", encoding="utf-8")
        print(f"SBOM written to {output}", file=sys.stderr)
    else:
        print(sbom_json)

    return sbom_json


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate CycloneDX SBOM for IronDome",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (default: stdout)",
        default=None,
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON (default: True)",
    )
    parser.add_argument(
        "--no-pretty",
        action="store_false",
        dest="pretty",
        help="Compact JSON output",
    )
    args = parser.parse_args()

    try:
        generate_sbom(output=args.output, pretty=args.pretty)
        return 0
    except Exception as e:
        print(f"Error generating SBOM: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
