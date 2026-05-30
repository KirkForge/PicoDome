#!/usr/bin/env bash
# ─── Reproducible Build Script for PicoDome ─────────────────────────────────
#
# This script performs a bit-for-bit reproducible build by:
# 1. Setting SOURCE_DATE_EPOCH for deterministic timestamps
# 2. Running pip install with --no-build-isolation and hash-checking mode
# 3. Building the wheel with PYTHONHASHSEED=0
# 4. Verifying the output hash matches a reference build
#
# Usage:
#   ./scripts/reproducible_build.sh [SOURCE_DATE_EPOCH]
#
# Environment variables:
#   SOURCE_DATE_EPOCH - If set, used for all timestamps (recommended: CI sets this)
#   PYTHONHASHSEED    - If set, used for hash randomization (default: 0)
#   IRONDOME_OFFLINE  - If set, build in offline/air-gapped mode (default: 1)
#   IRONDOME_REQUIRE_HASHES - If set, require hash verification (default: 1)

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/dist"
REFERENCE_HASH_FILE="${PROJECT_DIR}/.build-hash-reference"

# Source date epoch: use env var, then arg, then current time truncated to day
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    EPOCH="${SOURCE_DATE_EPOCH}"
elif [ -n "${1:-}" ]; then
    EPOCH="$1"
else
    # Default: truncate to start of current day (UTC) for reproducibility
    EPOCH="$(date -u +%Y-%m-%d -d today | xargs -I{} date -u -d "{}" +%s)"
fi

export SOURCE_DATE_EPOCH="${EPOCH}"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export PYTHONUTF8=1
export LC_ALL=C.UTF-8

IRONDOME_OFFLINE="${IRONDOME_OFFLINE:-1}"
IRONDOME_REQUIRE_HASHES="${IRONDOME_REQUIRE_HASHES:-1}"

echo "═══════════════════════════════════════════════════════════════════"
echo "  PicoDome Reproducible Build"
echo "═══════════════════════════════════════════════════════════════════"
echo "  SOURCE_DATE_EPOCH : ${EPOCH}"
echo "  PYTHONHASHSEED    : ${PYTHONHASHSEED}"
echo "  Project dir       : ${PROJECT_DIR}"
echo "  Build dir         : ${BUILD_DIR}"
echo "  Offline           : ${IRONDOME_OFFLINE}"
echo "  Require hashes    : ${IRONDOME_REQUIRE_HASHES}"
echo "═══════════════════════════════════════════════════════════════════"

cd "${PROJECT_DIR}"

# ─── Step 1: Clean previous builds ───────────────────────────────────────────

echo ""
echo "▶ Step 1: Cleaning previous builds..."
rm -rf "${BUILD_DIR}"
rm -rf "${PROJECT_DIR}/build"
mkdir -p "${BUILD_DIR}"

# ─── Step 2: Verify dependencies (if requirements.txt exists) ─────────────────

echo ""
echo "▶ Step 2: Verifying dependencies..."

PIP_ARGS=(
    "--no-build-isolation"
)

if [ "${IRONDOME_REQUIRE_HASHES}" = "1" ]; then
    PIP_ARGS+=("--require-hashes")
fi

if [ "${IRONDOME_OFFLINE}" = "1" ]; then
    PIP_ARGS+=("--offline" 2>/dev/null) || true
fi

# Check for requirements file with hashes
REQ_FILE="${PROJECT_DIR}/requirements.txt"
if [ -f "${REQ_FILE}" ]; then
    echo "  Found requirements.txt — verifying hashes..."
    if [ "${IRONDOME_REQUIRE_HASHES}" = "1" ]; then
        # Check that requirements.txt has hash lines
        HASH_COUNT=$(grep -c "^--hash=" "${REQ_FILE}" 2>/dev/null || echo "0")
        if [ "${HASH_COUNT}" = "0" ]; then
            echo "  ⚠  requirements.txt has no --hash lines — generating hash requirements..."
            pip hash "${REQ_FILE}" 2>/dev/null || echo "  ⚠  Could not hash requirements (pip hash not available)"
        fi
    fi
else
    echo "  No requirements.txt found — skipping dependency verification"
fi

# ─── Step 3: Build the wheel ──────────────────────────────────────────────────

echo ""
echo "▶ Step 3: Building wheel with PYTHONHASHSEED=0..."

# Build with python -m build (or fallback to setup.py)
if python3 -m build --version &>/dev/null; then
    echo "  Using python -m build"
    python3 -m build \
        --no-build-isolation \
        --wheel \
        --outdir "${BUILD_DIR}" \
        "${PROJECT_DIR}"
else
    echo "  Using setup.py bdist_wheel (fallback)"
    python3 setup.py bdist_wheel \
        --dist-dir "${BUILD_DIR}" \
        --build-number "" \
        2>&1 || {
        echo "  ⚠  setup.py build failed — trying pip wheel..."
        pip wheel \
            --no-build-isolation \
            --wheel-dir "${BUILD_DIR}" \
            "${PROJECT_DIR}"
    }
fi

# ─── Step 4: Fix wheel timestamps ────────────────────────────────────────────

echo ""
echo "▶ Step 4: Fixing wheel timestamps to epoch..."

WHEEL_FILE=$(find "${BUILD_DIR}" -name "*.whl" -type f | head -1)

if [ -z "${WHEEL_FILE}" ]; then
    echo "  ✗ No wheel file found in ${BUILD_DIR}"
    exit 1
fi

echo "  Found wheel: $(basename "${WHEEL_FILE}")"

# Use reproducible.py to verify and fix timestamps
python3 -c "
import sys
sys.path.insert(0, '${PROJECT_DIR}/src')
from irondome.reproducible import verify_reproducible_build
result = verify_reproducible_build('${WHEEL_FILE}')
if result['violations']:
    print('  ⚠  Timestamp violations found:')
    for v in result['violations']:
        print(f'    - {v}')
else:
    print('  ✓ No timestamp violations — wheel is reproducible')
print(f'  Wheel hash: {result[\"wheel_hash\"]}')
"

# ─── Step 5: Compute and verify build hash ────────────────────────────────────

echo ""
echo "▶ Step 5: Computing build hash..."

BUILD_HASH=$(sha256sum "${WHEEL_FILE}" | cut -d' ' -f1)
echo "  SHA-256: ${BUILD_HASH}"
echo "  Wheel  : $(basename "${WHEEL_FILE}")"

# Save current build hash
echo "${BUILD_HASH}" > "${BUILD_DIR}/.build-hash"
echo "$(basename "${WHEEL_FILE}")" >> "${BUILD_DIR}/.build-hash"

# Compare with reference if it exists
if [ -f "${REFERENCE_HASH_FILE}" ]; then
    REFERENCE_HASH=$(head -1 "${REFERENCE_HASH_FILE}")
    if [ "${BUILD_HASH}" = "${REFERENCE_HASH}" ]; then
        echo ""
        echo "  ✓ BUILD IS REPRODUCIBLE — hash matches reference"
        echo "    Reference: ${REFERENCE_HASH}"
        echo "    Current:   ${BUILD_HASH}"
    else
        echo ""
        echo "  ✗ BUILD IS NOT REPRODUCIBLE — hash differs from reference"
        echo "    Reference: ${REFERENCE_HASH}"
        echo "    Current:   ${BUILD_HASH}"
        echo ""
        echo "  If this is expected (e.g., version bump), update the reference:"
        echo "    echo '${BUILD_HASH}' > ${REFERENCE_HASH_FILE}"
        exit 1
    fi
else
    echo ""
    echo "  ℹ  No reference hash file found — creating one"
    echo "  ${BUILD_HASH}" > "${REFERENCE_HASH_FILE}"
    echo "  Future builds will be compared against this hash"
fi

# ─── Step 6: Generate build manifest ─────────────────────────────────────────

echo ""
echo "▶ Step 6: Generating build manifest..."

python3 -c "
import sys
sys.path.insert(0, '${PROJECT_DIR}/src')
from irondome.reproducible import generate_build_manifest
manifest_path = generate_build_manifest('${PROJECT_DIR}')
print(f'  Manifest written to: {manifest_path}')
"

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  ✓ Reproducible build complete"
echo "  Wheel: ${WHEEL_FILE}"
echo "  Hash:  ${BUILD_HASH}"
echo "  Epoch: ${EPOCH}"
echo "═══════════════════════════════════════════════════════════════════"