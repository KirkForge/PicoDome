#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# ci.sh — Pre-push CI gate for IronDome
#
# Runs the same checks as the CI pipeline locally so you catch
# failures before pushing. Exits 1 on any failure.
#
# Usage:
#   ./scripts/ci.sh           # run all checks
#   ./scripts/ci.sh --quick   # skip determinism verification
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

QUICK=0
if [[ "${1:-}" == "--quick" ]]; then
    QUICK=1
fi

PASS=0
FAIL=0

section() {
    echo ""
    echo -e "${YELLOW}━━━ $1 ━━━${NC}"
}

pass() {
    echo -e "  ${GREEN}✓ $1${NC}"
    ((PASS++)) || true
}

fail() {
    echo -e "  ${RED}✗ $1${NC}"
    ((FAIL++)) || true
}

# ── Lint ──────────────────────────────────────────────────────────
section "Ruff Lint"
if command -v ruff &>/dev/null; then
    if ruff check src/ tests/; then
        pass "ruff check"
    else
        fail "ruff check"
    fi
else
    echo "  ⚠ ruff not installed, skipping lint"
fi

# ── Format ───────────────────────────────────────────────────────
section "Ruff Format"
if command -v ruff &>/dev/null; then
    if ruff format --check src/ tests/; then
        pass "ruff format check"
    else
        fail "ruff format check"
    fi
else
    echo "  ⚠ ruff not installed, skipping format check"
fi

# ── Type Check ────────────────────────────────────────────────────
section "Mypy Type Check"
if command -v mypy &>/dev/null; then
    if mypy src/irondome; then
        pass "mypy"
    else
        fail "mypy"
    fi
else
    echo "  ⚠ mypy not installed, skipping type check"
fi

# ── Tests ─────────────────────────────────────────────────────────
section "Pytest"
if python -m pytest -v --tb=short 2>/dev/null; then
    pass "pytest"
else
    fail "pytest"
fi

# ── Determinism Verification ──────────────────────────────────────
if [[ $QUICK -eq 0 ]]; then
    section "Determinism Verification"
    echo "  Running Iron Dome sandbox twice in deterministic mode..."
    RUN1=$(python -m irondome sandbox --deterministic-output --format json echo "ci-test" 2>/dev/null | sha256sum)
    RUN2=$(python -m irondome sandbox --deterministic-output --format json echo "ci-test" 2>/dev/null | sha256sum)
    echo "  Run 1: ${RUN1%% *}"
    echo "  Run 2: ${RUN2%% *}"
    if [[ "$RUN1" == "$RUN2" ]]; then
        pass "determinism gate (SHA-256 match)"
    else
        fail "determinism gate (SHA-256 mismatch)"
    fi
else
    section "Determinism Verification (SKIPPED --quick)"
fi

# ── Self-Test ─────────────────────────────────────────────────────
section "Self-Test (Pipeline)"
if python -m irondome pipeline echo "ci-test" 2>/dev/null; then
    pass "irondome pipeline echo ci-test"
else
    fail "irondome pipeline echo ci-test"
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}━━━ Summary ━━━${NC}"
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n${RED}CI FAILED — fix errors before pushing${NC}"
    exit 1
else
    echo -e "\n${GREEN}CI PASSED — safe to push${NC}"
    exit 0
fi