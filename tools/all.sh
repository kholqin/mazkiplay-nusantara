#!/usr/bin/env bash

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0

COVERAGE_MIN="${COVERAGE_MIN:-70}"

run_step() {
    local name="$1"
    shift

    echo
    echo "=================================================="
    echo "[ALL] $name"
    echo "=================================================="

    if "$@"; then
        echo "[PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $name"
        FAIL=$((FAIL + 1))
    fi
}

echo
echo "╔══════════════════════════════════════════════════╗"
echo "║        MAZKIPLAY NUSANTARA / ALL QA             ║"
echo "╚══════════════════════════════════════════════════╝"
echo
echo "ROOT: $ROOT"
echo "PYTHON: $(python --version 2>&1)"
echo "COVERAGE MIN: ${COVERAGE_MIN}%"
echo

run_step \
    "Python compilation" \
    python -m compileall -q app modules tests

run_step \
    "Test collection" \
    python -m pytest --collect-only -q

run_step \
    "Full test suite" \
    python -m pytest -q

run_step \
    "Coverage quality gate" \
    bash -c '
        python -m pytest \
            --cov=app \
            --cov=modules \
            --cov-report=term-missing \
            --cov-fail-under="$1"
    ' _ "$COVERAGE_MIN"

run_step \
    "CLI smoke test" \
    python -m app.cli --help

run_step \
    "Repository hygiene" \
    bash -c '
        set -eu

        forbidden=0

        while IFS= read -r file; do
            case "$file" in
                *.pyc|*.pyo)
                    echo "[HYGIENE] generated Python artifact: $file"
                    forbidden=1
                    ;;
                */__pycache__/*)
                    echo "[HYGIENE] cache directory: $file"
                    forbidden=1
                    ;;
                *.bak|*.old|*.before-*|*.orig)
                    echo "[HYGIENE] backup artifact: $file"
                    forbidden=1
                    ;;
            esac
        done < <(git ls-files --cached --others --exclude-standard)

        if git diff --cached --name-only | grep -E \
            "(^|/)(\.env|.*\.pem|.*\.key)$" >/dev/null 2>&1; then
            echo "[HYGIENE] possible secret/key staged"
            forbidden=1
        fi

        if [ "$forbidden" -ne 0 ]; then
            exit 1
        fi

        echo "[HYGIENE] No forbidden tracked/untracked artifacts detected."
    '

echo
echo "=================================================="
echo "[ALL] Repository status"
echo "=================================================="

git status --short

echo
echo "=================================================="
echo "[ALL] Diff summary"
echo "=================================================="

git diff --stat

echo
echo "=================================================="
echo "[ALL] Summary"
echo "=================================================="

echo "PASSED STEPS : $PASS"
echo "FAILED STEPS : $FAIL"

if [ "$FAIL" -eq 0 ]; then
    echo
    echo "STATUS: ALL QA PASSED"
    exit 0
else
    echo
    echo "STATUS: QA FAILED"
    exit 1
fi
