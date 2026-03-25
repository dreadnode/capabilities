#!/usr/bin/env bash
# test_security_scan.sh — Integration tests for the security scanning setup.
#
# Verifies that:
#   1. The scanner is installable and runnable
#   2. The custom policy loads without errors
#   3. Individual skill scans produce valid output
#   4. Batch scanning works across orgs
#   5. CI mode produces SARIF output
#   6. The --fail-on-severity flag works correctly
#   7. A deliberately malicious skill is caught
#
# Usage:
#   ./tests/test_security_scan.sh           # run all tests
#   ./tests/test_security_scan.sh -v        # verbose output
#
# Requires: uv, jq

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCANNER="uvx --from cisco-ai-skill-scanner skill-scanner"
PASS=0
FAIL=0
VERBOSE=false
TMPDIR_BASE=""

[[ "${1:-}" == "-v" ]] && VERBOSE=true

# --- Helpers -------------------------------------------------------------

cleanup() {
    if [[ -n "${TMPDIR_BASE}" && -d "${TMPDIR_BASE}" ]]; then
        rm -rf "${TMPDIR_BASE}"
    fi
}
trap cleanup EXIT

setup_tmpdir() {
    TMPDIR_BASE="$(mktemp -d)"
}

pass() {
    PASS=$((PASS + 1))
    echo "  ✓ $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "  ✗ $1"
    if [[ "${VERBOSE}" == true && -n "${2:-}" ]]; then
        echo "    ${2}"
    fi
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "${expected}" == "${actual}" ]]; then
        pass "${desc}"
    else
        fail "${desc}" "expected='${expected}' actual='${actual}'"
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "${haystack}" | grep -qF -- "${needle}"; then
        pass "${desc}"
    else
        fail "${desc}" "output does not contain '${needle}'"
    fi
}

assert_file_exists() {
    local desc="$1" path="$2"
    if [[ -f "${path}" ]]; then
        pass "${desc}"
    else
        fail "${desc}" "file not found: ${path}"
    fi
}

assert_exit_code() {
    local desc="$1" expected="$2"
    shift 2
    local actual=0
    "$@" > /dev/null 2>&1 || actual=$?
    if [[ "${expected}" -eq "${actual}" ]]; then
        pass "${desc}"
    else
        fail "${desc}" "expected exit ${expected}, got ${actual}"
    fi
}

# --- Tests ---------------------------------------------------------------

echo "=== Security Scan Tests ==="
echo ""
setup_tmpdir

# 1. Scanner is available
echo "[1] Scanner availability"
if ${SCANNER} --version > /dev/null 2>&1; then
    pass "skill-scanner is available via uvx"
else
    fail "skill-scanner is not available"
    echo "FATAL: Cannot continue without scanner. Install with: pip install cisco-ai-skill-scanner"
    exit 1
fi

# 2. Custom policy loads
echo ""
echo "[2] Custom policy"
output=$(${SCANNER} scan-all "${REPO_ROOT}/dreadnode" \
    --recursive --lenient \
    --policy "${REPO_ROOT}/scan-policy.yaml" \
    --format json --compact 2>&1) || true
assert_contains "policy loads without errors" "${output}" '"summary"'

# Extract policy name from output
policy_name=$(echo "${output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    r = data.get('results', [{}])[0]
    print(r.get('scan_metadata', {}).get('policy_name', ''))
except: print('')
" 2>/dev/null) || true
assert_eq "policy name is 'capabilities'" "capabilities" "${policy_name}"

# 3. Individual skill scan
echo ""
echo "[3] Individual skill scan"
# Find a real skill to test
skill_dir=$(find "${REPO_ROOT}/dreadnode" -name "SKILL.md" -type f -print -quit 2>/dev/null | xargs dirname)
if [[ -n "${skill_dir}" ]]; then
    scan_out=$(${SCANNER} scan "${skill_dir}" \
        --lenient --policy "${REPO_ROOT}/scan-policy.yaml" \
        --format json --compact 2>&1)
    assert_contains "scan produces valid JSON" "${scan_out}" '"skill_name"'
    assert_contains "scan includes is_safe field" "${scan_out}" '"is_safe"'
    assert_contains "scan includes analyzers_used" "${scan_out}" '"analyzers_used"'

    # Verify static + bytecode + pipeline analyzers ran
    analyzers=$(echo "${scan_out}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(' '.join(data.get('analyzers_used', [])))
except: print('')
" 2>/dev/null) || true
    assert_contains "static analyzer ran" "${analyzers}" "static"
    assert_contains "pipeline analyzer ran" "${analyzers}" "pipeline"
else
    fail "no skills found to test"
fi

# 4. Batch scan produces summary
echo ""
echo "[4] Batch scanning"
batch_out=$(${SCANNER} scan-all "${REPO_ROOT}/dreadnode" \
    --recursive --lenient \
    --policy "${REPO_ROOT}/scan-policy.yaml" \
    --format json --compact 2>&1)
total=$(echo "${batch_out}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('summary', {}).get('total_skills_scanned', 0))
except: print(0)
" 2>/dev/null) || true

if [[ "${total}" -gt 0 ]]; then
    pass "batch scan found ${total} skills"
else
    fail "batch scan found no skills"
fi

# 5. SARIF output
echo ""
echo "[5] SARIF output"
sarif_file="${TMPDIR_BASE}/test.sarif"
${SCANNER} scan-all "${REPO_ROOT}/dreadnode" \
    --recursive --lenient \
    --policy "${REPO_ROOT}/scan-policy.yaml" \
    --format sarif \
    --output-sarif "${sarif_file}" 2>/dev/null || true
assert_file_exists "SARIF file created" "${sarif_file}"

if [[ -f "${sarif_file}" ]]; then
    sarif_version=$(python3 -c "
import json
with open('${sarif_file}') as f:
    data = json.load(f)
print(data.get('version', ''))
" 2>/dev/null) || true
    assert_eq "SARIF version is 2.1.0" "2.1.0" "${sarif_version}"

    sarif_tool=$(python3 -c "
import json
with open('${sarif_file}') as f:
    data = json.load(f)
print(data.get('runs', [{}])[0].get('tool', {}).get('driver', {}).get('name', ''))
" 2>/dev/null) || true
    assert_eq "SARIF tool is skill-scanner" "skill-scanner" "${sarif_tool}"
fi

# 6. Fail-on-severity flag
echo ""
echo "[6] Severity threshold"
# Use pre-built malicious skill fixture
malicious_dir="${REPO_ROOT}/tests/fixtures/malicious-skill"

# This should find issues (redirect stderr to avoid warnings corrupting JSON)
malicious_out=$(${SCANNER} scan "${malicious_dir}" \
    --lenient --format json --compact 2>/dev/null) || true
is_safe=$(echo "${malicious_out}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(str(data.get('is_safe', True)).lower())
except: print('true')
" 2>/dev/null) || true
assert_eq "malicious skill detected as unsafe" "false" "${is_safe}"

findings_count=$(echo "${malicious_out}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('findings_count', 0))
except: print(0)
" 2>/dev/null) || true

if [[ "${findings_count}" -gt 0 ]]; then
    pass "malicious skill produced ${findings_count} findings"
else
    fail "malicious skill produced no findings"
fi

# --fail-on-severity should return non-zero for malicious content
set +e
${SCANNER} scan "${malicious_dir}" \
    --lenient --format json --compact \
    --fail-on-severity medium > /dev/null 2>&1
exit_code=$?
set -e
if [[ "${exit_code}" -ne 0 ]]; then
    pass "--fail-on-severity returns non-zero for malicious skill"
else
    fail "--fail-on-severity returned 0 for malicious skill" "exit code: ${exit_code}"
fi

# Clean skill fixture should pass
clean_dir="${REPO_ROOT}/tests/fixtures/clean-skill"
clean_out=$(${SCANNER} scan "${clean_dir}" \
    --lenient --format json --compact 2>&1) || true
clean_safe=$(echo "${clean_out}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(str(data.get('is_safe', False)).lower())
except: print('false')
" 2>/dev/null) || true
assert_eq "clean skill detected as safe" "true" "${clean_safe}"

# 7. Script wrapper
echo ""
echo "[7] Script wrapper"
assert_file_exists "security-scan.sh exists" "${REPO_ROOT}/scripts/security-scan.sh"
if [[ -x "${REPO_ROOT}/scripts/security-scan.sh" ]]; then
    pass "security-scan.sh is executable"
else
    fail "security-scan.sh is not executable"
fi

# Test --help
help_out=$("${REPO_ROOT}/scripts/security-scan.sh" --help 2>&1) || true
assert_contains "help shows usage" "${help_out}" "Usage"
assert_contains "help shows --ci flag" "${help_out}" "--ci"

# Test wrapper runs successfully on a single org
wrapper_out=$("${REPO_ROOT}/scripts/security-scan.sh" dreadnode 2>&1) || true
assert_contains "wrapper scans dreadnode" "${wrapper_out}" "dreadnode"

# 8. Behavioral analysis
echo ""
echo "[8] Behavioral analysis"
behavioral_out=$(${SCANNER} scan "${skill_dir}" \
    --lenient --use-behavioral \
    --policy "${REPO_ROOT}/scan-policy.yaml" \
    --format json --compact 2>&1) || true
assert_contains "behavioral analyzer available" "${behavioral_out}" "behavioral"

# --- Summary -------------------------------------------------------------
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
