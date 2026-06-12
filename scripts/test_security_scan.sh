#!/usr/bin/env bash
# test_security_scan.sh — Integration tests for the SkillSpector scanning setup.
#
# Verifies that:
#   1. SkillSpector is installable and runnable from git
#   2. Individual skill scans produce valid output
#   3. SARIF output is generated and valid
#   4. A deliberately malicious skill scores higher than a clean one
#
# Usage:
#   ./scripts/test_security_scan.sh         # run all tests
#   ./scripts/test_security_scan.sh -v      # verbose output
#
# Requires: uv, jq

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCANNER="uvx --from git+https://github.com/NVIDIA/SkillSpector skillspector"
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

assert_json_field_gt() {
    local desc="$1" file="$2" jpath="$3" min="$4"
    local actual
    actual=$(jq -r "${jpath} // 0" "${file}")
    if [[ "$(echo "${actual} > ${min}" | bc -l)" == "1" ]]; then
        pass "${desc}"
    else
        fail "${desc}" "expected ${jpath} > ${min}, got ${actual}"
    fi
}

# --- Tests ---------------------------------------------------------------

echo "=== Security Scan Tests (SkillSpector) ==="
echo ""
setup_tmpdir

# 1. Scanner is available
echo "[1] Scanner availability"
version_out=$(${SCANNER} --version 2>&1) || true
if echo "${version_out}" | grep -q "SkillSpector"; then
    pass "SkillSpector is available via uvx from git"
else
    fail "SkillSpector is not available"
    echo "FATAL: Cannot continue without scanner."
    exit 1
fi

# 2. Individual skill scan produces JSON
echo ""
echo "[2] Individual skill scan"
skill_dir=$(find "${REPO_ROOT}/capabilities/ai-red-teaming" -name "SKILL.md" -type f -print -quit 2>/dev/null | xargs dirname)
if [[ -n "${skill_dir}" ]]; then
    scan_out=$(${SCANNER} scan "${skill_dir}" --format json --no-llm 2>&1)
    assert_contains "scan produces JSON output" "${scan_out}" '"risk_assessment"'
    assert_contains "scan includes issues array" "${scan_out}" '"issues"'
else
    fail "no skills found to test"
fi

# 3. SARIF output
echo ""
echo "[3] SARIF output"
sarif_file="${TMPDIR_BASE}/test.sarif"
${SCANNER} scan "${skill_dir}" --format sarif --no-llm --output "${sarif_file}" 2>/dev/null || true
assert_file_exists "SARIF file created" "${sarif_file}"

if [[ -f "${sarif_file}" ]]; then
    sarif_version=$(jq -r '.version' "${sarif_file}" 2>/dev/null || true)
    assert_contains "SARIF version is 2.1.0" "${sarif_version}" "2.1.0"

    sarif_tool=$(jq -r '.runs[0].tool.driver.name' "${sarif_file}" 2>/dev/null || true)
    assert_contains "SARIF tool is skillspector" "${sarif_tool}" "skillspector"
fi

# 4. Malicious skill scores higher than clean skill
echo ""
echo "[4] Malicious vs clean skill detection"
malicious_json="${TMPDIR_BASE}/malicious.json"
clean_json="${TMPDIR_BASE}/clean.json"

${SCANNER} scan "${REPO_ROOT}/scripts/fixtures/malicious-skill" \
  --format json --no-llm --output "${malicious_json}" 2>/dev/null || true
${SCANNER} scan "${REPO_ROOT}/scripts/fixtures/clean-skill" \
  --format json --no-llm --output "${clean_json}" 2>/dev/null || true

assert_file_exists "malicious skill JSON report created" "${malicious_json}"
assert_file_exists "clean skill JSON report created" "${clean_json}"

if [[ -f "${malicious_json}" && -f "${clean_json}" ]]; then
    assert_json_field_gt "malicious skill has higher risk score than clean" \
      "${malicious_json}" '.risk_assessment.score' '0'

    clean_score=$(jq -r '.risk_assessment.score // 0' "${clean_json}")
    malicious_score=$(jq -r '.risk_assessment.score // 0' "${malicious_json}")
    if [[ "${malicious_score}" -gt "${clean_score}" ]]; then
        pass "malicious skill (${malicious_score}) scores higher than clean (${clean_score})"
    else
        fail "malicious skill (${malicious_score}) did not score higher than clean (${clean_score})"
    fi

    if [[ "${malicious_score}" -gt 50 ]]; then
        pass "malicious skill exceeds risk threshold (>50)"
    else
        fail "malicious skill did not exceed risk threshold" "score=${malicious_score}"
    fi
fi

# 5. Script wrapper
echo ""
echo "[5] Script wrapper"
assert_file_exists "security-scan.sh exists" "${REPO_ROOT}/scripts/security-scan.sh"
if [[ -x "${REPO_ROOT}/scripts/security-scan.sh" ]]; then
    pass "security-scan.sh is executable"
else
    fail "security-scan.sh is not executable"
fi

help_out=$("${REPO_ROOT}/scripts/security-scan.sh" --help 2>&1) || true
assert_contains "help shows usage" "${help_out}" "Usage"
assert_contains "help shows --format flag" "${help_out}" "--format"

wrapper_out=$("${REPO_ROOT}/scripts/security-scan.sh" ai-red-teaming 2>&1) || true
assert_contains "wrapper scans ai-red-teaming" "${wrapper_out}" "ai-red-teaming"

# --- Summary -------------------------------------------------------------
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
