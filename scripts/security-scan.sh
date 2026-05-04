#!/usr/bin/env bash
# security-scan.sh — Run cisco-ai-skill-scanner across all capabilities
#
# Usage:
#   ./scripts/security-scan.sh                      # scan all capabilities, summary
#   ./scripts/security-scan.sh web-security         # scan one capability
#   ./scripts/security-scan.sh --format json        # JSON output
#   ./scripts/security-scan.sh --ci                 # CI mode: SARIF + fail on high
#   ./scripts/security-scan.sh --behavioral         # enable behavioral analysis
#
# Requires: uv (https://docs.astral.sh/uv/)
# Package:  cisco-ai-skill-scanner (installed automatically via uvx)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICY="${REPO_ROOT}/scan-policy.yaml"
SCANNER="uvx --from cisco-ai-skill-scanner skill-scanner"

# Auto-discover capability directories under capabilities/
CAPABILITY_DIRS=()
for dir in "${REPO_ROOT}"/capabilities/*/; do
    dir="$(basename "${dir}")"
    if [[ -f "${REPO_ROOT}/capabilities/${dir}/capability.yaml" ]]; then
        CAPABILITY_DIRS+=("${dir}")
    fi
done

# Defaults
FORMAT="summary"
CI_MODE=false
USE_BEHAVIORAL=false
FAIL_SEVERITY=""
OUTPUT_SARIF=""
OUTPUT_JSON=""
TARGET_CAPABILITY=""
EXTRA_ARGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [CAPABILITY]

Scan capabilities for security issues using cisco-ai-skill-scanner.

Options:
  --ci              CI mode: produce SARIF, fail on high+ severity
  --format FMT      Output format: summary|json|markdown|table|sarif|html
  --behavioral      Enable behavioral dataflow analysis (slower, deeper)
  --fail-on SEV     Fail if findings >= severity (critical|high|medium|low)
  --sarif FILE      Write SARIF report to FILE
  --json FILE       Write JSON report to FILE
  -h, --help        Show this help

Arguments:
  CAPABILITY        Scan only this capability directory (e.g. web-security)

Examples:
  $(basename "$0")                    # scan everything, summary output
  $(basename "$0") web-security       # scan one capability
  $(basename "$0") --ci               # CI pipeline mode
  $(basename "$0") --behavioral       # deep analysis
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ci)
            CI_MODE=true
            FORMAT="summary"
            FAIL_SEVERITY="high"
            shift
            ;;
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --behavioral)
            USE_BEHAVIORAL=true
            shift
            ;;
        --fail-on)
            FAIL_SEVERITY="$2"
            shift 2
            ;;
        --sarif)
            OUTPUT_SARIF="$2"
            shift 2
            ;;
        --json)
            OUTPUT_JSON="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            EXTRA_ARGS+=("$1")
            shift
            ;;
        *)
            TARGET_CAPABILITY="$1"
            shift
            ;;
    esac
done

# Resolve which capabilities to scan
if [[ -n "${TARGET_CAPABILITY}" ]]; then
    if [[ ! -d "${REPO_ROOT}/capabilities/${TARGET_CAPABILITY}" ]]; then
        echo "Error: capability directory '${TARGET_CAPABILITY}' not found" >&2
        exit 1
    fi
    CAPABILITY_DIRS=("${TARGET_CAPABILITY}")
fi

# Build scanner command
build_cmd() {
    local cap_dir="$1"
    local cmd=(${SCANNER} scan-all "${REPO_ROOT}/capabilities/${cap_dir}")
    cmd+=(--recursive --lenient)
    cmd+=(--policy "${POLICY}")
    cmd+=(--format "${FORMAT}")

    if [[ "${USE_BEHAVIORAL}" == true ]]; then
        cmd+=(--use-behavioral)
    fi

    if [[ -n "${FAIL_SEVERITY}" ]]; then
        cmd+=(--fail-on-severity "${FAIL_SEVERITY}")
    fi

    if [[ -n "${OUTPUT_SARIF}" ]]; then
        cmd+=(--output-sarif "${OUTPUT_SARIF}")
    fi

    if [[ -n "${OUTPUT_JSON}" ]]; then
        cmd+=(--output-json "${OUTPUT_JSON}")
    fi

    cmd+=("${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}")

    echo "${cmd[@]}"
}

# Run scans
overall_exit=0

for cap_dir in "${CAPABILITY_DIRS[@]}"; do
    if [[ ! -d "${REPO_ROOT}/capabilities/${cap_dir}" ]]; then
        continue
    fi

    # Check if capability has any skills to scan
    skill_count=$(find "${REPO_ROOT}/capabilities/${cap_dir}" -name "SKILL.md" -type f 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${skill_count}" -eq 0 ]]; then
        echo "==> ${cap_dir}/ — no skills found, skipping"
        continue
    fi

    echo "==> Scanning ${cap_dir}/ (${skill_count} skills)"

    cmd=$(build_cmd "${cap_dir}")

    if [[ "${CI_MODE}" == true ]]; then
        # In CI mode, capture SARIF per-capability and merge later
        sarif_file="${REPO_ROOT}/.security-scan-${cap_dir}.sarif"
        cmd="${cmd} --output-sarif ${sarif_file}"
    fi

    if eval "${cmd}"; then
        echo "    ✓ ${cap_dir}/ passed"
    else
        exit_code=$?
        echo "    ✗ ${cap_dir}/ has findings (exit ${exit_code})"
        overall_exit=1
    fi
    echo ""
done

# CI summary
if [[ "${CI_MODE}" == true ]]; then
    sarif_files=()
    for cap_dir in "${CAPABILITY_DIRS[@]}"; do
        f="${REPO_ROOT}/.security-scan-${cap_dir}.sarif"
        if [[ -f "${f}" ]]; then
            sarif_files+=("${f}")
        fi
    done

    if [[ ${#sarif_files[@]} -gt 0 ]]; then
        if [[ -n "${OUTPUT_SARIF}" ]]; then
            cp "${sarif_files[-1]}" "${OUTPUT_SARIF}"
        fi
        echo "SARIF reports: ${sarif_files[*]}"
    fi
fi

if [[ "${overall_exit}" -eq 0 ]]; then
    echo "All scans passed."
else
    echo "Security scan found issues above threshold."
    exit 1
fi
