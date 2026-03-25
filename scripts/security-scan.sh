#!/usr/bin/env bash
# security-scan.sh — Run cisco-ai-skill-scanner across all capabilities
#
# Usage:
#   ./scripts/security-scan.sh                      # scan all orgs, summary
#   ./scripts/security-scan.sh dreadnode             # scan one org
#   ./scripts/security-scan.sh --format json         # JSON output
#   ./scripts/security-scan.sh --ci                  # CI mode: SARIF + fail on high
#   ./scripts/security-scan.sh --behavioral          # enable behavioral analysis
#
# Requires: uv (https://docs.astral.sh/uv/)
# Package:  cisco-ai-skill-scanner (installed automatically via uvx)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICY="${REPO_ROOT}/scan-policy.yaml"
SCANNER="uvx --from cisco-ai-skill-scanner skill-scanner"

# Auto-discover org directories (any top-level dir containing capability.yaml)
ORG_DIRS=()
for dir in "${REPO_ROOT}"/*/; do
    dir="$(basename "${dir}")"
    if find "${REPO_ROOT}/${dir}" -maxdepth 2 -name "capability.yaml" -quit 2>/dev/null | grep -q .; then
        ORG_DIRS+=("${dir}")
    fi
done

# Defaults
FORMAT="summary"
CI_MODE=false
USE_BEHAVIORAL=false
FAIL_SEVERITY=""
OUTPUT_SARIF=""
OUTPUT_JSON=""
TARGET_ORG=""
EXTRA_ARGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [ORG]

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
  ORG               Scan only this org directory (e.g. dreadnode)

Examples:
  $(basename "$0")                    # scan everything, summary output
  $(basename "$0") dreadnode          # scan one org
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
            TARGET_ORG="$1"
            shift
            ;;
    esac
done

# Resolve which orgs to scan
if [[ -n "${TARGET_ORG}" ]]; then
    if [[ ! -d "${REPO_ROOT}/${TARGET_ORG}" ]]; then
        echo "Error: org directory '${TARGET_ORG}' not found" >&2
        exit 1
    fi
    ORG_DIRS=("${TARGET_ORG}")
fi

# Build scanner command
build_cmd() {
    local org_dir="$1"
    local cmd=(${SCANNER} scan-all "${REPO_ROOT}/${org_dir}")
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

for org_dir in "${ORG_DIRS[@]}"; do
    if [[ ! -d "${REPO_ROOT}/${org_dir}" ]]; then
        continue
    fi

    # Check if org has any skills to scan
    skill_count=$(find "${REPO_ROOT}/${org_dir}" -name "SKILL.md" -type f 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${skill_count}" -eq 0 ]]; then
        echo "==> ${org_dir}/ — no skills found, skipping"
        continue
    fi

    echo "==> Scanning ${org_dir}/ (${skill_count} skills)"

    cmd=$(build_cmd "${org_dir}")

    if [[ "${CI_MODE}" == true ]]; then
        # In CI mode, capture SARIF per-org and merge later
        sarif_file="${REPO_ROOT}/.security-scan-${org_dir}.sarif"
        cmd="${cmd} --output-sarif ${sarif_file}"
    fi

    if eval "${cmd}"; then
        echo "    ✓ ${org_dir}/ passed"
    else
        exit_code=$?
        echo "    ✗ ${org_dir}/ has findings (exit ${exit_code})"
        overall_exit=1
    fi
    echo ""
done

# CI summary
if [[ "${CI_MODE}" == true ]]; then
    sarif_files=()
    for org_dir in "${ORG_DIRS[@]}"; do
        f="${REPO_ROOT}/.security-scan-${org_dir}.sarif"
        if [[ -f "${f}" ]]; then
            sarif_files+=("${f}")
        fi
    done

    if [[ ${#sarif_files[@]} -gt 0 ]]; then
        # If a single SARIF output was requested, use the last org's file
        # For multi-org, each is available as .security-scan-{org}.sarif
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
