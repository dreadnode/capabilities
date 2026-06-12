#!/usr/bin/env bash
# security-scan.sh — Run NVIDIA SkillSpector across all capabilities
#
# Usage:
#   ./scripts/security-scan.sh                      # scan all capabilities, summary
#   ./scripts/security-scan.sh web-security         # scan one capability
#   ./scripts/security-scan.sh --format json        # JSON output
#   ./scripts/security-scan.sh --sarif FILE         # SARIF output
#
# Requires: uv (https://docs.astral.sh/uv/)
# Package:  skillspector (installed from git, see pyproject.toml)
#
# Note: SkillSpector is not yet on PyPI. We install from the public
# GitHub repo. Use --no-llm in CI to keep scans deterministic and avoid
# needing provider API keys.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# SkillSpector is not published to PyPI yet; install from git.
SCANNER="uvx --from git+https://github.com/NVIDIA/SkillSpector skillspector"

# Auto-discover capability directories under capabilities/
CAPABILITY_DIRS=()
for dir in "${REPO_ROOT}"/capabilities/*/; do
    dir="$(basename "${dir}")"
    if [[ -f "${REPO_ROOT}/capabilities/${dir}/capability.yaml" ]]; then
        CAPABILITY_DIRS+=("${dir}")
    fi
done

# Defaults
FORMAT="terminal"
TARGET_CAPABILITY=""
OUTPUT_SARIF=""
OUTPUT_JSON=""
NO_LLM=true
EXTRA_ARGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [CAPABILITY]

Scan capabilities for security issues using NVIDIA SkillSpector.

Options:
  --format FMT      Output format: terminal|json|markdown|sarif [default: terminal]
  --sarif FILE      Write SARIF report to FILE
  --json FILE       Write JSON report to FILE
  --llm             Enable LLM semantic analysis (requires API keys)
  -h, --help        Show this help

Arguments:
  CAPABILITY        Scan only this capability directory (e.g. web-security)

Examples:
  $(basename "$0")                    # scan everything, summary output
  $(basename "$0") web-security       # scan one capability
  $(basename "$0") --format sarif --sarif report.sarif
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --sarif)
            OUTPUT_SARIF="$2"
            FORMAT="sarif"
            shift 2
            ;;
        --json)
            OUTPUT_JSON="$2"
            FORMAT="json"
            shift 2
            ;;
        --llm)
            NO_LLM=false
            shift
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
    local output_path="$2"
    local cmd=(${SCANNER} scan "${REPO_ROOT}/capabilities/${cap_dir}")
    cmd+=(--format "${FORMAT}")

    if [[ "${NO_LLM}" == true ]]; then
        cmd+=(--no-llm)
    fi

    if [[ -n "${output_path}" ]]; then
        cmd+=(--output "${output_path}")
    fi

    cmd+=("${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}")

    echo "${cmd[@]}"
}

# Run scans
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

    output_path=""
    if [[ -n "${OUTPUT_SARIF}" ]]; then
        output_path="${OUTPUT_SARIF}"
    elif [[ -n "${OUTPUT_JSON}" ]]; then
        output_path="${OUTPUT_JSON}"
    fi

    cmd=$(build_cmd "${cap_dir}" "${output_path}")

    # SkillSpector exits 1 when risk_score > 50. Security-focused
    # capabilities often score high, so we report findings but do not
    # fail the wrapper by default. CI can decide whether to gate merges.
    if eval "${cmd}"; then
        echo "    ✓ ${cap_dir}/ scan completed"
    else
        exit_code=$?
        echo "    ⚠ ${cap_dir}/ scan completed with findings (exit ${exit_code})"
    fi
    echo ""
done
