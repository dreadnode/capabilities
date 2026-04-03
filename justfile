# Capabilities repo — local development recipes
# https://github.com/casey/just

set dotenv-load := false

default:
    @just --list

# Validate all capabilities across all orgs (pass strict="true" for CI-level checks)
validate strict="false":
    #!/usr/bin/env bash
    set -euo pipefail
    failed=0
    for org_dir in dreadnode trailofbits ghostsecurity; do
        if [[ -d "${org_dir}" ]]; then
            echo "==> ${org_dir}/"
            cmd=(uv run --with dreadnode dreadnode capability validate "${org_dir}")
            [[ "{{ strict }}" == "true" ]] && cmd+=(--strict)
            "${cmd[@]}" || failed=1
            echo ""
        fi
    done
    [[ "${failed}" -eq 0 ]] || exit 1

# Security scan all skills (pass org to scan one, behavioral="true" for deep analysis)
security-scan org="" behavioral="false":
    #!/usr/bin/env bash
    set -euo pipefail
    cmd=(./scripts/security-scan.sh)
    [[ "{{ behavioral }}" == "true" ]] && cmd+=(--behavioral)
    [[ -n "{{ org }}" ]] && cmd+=("{{ org }}")
    "${cmd[@]}"

# Run security scan tests
test-security-scan:
    ./tests/test_security_scan.sh -v

# Sync all capabilities to local platform (requires running API + SDK profile)
sync-local org="" force="false":
    #!/usr/bin/env bash
    set -euo pipefail
    server="${DREADNODE_LOCAL_API_URL:-http://localhost:8000}"
    base=(--server "$server")
    [[ -n "${DREADNODE_API_KEY:-}" ]] && base+=(--api-key "$DREADNODE_API_KEY")

    if [[ -n "{{ org }}" ]]; then
        orgs=("{{ org }}")
    else
        orgs=(dreadnode trailofbits ghostsecurity)
    fi

    for org_dir in "${orgs[@]}"; do
        if [[ -d "${org_dir}" ]]; then
            echo "==> Syncing ${org_dir}/ to local"
            cmd=(uv run --with dreadnode dreadnode capability sync "${org_dir}")
            cmd+=("${base[@]}" --organization "${org_dir}")
            [[ "{{ force }}" == "true" ]] && cmd+=(--force)
            "${cmd[@]}"
            echo ""
        fi
    done

# Mirror repo dreadnode capabilities into ~/.dreadnode/capabilities
sync-dreadnode-files:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "${HOME}/.dreadnode/capabilities"
    rsync -a --delete --delete-excluded --exclude '.DS_Store' dreadnode/ "${HOME}/.dreadnode/capabilities/"
