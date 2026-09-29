#!/usr/bin/env bash
# Install CLI tools for the web-security capability.
# Runs at sandbox provision time via dependencies.scripts.
set -euo pipefail

ARCH="$(uname -m)"
OS="$(uname -s)"

case "$OS" in
  Linux) ;;
  *)
    echo "web-security sandbox provisioning supports Linux; manage local CLI dependencies separately on $OS" >&2
    exit 0
    ;;
esac

export PATH="$HOME/.pdtm/go/bin:$HOME/go/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH"

# Keep errexit inside each stage, but let independent stages finish. Do not
# invoke the subshell in an `if` or `||`: bash would disable errexit inside it.
failed_stages=()
run_stage() {
  local name="$1" status
  shift
  echo "web-security: starting $name" >&2
  set +e
  ( set -e; "$@" )
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    failed_stages+=("$name")
    echo "web-security: $name failed (exit $status)" >&2
  fi
}

# Retry commands that fetch dependencies, at most three times. The SDK's
# aggregate install deadline still bounds the entire pass.
retry() {
  local attempt status
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    else
      status=$?
    fi
    [ "$attempt" -eq 3 ] && return "$status"
    echo "web-security: retrying $1 after attempt $attempt" >&2
    sleep "$attempt"
  done
}

# Stage downloads and clones in an invocation-local temporary directory.
INSTALL_TMP="$(mktemp -d)"
trap 'rm -rf "$INSTALL_TMP"' EXIT

clone_repo() {
  local url="$1" target="$2" staging
  shift 2
  staging="$(mktemp -d "$INSTALL_TMP/clone.XXXXXX")" || return
  git clone --depth 1 "$@" "$url" "$staging" && mv "$staging" "$target"
}

# `have <tool>` — is this already on PATH, or in one of the two directories the
# tools below install into?
#
# Every fetch in this script is guarded on the artefact it would produce, so a
# runtime image that already carries the tooling completes without a single
# outbound request. That matters beyond speed: self-hosted deployments run with
# no route to the internet, and this script runs on every sandbox boot where
# the capability changed, so an unguarded download is a repeated outbound
# attempt that cannot succeed. It is also why versions are pinned rather than
# `@latest` — an unpinned install re-resolves against the network even when the
# binary is present, and produces a different tool set on different days.
have() {
  command -v "$1" >/dev/null 2>&1 \
    || [ -x "$HOME/.pdtm/go/bin/$1" ] \
    || [ -x "$HOME/go/bin/$1" ]
}

# Some vendor tooling installs into root-owned paths. Whether this script runs
# as root depends on the image, so escalate only when needed and only when it
# is available — and let the caller decide what a failure means.
as_root() {
  if [ "$(id -u)" = "0" ]; then
    "$@"
  else
    sudo -n "$@" 2>/dev/null
  fi
}

# Target the selected Python interpreter. Virtualenv installs run as the
# current user; system installs use root privileges and system-package flags.
py_install() {
  local python in_venv uv
  local -a command system_flags
  python="$(command -v python3)" || return
  in_venv="$("$python" -c 'import sys; print(int(sys.prefix != sys.base_prefix))')" || return
  if uv="$(command -v uv)"; then
    command=("$uv" pip install --python "$python")
    system_flags=(--system --break-system-packages)
  else
    command=("$python" -m pip install)
    system_flags=(--break-system-packages)
  fi
  if [ "$in_venv" = 1 ]; then
    "${command[@]}" "$@"
  else
    as_root "${command[@]}" "${system_flags[@]}" "$@"
  fi
}

GO_TOOL_VERSIONS_protoscope="v0.0.0-20221109213918-8e7a6aafa2c9"
GO_TOOL_VERSIONS_interactsh="v1.3.1"
GO_TOOL_VERSIONS_2fa="v1.2.0"
GO_VERSION="1.26.6"
KATANA_VERSION="1.7.0"
KITERUNNER_VERSION="v1.0.2"

have_pd_tool() {
  if [ "$1" = "httpx" ]; then
    # Python's httpx package also installs an `httpx` CLI; only
    # ProjectDiscovery's answers `-version`.
    { command -v httpx >/dev/null 2>&1 && httpx -version >/dev/null 2>&1; } \
      || { [ -x "$HOME/.pdtm/go/bin/httpx" ] && "$HOME/.pdtm/go/bin/httpx" -version >/dev/null 2>&1; } \
      || { [ -x "$HOME/go/bin/httpx" ] && "$HOME/go/bin/httpx" -version >/dev/null 2>&1; }
  else
    have "$1"
  fi
}

install_pd_tool() {
  local tool="$1" package="$2" version="$3"
  have_pd_tool "$tool" && return
  mkdir -p "$HOME/.pdtm/go/bin"
  GOBIN="$HOME/.pdtm/go/bin" retry go install "${package}@${version}"
  have_pd_tool "$tool"
}

# What is actually missing, before anything is fetched.
missing_go_tools=""
for tool in protoscope interactsh-client 2fa; do
  have "$tool" || missing_go_tools="$missing_go_tools $tool"
done
missing_pd_tools=""
for tool in nuclei httpx subfinder naabu dnsx uncover alterx tlsx asnmap; do
  have_pd_tool "$tool" || missing_pd_tools="$missing_pd_tools $tool"
done

# -- Go toolchain (only when something still has to be built) --------------
# Deliberately last in the decision order: the toolchain is a ~150 MB download
# whose only purpose is building the tools above. If they are all present it is
# never needed, so it is never requested.
need_go=false
[ -n "$missing_go_tools" ] && need_go=true
[ -n "$missing_pd_tools" ] && need_go=true
have kr || need_go=true
install_go() {
  if [ "$need_go" = true ] && ! command -v go &>/dev/null; then
    case "$ARCH" in
      aarch64|arm64) GOARCH="arm64" ;;
      *)             GOARCH="amd64" ;;
    esac
    retry curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o "$INSTALL_TMP/go.tar.gz"
    as_root tar -xzf "$INSTALL_TMP/go.tar.gz" -C /usr/local
    go version
  fi
}
run_stage go install_go

# -- ProjectDiscovery tools ------------------------------------------------
if [ -n "$missing_pd_tools" ]; then
  run_stage nuclei install_pd_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei v3.11.1
  run_stage httpx install_pd_tool httpx github.com/projectdiscovery/httpx/cmd/httpx v1.12.0
  run_stage subfinder install_pd_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder v2.16.0
  run_stage naabu install_pd_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu v2.6.1
  run_stage dnsx install_pd_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx v1.3.1
  run_stage uncover install_pd_tool uncover github.com/projectdiscovery/uncover/cmd/uncover v1.2.1
  run_stage alterx install_pd_tool alterx github.com/projectdiscovery/alterx/cmd/alterx v0.1.0
  run_stage tlsx install_pd_tool tlsx github.com/projectdiscovery/tlsx/cmd/tlsx v1.4.0
  run_stage asnmap install_pd_tool asnmap github.com/projectdiscovery/asnmap/cmd/asnmap v1.1.1
fi

# -- katana (pre-built binary) --------------------------------------------
install_katana() {
  if ! have katana; then
    DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
    mkdir -p "$HOME/.pdtm/go/bin"
    retry curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${DEB_ARCH}.zip" \
      -o "${INSTALL_TMP}/katana.zip"
    unzip -o "${INSTALL_TMP}/katana.zip" -d "${INSTALL_TMP}/katana_extract"
    mv "${INSTALL_TMP}/katana_extract/katana" "$HOME/.pdtm/go/bin/katana"
    chmod +x "$HOME/.pdtm/go/bin/katana"
    rm -rf "${INSTALL_TMP}/katana.zip" "${INSTALL_TMP}/katana_extract"
  fi
}
run_stage katana install_katana

# -- protoscope ------------------------------------------------------------
install_protoscope() {
  have protoscope || \
    retry go install "github.com/protocolbuffers/protoscope/cmd/protoscope@${GO_TOOL_VERSIONS_protoscope}"
}
run_stage protoscope install_protoscope

# -- interactsh-client -----------------------------------------------------
install_interactsh() {
  have interactsh-client || \
    retry go install "github.com/projectdiscovery/interactsh/cmd/interactsh-client@${GO_TOOL_VERSIONS_interactsh}"
}
run_stage interactsh install_interactsh

# -- 2fa (TOTP generator) --------------------------------------------------
install_twofa() {
  have 2fa || retry go install "rsc.io/2fa@${GO_TOOL_VERSIONS_2fa}"
}
run_stage twofa install_twofa

# surf is not installed: upstream grants no licence, so we have no right to use
# or redistribute it (ADM-447).

# -- kiterunner (API content discovery) ------------------------------------
install_kiterunner() {
  if ! have kr; then
    if retry clone_repo https://github.com/assetnote/kiterunner "${INSTALL_TMP}/kiterunner" --branch "$KITERUNNER_VERSION"; then
      ( cd "${INSTALL_TMP}/kiterunner" && retry make build )
      as_root mv "${INSTALL_TMP}/kiterunner/dist/kr" /usr/local/bin/kr
      rm -rf "${INSTALL_TMP}/kiterunner"
    else
      echo "WARN: kiterunner clone failed, skipping" >&2
      return 1
    fi
  fi
}
run_stage kiterunner install_kiterunner

# -- Caido CLI -------------------------------------------------------------
# Pinned Caido CLI (headless server) release. Auth is handled at runtime via
# CAIDO_URL + CAIDO_PAT env vars or the device flow login.
#
# Keep this pin >= 0.57.0. The vendored caido-mode skill runs on
# @caido/sdk-client 0.4.0, which targets the 0.57 replay schema (ReplaySession
# as an interface, `kind: ReplaySessionKind!` on createReplaySession, and
# task-based sending via startReplayTask). Pinning an older server here puts
# the client and server on opposite sides of that schema break.
# tests/test_caido_mode_skill.py enforces the floor.
install_caido_cli() {
  if ! command -v caido-cli &>/dev/null; then
    CAIDO_VERSION="0.57.1"
    case "$ARCH" in
      aarch64|arm64) CAIDO_ARCH="aarch64" ;;
      *)             CAIDO_ARCH="x86_64" ;;
    esac
    retry curl -fsSL "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" \
      -o "${INSTALL_TMP}/caido-cli.tar.gz" \
    && as_root tar -xzf "${INSTALL_TMP}/caido-cli.tar.gz" -C /usr/local/bin/ \
    && rm "${INSTALL_TMP}/caido-cli.tar.gz" \
    || { echo "WARN: Caido CLI install failed (check version), skipping" >&2; return 1; }
  fi
}
run_stage caido_cli install_caido_cli

# -- Caido MCP server (Go, c0tton-fluff/caido-mcp-server) -------------------
# Full-surface Caido MCP server wired into capability.yaml as `caido-go`.
# Pinned to a release with SHA-256 verification. Installed to /usr/local/bin
# so it resolves on PATH for the MCP `command: caido-mcp-server`.
install_caido_mcp() {
  if ! command -v caido-mcp-server &>/dev/null; then
    CAIDO_MCP_VERSION="4.3.0"
    case "$ARCH" in
      aarch64|arm64)
        CAIDO_MCP_ARCH="arm64"
        CAIDO_MCP_SHA256="7b8d6a89f6b404345715a25d8201a0fbe37db9a0f23b8b1868d01c68b110071b"
        ;;
      *)
        CAIDO_MCP_ARCH="amd64"
        CAIDO_MCP_SHA256="5236620c693f973d5725133c660ca0ac852796dd75e02ce1993bd66202d0b04c"
        ;;
    esac
    CAIDO_MCP_URL="https://github.com/c0tton-fluff/caido-mcp-server/releases/download/v${CAIDO_MCP_VERSION}/caido-mcp-server-linux-${CAIDO_MCP_ARCH}"
    if retry curl -fsSL "$CAIDO_MCP_URL" -o "${INSTALL_TMP}/caido-mcp-server"; then
      if echo "${CAIDO_MCP_SHA256}  ${INSTALL_TMP}/caido-mcp-server" | sha256sum -c - >/dev/null 2>&1; then
        as_root install -m 0755 "${INSTALL_TMP}/caido-mcp-server" /usr/local/bin/caido-mcp-server
        echo "caido-mcp-server v${CAIDO_MCP_VERSION} installed"
      else
        echo "WARN: caido-mcp-server checksum mismatch, skipping install" >&2
        return 1
      fi
      rm -f "${INSTALL_TMP}/caido-mcp-server"
    else
      echo "WARN: caido-mcp-server download failed (check version), skipping" >&2
      return 1
    fi
  fi
}
run_stage caido_mcp install_caido_mcp

# -- Burp Suite Community (headless) ----------------------------------------
# Install the Burp Suite Community JAR and command-line launcher.
install_burp() {
  if [ ! -s /opt/burp/burpsuite.jar ]; then
    BURP_VERSION="2025.5"
    # Use root privileges for the installation directory and published artifacts.
    if as_root mkdir -p /opt/burp; then
      retry curl -fsSL "https://portswigger-cdn.net/burp/releases/download?product=community&version=${BURP_VERSION}&type=Jar" \
        -o "$INSTALL_TMP/burpsuite.jar" \
      || { echo "WARN: Burp Suite download failed (check version), skipping" >&2; return 1; }
      as_root install -m 0644 "$INSTALL_TMP/burpsuite.jar" /opt/burp/burpsuite.jar.tmp
      as_root mv /opt/burp/burpsuite.jar.tmp /opt/burp/burpsuite.jar
    else
      echo "WARN: cannot create /opt/burp (requires root); skipping Burp Suite" >&2
      return 1
    fi
  fi
  # Retry wrapper creation even when the JAR arrived on an earlier pass.
  if ! command -v burp >/dev/null 2>&1; then
    as_root tee /usr/local/bin/burp >/dev/null <<'BURPEOF'
#!/usr/bin/env bash
exec java -jar /opt/burp/burpsuite.jar "$@"
BURPEOF
    as_root chmod +x /usr/local/bin/burp
  fi
}
run_stage burp install_burp

# -- exiftool (EXIF metadata manipulation) ---------------------------------
install_exiftool() {
  if ! command -v exiftool &>/dev/null; then
    retry as_root apt-get install -y --no-install-recommends libimage-exiftool-perl \
      || { echo "WARN: exiftool install failed, skipping" >&2; return 1; }
  fi
}
run_stage exiftool install_exiftool

# -- Node.js + agent-browser -----------------------------------------------
install_browser() {
  NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  if [ "$NODE_MAJOR" -lt 24 ]; then
    retry curl -fsSL https://deb.nodesource.com/setup_24.x -o "$INSTALL_TMP/node-setup.sh"
    as_root bash "$INSTALL_TMP/node-setup.sh"
    retry as_root apt-get install -y --no-install-recommends nodejs \
      || { echo "WARN: Node.js install failed, skipping" >&2; return 1; }
  fi
  # Pin the agent-browser package version for repeatable installs.
  AGENT_BROWSER_VERSION="0.35.1"
  if ! have agent-browser; then
    retry as_root npm install -g "agent-browser@${AGENT_BROWSER_VERSION}" \
      || { echo "WARN: agent-browser install failed, skipping" >&2; return 1; }
  fi
  # `agent-browser install` downloads the browser binaries themselves. Guarded on
  # a completion marker so a failed download that creates the cache directory
  # is retried on the next pass. Sealed deployments still skip browser downloads.
  AGENT_BROWSER_CACHE="${AGENT_BROWSER_CACHE_DIR:-$HOME/.cache/agent-browser}"
  if [ "${DREADNODE_CAPABILITY_INSTALL:-}" != "sealed" ] && [ ! -f "$AGENT_BROWSER_CACHE/.dreadnode-installed" ]; then
    retry agent-browser install || { echo "WARN: agent-browser browser download failed, skipping" >&2; return 1; }
    mkdir -p "$AGENT_BROWSER_CACHE"
    touch "$AGENT_BROWSER_CACHE/.dreadnode-installed"
  fi
}
run_stage browser install_browser

# -- caido-mode skill deps (Caido TypeScript SDK CLI) -----------------------
# The caido-mode skill bundles a tsx CLI built on @caido/sdk-client (caido-ts).
# Pre-install its node_modules so `npx tsx caido-client.ts` resolves offline at
# runtime. Path is relative to the capability root (CAPABILITY_ROOT if exported,
# else the script's own location, which is <root>/scripts).
install_caido_mode() {
  CAIDO_MODE_DIR="${CAPABILITY_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}/skills/caido-mode"
  # npm ls checks installed dependencies locally, including incomplete node_modules
  # left by a failed install, without contacting the registry.
  if [ -f "$CAIDO_MODE_DIR/package.json" ] && ! ( cd "$CAIDO_MODE_DIR" && npm ls --depth=0 >/dev/null 2>&1 ); then
    ( cd "$CAIDO_MODE_DIR" && retry npm install --no-audit --no-fund ) \
      && echo "caido-mode skill deps installed (@caido/sdk-client / caido-ts)" \
      || { echo "WARN: caido-mode npm install failed, skipping" >&2; return 1; }
  fi
}
run_stage caido_mode install_caido_mode

# -- wrangler (Cloudflare Workers CLI for OAST endpoints) ------------------
# Deploys Cloudflare Workers as custom OAST endpoints (blind XSS payload
# hosting, configurable callback receivers, SSRF redirectors) — see the
# wrangler toolset and the wrangler-oast skill. Auth is runtime-only via
# CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID (CF_* aliases accepted).
# Pinned: an unpinned npm install re-resolves against the registry even when
# the binary is already present, which a sealed deployment must never do.
install_wrangler() {
  WRANGLER_VERSION="4.127.0"
  have wrangler || \
    retry as_root npm install -g "wrangler@${WRANGLER_VERSION}" \
    || { echo "WARN: wrangler install failed, skipping" >&2; return 1; }
}
run_stage wrangler install_wrangler

# -- ast-grep (AST-based code pattern search) ---------------------------------
# Tree-sitter based structural code matching for JS/TS/HTML. Lightweight
# alternative to semgrep for pattern matching (no taint analysis).
install_ast_grep() {
  have ast-grep || retry py_install ast-grep-cli || { echo "WARN: ast-grep install failed, skipping" >&2; return 1; }
}
run_stage ast_grep install_ast_grep

# -- waymore (Wayback Machine recon) -----------------------------------------
install_waymore() {
  have waymore || retry py_install waymore || { echo "WARN: waymore install failed, skipping" >&2; return 1; }
}
run_stage waymore install_waymore

# -- Pacu (AWS exploitation framework) ----------------------------------------
install_pacu() {
  have pacu || retry py_install pacu || { echo "WARN: pacu install failed, skipping" >&2; return 1; }
}
run_stage pacu install_pacu

# -- fireprox (AWS API Gateway IP rotation) ---------------------------------
# Requires AWS credentials at runtime. Cloned to a predictable path so the
# ip-rotation skill can reference it directly.
install_fireprox() {
  FIREPROX_DIR="$HOME/git/fireprox"
  if [ ! -d "$FIREPROX_DIR" ]; then
    mkdir -p "$HOME/git"
    retry clone_repo https://github.com/ustayready/fireprox "$FIREPROX_DIR"
  fi
  if [ ! -f "$FIREPROX_DIR/.dreadnode-deps-installed" ]; then
    retry py_install -r "$FIREPROX_DIR/requirements.txt"
    touch "$FIREPROX_DIR/.dreadnode-deps-installed"
  fi
}
run_stage fireprox install_fireprox

# -- archivealchemist (malicious archive crafter) ---------------------------
# Pure Python CLI for crafting Zip Slip, symlink, polyglot, and Unicode path
# confusion archives. Cloned to a predictable path for the agent prompt.
install_archivealchemist() {
  ARCHIVEALCHEMIST_DIR="$HOME/git/archivealchemist"
  if [ ! -d "$ARCHIVEALCHEMIST_DIR" ]; then
    mkdir -p "$HOME/git"
    retry clone_repo https://github.com/avlidienbrunn/archivealchemist "$ARCHIVEALCHEMIST_DIR" \
      || { echo "WARN: archivealchemist clone failed, skipping" >&2; return 1; }
  fi
}
run_stage archivealchemist install_archivealchemist

validate_tools() {
  local tool missing=0
  for tool in nuclei httpx subfinder naabu dnsx uncover alterx tlsx asnmap; do
    have_pd_tool "$tool" || { echo "Missing required tool: $tool" >&2; missing=1; }
  done
  for tool in katana protoscope interactsh-client 2fa kr caido-cli caido-mcp-server \
      burp exiftool agent-browser wrangler ast-grep waymore pacu; do
    have "$tool" || { echo "Missing required tool: $tool" >&2; missing=1; }
  done
  for artifact in /opt/burp/burpsuite.jar "$HOME/git/fireprox/fire.py" \
      "$HOME/git/archivealchemist/archive-alchemist.py"; do
    [ -s "$artifact" ] || { echo "Missing required artifact: $artifact" >&2; missing=1; }
  done
  return "$missing"
}
run_stage validation validate_tools

if [ "${#failed_stages[@]}" -gt 0 ]; then
  echo "web-security installation incomplete; failed stages: ${failed_stages[*]}" >&2
  exit 1
fi
# Retain downloaded modules after a failed pass so the next pass can reuse them.
if [ "$need_go" = true ]; then
  go clean -cache -modcache 2>/dev/null || true
fi

echo "web-security tools installed successfully"
