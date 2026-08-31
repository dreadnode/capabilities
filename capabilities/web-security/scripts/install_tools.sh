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

export PATH="$HOME/.pdtm/go/bin:$HOME/go/bin:$PATH"

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

# Install a Python package into whatever interpreter this runtime uses.
# `pip` is not always on PATH — a uv-managed virtualenv has no pip binary at
# all, which made the bare `pip install` calls below abort the run with
# "command not found" on exactly the images the SDK ships.
py_install() {
  if command -v uv >/dev/null 2>&1; then
    uv pip install --python "$(command -v python3)" "$@"
  elif command -v pip >/dev/null 2>&1; then
    pip install --break-system-packages "$@"
  else
    python3 -m pip install --break-system-packages "$@"
  fi
}

GO_TOOL_VERSIONS_pdtm="v0.1.5"
GO_TOOL_VERSIONS_protoscope="v0.0.0-20221109213918-8e7a6aafa2c9"
GO_TOOL_VERSIONS_interactsh="v1.3.1"
GO_TOOL_VERSIONS_2fa="v1.2.0"
GO_TOOL_VERSIONS_surf="v0.0.5"

PD_TOOLS="nuclei httpx subfinder naabu dnsx uncover alterx tlsx asnmap"

# What is actually missing, before anything is fetched.
missing_go_tools=""
for tool in protoscope interactsh-client 2fa surf; do
  have "$tool" || missing_go_tools="$missing_go_tools $tool"
done
missing_pd_tools=""
for tool in $PD_TOOLS; do
  have "$tool" || missing_pd_tools="$missing_pd_tools,$tool"
done
missing_pd_tools="${missing_pd_tools#,}"

# -- Go toolchain (only when something still has to be built) --------------
# Deliberately last in the decision order: the toolchain is a ~150 MB download
# whose only purpose is building the tools above. If they are all present it is
# never needed, so it is never requested.
need_go=false
[ -n "$missing_go_tools" ] && need_go=true
[ -n "$missing_pd_tools" ] && ! have pdtm && need_go=true
if [ "$need_go" = true ] && ! command -v go &>/dev/null; then
  GO_VERSION="1.24.3"
  case "$ARCH" in
    aarch64|arm64) GOARCH="arm64" ;;
    *)             GOARCH="amd64" ;;
  esac
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" | tar -xz -C /usr/local
  export PATH="/usr/local/go/bin:$PATH"
fi

# -- PDTM + ProjectDiscovery tools ----------------------------------------
if [ -n "$missing_pd_tools" ]; then
  if ! have pdtm; then
    go install "github.com/projectdiscovery/pdtm/cmd/pdtm@${GO_TOOL_VERSIONS_pdtm}"
  fi
  PDTM_BIN="$(command -v pdtm || echo "$(go env GOPATH)/bin/pdtm")"
  "$PDTM_BIN" -install "$missing_pd_tools"
fi

# -- katana (pre-built binary, go-tree-sitter build issue) -----------------
if ! have katana; then
  KATANA_VERSION="1.5.0"
  DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
  mkdir -p "$HOME/.pdtm/go/bin"
  curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${DEB_ARCH}.zip" \
    -o /tmp/katana.zip
  unzip -o /tmp/katana.zip -d /tmp/katana_extract
  mv /tmp/katana_extract/katana "$HOME/.pdtm/go/bin/katana"
  chmod +x "$HOME/.pdtm/go/bin/katana"
  rm -rf /tmp/katana.zip /tmp/katana_extract
fi

# -- protoscope ------------------------------------------------------------
have protoscope || \
  go install "github.com/protocolbuffers/protoscope/cmd/protoscope@${GO_TOOL_VERSIONS_protoscope}"

# -- interactsh-client -----------------------------------------------------
have interactsh-client || \
  go install "github.com/projectdiscovery/interactsh/cmd/interactsh-client@${GO_TOOL_VERSIONS_interactsh}"

# -- 2fa (TOTP generator) --------------------------------------------------
have 2fa || go install "rsc.io/2fa@${GO_TOOL_VERSIONS_2fa}"

# -- surf (SSRF target identification) ------------------------------------
have surf || go install "github.com/assetnote/surf/cmd/surf@${GO_TOOL_VERSIONS_surf}"

# -- kiterunner (API content discovery) ------------------------------------
if ! have kr; then
  if git clone --depth 1 https://github.com/assetnote/kiterunner /tmp/kiterunner; then
    ( cd /tmp/kiterunner && make build ) \
      && as_root mv /tmp/kiterunner/dist/kr /usr/local/bin/kr
    rm -rf /tmp/kiterunner
  else
    echo "WARN: kiterunner clone failed, skipping"
  fi
fi

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
if ! command -v caido-cli &>/dev/null; then
  CAIDO_VERSION="0.57.1"
  case "$ARCH" in
    aarch64|arm64) CAIDO_ARCH="aarch64" ;;
    *)             CAIDO_ARCH="x86_64" ;;
  esac
  curl -fsSL "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" \
    -o /tmp/caido-cli.tar.gz \
  && as_root tar -xzf /tmp/caido-cli.tar.gz -C /usr/local/bin/ \
  && rm /tmp/caido-cli.tar.gz \
  || echo "WARN: Caido CLI install failed (check version), skipping"
fi

# -- Caido MCP server (Go, c0tton-fluff/caido-mcp-server) -------------------
# Full-surface Caido MCP server wired into capability.yaml as `caido-go`.
# Pinned to a release with SHA-256 verification. Installed to /usr/local/bin
# so it resolves on PATH for the MCP `command: caido-mcp-server`.
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
  if curl -fsSL "$CAIDO_MCP_URL" -o /tmp/caido-mcp-server; then
    if echo "${CAIDO_MCP_SHA256}  /tmp/caido-mcp-server" | sha256sum -c - >/dev/null 2>&1; then
      as_root install -m 0755 /tmp/caido-mcp-server /usr/local/bin/caido-mcp-server
      echo "caido-mcp-server v${CAIDO_MCP_VERSION} installed"
    else
      echo "WARN: caido-mcp-server checksum mismatch, skipping install" >&2
    fi
    rm -f /tmp/caido-mcp-server
  else
    echo "WARN: caido-mcp-server download failed (check version), skipping" >&2
  fi
fi

# -- Burp Suite Community (headless) ----------------------------------------
# Downloads the Burp Suite Community JAR for headless scanning.
# Pro features require BURP_LICENSE_KEY at runtime.
if [ ! -f /opt/burp/burpsuite.jar ]; then
  BURP_VERSION="2025.5"
  # /opt and /usr/local/bin are root-owned, and this script does not always run
  # as root. Previously the unguarded `mkdir` aborted the entire provision under
  # `set -e` on a non-root runtime, taking every tool below it down with it.
  if as_root mkdir -p /opt/burp; then
    as_root curl -fsSL "https://portswigger-cdn.net/burp/releases/download?product=community&version=${BURP_VERSION}&type=Jar" \
      -o /opt/burp/burpsuite.jar \
    || echo "WARN: Burp Suite download failed (check version), skipping"
    # Only wrap a jar that actually arrived — a `burp` on PATH pointing at
    # nothing is worse than no `burp` at all.
    if [ -f /opt/burp/burpsuite.jar ]; then
      as_root tee /usr/local/bin/burp >/dev/null <<'BURPEOF'
#!/usr/bin/env bash
exec java -jar /opt/burp/burpsuite.jar "$@"
BURPEOF
      as_root chmod +x /usr/local/bin/burp
    fi
  else
    echo "WARN: cannot create /opt/burp (requires root); skipping Burp Suite"
  fi
fi

# -- jxscout ----------------------------------------------------------------
# Commercial binary — if JXSCOUT_BINARY_URL is set, download from there.
# Otherwise skip; the MCP server falls back to PATH / ~/go/bin / ~/bin.
if ! command -v jxscout-pro-v2 &>/dev/null && [ -n "${JXSCOUT_BINARY_URL:-}" ]; then
  curl -fsSL "$JXSCOUT_BINARY_URL" -o /tmp/jxscout-pro-v2 \
    && as_root install -m 0755 /tmp/jxscout-pro-v2 /usr/local/bin/jxscout-pro-v2
  rm -f /tmp/jxscout-pro-v2
  echo "jxscout installed from JXSCOUT_BINARY_URL"
elif ! command -v jxscout-pro-v2 &>/dev/null; then
  echo "WARN: jxscout-pro-v2 not found. Set JXSCOUT_BINARY_URL to install, or place binary on PATH."
fi

# -- exiftool (EXIF metadata manipulation) ---------------------------------
if ! command -v exiftool &>/dev/null; then
  as_root apt-get install -y --no-install-recommends libimage-exiftool-perl \
    || echo "WARN: exiftool install failed, skipping"
fi

# -- Node.js + agent-browser -----------------------------------------------
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | as_root bash - \
    && as_root apt-get install -y --no-install-recommends nodejs \
    || echo "WARN: Node.js install failed, skipping"
fi
# agent-browser pinned to the current latest — an unpinned install resolves
# to a different tool on different days, which no SBOM can describe.
AGENT_BROWSER_VERSION="0.35.1"
if ! have agent-browser; then
  as_root npm install -g "agent-browser@${AGENT_BROWSER_VERSION}" \
    || echo "WARN: agent-browser install failed, skipping"
fi
# `agent-browser install` downloads the browser binaries themselves. Guarded on
# its cache so a runtime that already has them makes no request, and left
# non-fatal because a disconnected deployment that cannot fetch a browser
# should still get the rest of this capability's tooling.
AGENT_BROWSER_CACHE="${AGENT_BROWSER_CACHE_DIR:-$HOME/.cache/agent-browser}"
if [ ! -d "$AGENT_BROWSER_CACHE" ]; then
  agent-browser install || echo "WARN: agent-browser browser download failed, skipping"
fi

# -- caido-mode skill deps (Caido TypeScript SDK CLI) -----------------------
# The caido-mode skill bundles a tsx CLI built on @caido/sdk-client (caido-ts).
# Pre-install its node_modules so `npx tsx caido-client.ts` resolves offline at
# runtime. Path is relative to the capability root (CAPABILITY_ROOT if exported,
# else the script's own location, which is <root>/scripts).
CAIDO_MODE_DIR="${CAPABILITY_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}/skills/caido-mode"
# Guarded on node_modules: without it this reaches the npm registry on every
# boot even when the dependencies are already installed.
if [ -f "$CAIDO_MODE_DIR/package.json" ] && [ ! -d "$CAIDO_MODE_DIR/node_modules" ]; then
  ( cd "$CAIDO_MODE_DIR" && npm install --no-audit --no-fund ) \
    && echo "caido-mode skill deps installed (@caido/sdk-client / caido-ts)" \
    || echo "WARN: caido-mode npm install failed, skipping"
fi

# -- wrangler (Cloudflare Workers CLI for OAST endpoints) ------------------
# Deploys Cloudflare Workers as custom OAST endpoints (blind XSS payload
# hosting, configurable callback receivers, SSRF redirectors) — see the
# wrangler toolset and the wrangler-oast skill. Auth is runtime-only via
# CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID (CF_* aliases accepted).
# Pinned: an unpinned npm install re-resolves against the registry even when
# the binary is already present, which a sealed deployment must never do.
WRANGLER_VERSION="4.127.0"
have wrangler || \
  as_root npm install -g "wrangler@${WRANGLER_VERSION}" \
  || echo "WARN: wrangler install failed, skipping"

# -- ast-grep (AST-based code pattern search) ---------------------------------
# Tree-sitter based structural code matching for JS/TS/HTML. Lightweight
# alternative to semgrep for pattern matching (no taint analysis).
have ast-grep || py_install ast-grep-cli || echo "WARN: ast-grep install failed, skipping"

# -- waymore (Wayback Machine recon) -----------------------------------------
have waymore || py_install waymore || echo "WARN: waymore install failed, skipping"

# -- Pacu (AWS exploitation framework) ----------------------------------------
have pacu || py_install pacu || echo "WARN: pacu install failed, skipping"

# -- fireprox (AWS API Gateway IP rotation) ---------------------------------
# Requires AWS credentials at runtime. Cloned to a predictable path so the
# ip-rotation skill can reference it directly.
FIREPROX_DIR="$HOME/git/fireprox"
if [ ! -d "$FIREPROX_DIR" ]; then
  # Requirements are installed only alongside a fresh clone. Re-running them on
  # every boot re-resolves against PyPI for an environment that already
  # satisfies them.
  if git clone --depth 1 https://github.com/ustayready/fireprox "$FIREPROX_DIR"; then
    py_install -r "$FIREPROX_DIR/requirements.txt" \
      || echo "WARN: fireprox requirements install failed, skipping"
  else
    echo "WARN: fireprox clone failed, skipping"
  fi
fi

# -- archivealchemist (malicious archive crafter) ---------------------------
# Pure Python CLI for crafting Zip Slip, symlink, polyglot, and Unicode path
# confusion archives. Cloned to a predictable path for the agent prompt.
ARCHIVEALCHEMIST_DIR="$HOME/git/archivealchemist"
if [ ! -d "$ARCHIVEALCHEMIST_DIR" ]; then
  git clone --depth 1 https://github.com/avlidienbrunn/archivealchemist "$ARCHIVEALCHEMIST_DIR" \
    || echo "WARN: archivealchemist clone failed, skipping"
fi

# -- Clean up Go build cache -----------------------------------------------
if [ "$need_go" = true ]; then
  go clean -cache -modcache 2>/dev/null || true
fi

echo "web-security tools installed successfully"
