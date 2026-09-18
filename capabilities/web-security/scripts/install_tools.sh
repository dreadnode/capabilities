#!/usr/bin/env bash
# Install CLI tools for the web-security capability.
# Runs at sandbox provision time via dependencies.scripts.
set -euo pipefail

ARCH="$(uname -m)"

# The self-hosted runtime prebakes these tools. Keep this installer as a fallback
# for other sandbox providers, but never replace a binary that is already on PATH.
ensure_go() {
  export PATH="$HOME/go/bin:$PATH"
  if command -v go &>/dev/null; then
    return
  fi

  GO_VERSION="1.26.6"
  case "$ARCH" in
    aarch64|arm64) GOARCH="arm64" ;;
    *)             GOARCH="amd64" ;;
  esac
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" | tar -xz -C /usr/local
  export PATH="/usr/local/go/bin:$PATH"
}

# -- ProjectDiscovery tools -----------------------------------------------
install_pd_tool() {
  local tool="$1" package="$2" version="$3"
  if command -v "$tool" &>/dev/null; then
    if [[ "$tool" != "httpx" ]] || "$tool" -version &>/dev/null; then
      return
    fi
  fi

  ensure_go
  mkdir -p "$HOME/.pdtm/go/bin"
  GOBIN="$HOME/.pdtm/go/bin" go install "${package}@${version}"
  export PATH="$HOME/.pdtm/go/bin:$PATH"
}

install_pd_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei v3.11.1
install_pd_tool httpx github.com/projectdiscovery/httpx/cmd/httpx v1.12.0
install_pd_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder v2.16.0
install_pd_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu v2.6.1
install_pd_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx v1.3.1
install_pd_tool uncover github.com/projectdiscovery/uncover/cmd/uncover v1.2.1
install_pd_tool alterx github.com/projectdiscovery/alterx/cmd/alterx v0.1.0
install_pd_tool tlsx github.com/projectdiscovery/tlsx/cmd/tlsx v1.4.0
install_pd_tool asnmap github.com/projectdiscovery/asnmap/cmd/asnmap v1.1.1

# -- katana (pre-built binary, go-tree-sitter build issue) -----------------
if ! command -v katana &>/dev/null; then
  KATANA_VERSION="1.7.0"
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
if ! command -v protoscope &>/dev/null; then
  ensure_go
  go install github.com/protocolbuffers/protoscope/cmd/protoscope@v0.0.0-20221109213918-8e7a6aafa2c9
fi

# -- interactsh-client -----------------------------------------------------
if ! command -v interactsh-client &>/dev/null; then
  ensure_go
  go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.3.1
fi

# -- 2fa (TOTP generator) --------------------------------------------------
if ! command -v 2fa &>/dev/null; then
  ensure_go
  go install rsc.io/2fa@v1.2.0
fi

# -- surf (SSRF target identification) ------------------------------------
if ! command -v surf &>/dev/null; then
  ensure_go
  go install github.com/assetnote/surf/cmd/surf@v0.0.5
fi

# -- kiterunner (API content discovery) ------------------------------------
if ! command -v kr &>/dev/null; then
  git clone --depth 1 --branch v1.0.2 https://github.com/assetnote/kiterunner /tmp/kiterunner
  cd /tmp/kiterunner && make build
  mv /tmp/kiterunner/dist/kr /usr/local/bin/kr
  rm -rf /tmp/kiterunner
  cd -
fi

# -- Caido CLI -------------------------------------------------------------
# Downloads the latest Caido CLI binary. Auth is handled at runtime via
# CAIDO_URL + CAIDO_PAT env vars or the device flow login.
if ! command -v caido-cli &>/dev/null; then
  CAIDO_VERSION="0.45.0"
  case "$ARCH" in
    aarch64|arm64) CAIDO_ARCH="aarch64" ;;
    *)             CAIDO_ARCH="x86_64" ;;
  esac
  curl -fsSL "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" \
    -o /tmp/caido-cli.tar.gz \
  && tar -xzf /tmp/caido-cli.tar.gz -C /usr/local/bin/ \
  && rm /tmp/caido-cli.tar.gz \
  || echo "WARN: Caido CLI install failed (check version), skipping"
fi

# -- Burp Suite Community (headless) ----------------------------------------
# Downloads the Burp Suite Community JAR for headless scanning.
# Pro features require BURP_LICENSE_KEY at runtime.
if [ ! -f /opt/burp/burpsuite.jar ]; then
  BURP_VERSION="2025.5"
  mkdir -p /opt/burp
  curl -fsSL "https://portswigger-cdn.net/burp/releases/download?product=community&version=${BURP_VERSION}&type=Jar" \
    -o /opt/burp/burpsuite.jar \
  || echo "WARN: Burp Suite download failed (check version), skipping"
  # Wrapper script for convenience
  cat > /usr/local/bin/burp <<'BURPEOF'
#!/usr/bin/env bash
exec java -jar /opt/burp/burpsuite.jar "$@"
BURPEOF
  chmod +x /usr/local/bin/burp
fi

# -- jxscout ----------------------------------------------------------------
# Commercial binary — if JXSCOUT_BINARY_URL is set, download from there.
# Otherwise skip; the MCP server falls back to PATH / ~/go/bin / ~/bin.
if ! command -v jxscout-pro-v2 &>/dev/null && [ -n "${JXSCOUT_BINARY_URL:-}" ]; then
  curl -fsSL "$JXSCOUT_BINARY_URL" -o /usr/local/bin/jxscout-pro-v2
  chmod +x /usr/local/bin/jxscout-pro-v2
  echo "jxscout installed from JXSCOUT_BINARY_URL"
elif ! command -v jxscout-pro-v2 &>/dev/null; then
  echo "WARN: jxscout-pro-v2 not found. Set JXSCOUT_BINARY_URL to install, or place binary on PATH."
fi

# -- Node.js + agent-browser -----------------------------------------------
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if ((NODE_MAJOR < 24)); then
  curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
  apt-get install -y --no-install-recommends nodejs
fi
if ! command -v agent-browser &>/dev/null; then
  npm install -g agent-browser@0.35.0
fi
if [[ "${DREADNODE_CAPABILITY_INSTALL:-}" != "sealed" ]]; then
  agent-browser install
fi

# -- Clean up Go build cache -----------------------------------------------
if command -v go &>/dev/null; then
  go clean -cache -modcache 2>/dev/null || true
fi

echo "web-security tools installed successfully"
