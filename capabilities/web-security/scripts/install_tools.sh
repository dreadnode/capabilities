#!/usr/bin/env bash
# Install CLI tools for the web-security capability.
# Runs at sandbox provision time via dependencies.scripts.
set -euo pipefail

ARCH="$(uname -m)"

# -- Go toolchain (needed for pdtm, protoscope, interactsh, surf) ---------
if ! command -v go &>/dev/null; then
  GO_VERSION="1.24.3"
  case "$ARCH" in
    aarch64|arm64) GOARCH="arm64" ;;
    *)             GOARCH="amd64" ;;
  esac
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" | tar -xz -C /usr/local
  export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
fi

# -- PDTM + ProjectDiscovery tools ----------------------------------------
go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install nuclei,httpx,subfinder,naabu,dnsx,uncover,alterx,tlsx,asnmap
export PATH="$HOME/.pdtm/go/bin:$PATH"

# -- katana (pre-built binary, go-tree-sitter build issue) -----------------
KATANA_VERSION="1.5.0"
DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${DEB_ARCH}.zip" \
  -o /tmp/katana.zip
unzip -o /tmp/katana.zip -d /tmp/katana_extract
mv /tmp/katana_extract/katana "$HOME/.pdtm/go/bin/katana"
chmod +x "$HOME/.pdtm/go/bin/katana"
rm -rf /tmp/katana.zip /tmp/katana_extract

# -- protoscope ------------------------------------------------------------
go install github.com/protocolbuffers/protoscope/cmd/protoscope@latest

# -- interactsh-client -----------------------------------------------------
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# -- 2fa (TOTP generator) --------------------------------------------------
go install rsc.io/2fa@latest

# -- surf (SSRF target identification) ------------------------------------
go install github.com/assetnote/surf/cmd/surf@latest

# -- kiterunner (API content discovery) ------------------------------------
if ! command -v kr &>/dev/null; then
  git clone --depth 1 https://github.com/assetnote/kiterunner /tmp/kiterunner
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

# -- exiftool (EXIF metadata manipulation) ---------------------------------
if ! command -v exiftool &>/dev/null; then
  apt-get install -y --no-install-recommends libimage-exiftool-perl
fi

# -- Node.js + agent-browser -----------------------------------------------
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y --no-install-recommends nodejs
fi
npm install -g agent-browser
agent-browser install || true

# -- waymore (Wayback Machine recon) -----------------------------------------
pip install --break-system-packages waymore

# -- Pacu (AWS exploitation framework) ----------------------------------------
pip install --break-system-packages pacu

# -- fireprox (AWS API Gateway IP rotation) ---------------------------------
# Requires AWS credentials at runtime. Cloned to a predictable path so the
# ip-rotation skill can reference it directly.
FIREPROX_DIR="$HOME/git/fireprox"
if [ ! -d "$FIREPROX_DIR" ]; then
  git clone --depth 1 https://github.com/ustayready/fireprox "$FIREPROX_DIR"
fi
pip install --break-system-packages -r "$FIREPROX_DIR/requirements.txt"

# -- archivealchemist (malicious archive crafter) ---------------------------
# Pure Python CLI for crafting Zip Slip, symlink, polyglot, and Unicode path
# confusion archives. Cloned to a predictable path for the agent prompt.
ARCHIVEALCHEMIST_DIR="$HOME/git/archivealchemist"
if [ ! -d "$ARCHIVEALCHEMIST_DIR" ]; then
  git clone --depth 1 https://github.com/avlidienbrunn/archivealchemist "$ARCHIVEALCHEMIST_DIR"
fi

# -- Clean up Go build cache -----------------------------------------------
go clean -cache -modcache 2>/dev/null || true

echo "web-security tools installed successfully"
