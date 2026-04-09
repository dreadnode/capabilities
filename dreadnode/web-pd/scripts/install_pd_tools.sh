#!/usr/bin/env bash
set -euo pipefail

if ! command -v pdtm >/dev/null 2>&1; then
  echo "pdtm is required to install ProjectDiscovery binaries." >&2
  echo "Install pdtm first, then rerun this script." >&2
  exit 1
fi

TOOLS="subfinder,httpx,katana,dnsx,naabu,tlsx,alterx,nuclei"

echo "Installing ProjectDiscovery tools with pdtm: ${TOOLS}"
pdtm -i "${TOOLS}"
