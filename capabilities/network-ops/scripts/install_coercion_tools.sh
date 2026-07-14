#!/usr/bin/env bash
# Install dependencies for the network-ops capability.
# Runs at sandbox provision time via dependencies.scripts.
set -euo pipefail

# -- Impacket (ensure it's importable by the runtime Python) ----------------
# dependencies.python should handle this, but belt-and-suspenders: if the
# runtime Python can't import impacket, install it explicitly.
if ! python3 -c "import impacket" 2>/dev/null; then
    echo "[+] Installing impacket into runtime Python"
    python3 -m pip install --quiet "impacket>=0.12.0" 2>/dev/null \
        || python3 -m pip install --quiet --break-system-packages "impacket>=0.12.0"
else
    echo "[*] impacket already importable, skipping"
fi

# -- Coercion scripts -------------------------------------------------------
REPOS=(
    "https://github.com/topotam/PetitPotam /opt/PetitPotam"
    "https://github.com/Wh04m1001/DFSCoerce /opt/DFSCoerce"
    "https://github.com/ShutdownRepo/ShadowCoerce /opt/ShadowCoerce"
)

for entry in "${REPOS[@]}"; do
    read -r url dest <<< "$entry"
    if [ -d "$dest" ]; then
        echo "[*] $dest already exists, skipping"
    else
        echo "[+] Cloning $(basename "$dest") to $dest"
        git clone --depth 1 "$url" "$dest"
    fi
done
