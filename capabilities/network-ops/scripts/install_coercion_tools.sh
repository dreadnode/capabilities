#!/usr/bin/env bash
# Install coercion scripts for NTLM relay attacks.
# Runs at sandbox provision time via dependencies.scripts.
set -euo pipefail

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
