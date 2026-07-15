#!/usr/bin/env bash
# Install dependencies for the network-ops capability.
# Runs at sandbox provision time via dependencies.scripts.
set -euo pipefail

# -- Impacket (ensure it's importable by the runtime Python) ----------------
# dependencies.python should handle this, but belt-and-suspenders: if the
# runtime Python can't import impacket, install it explicitly.
if ! python3 -c "import impacket" 2>/dev/null; then
    echo "[+] Installing impacket into runtime Python"
    python3 -m pip install --quiet "impacket>=0.12.0" \
        || python3 -m pip install --quiet --break-system-packages "impacket>=0.12.0"
else
    echo "[*] impacket already importable, skipping"
fi

# -- OpenSSL legacy provider (MD4 for NTLM) ---------------------------------
# Modern OpenSSL disables MD4, breaking impacket tools that compute NTLM hashes
# (rbcd, dacledit, owneredit, and any NTLM password auth path).
# Enable the legacy provider if the config exists and isn't already patched.
OPENSSL_CONF="$(openssl version -d 2>/dev/null | sed 's/.*"\(.*\)"/\1/')/openssl.cnf"
if [ -f "$OPENSSL_CONF" ] && ! grep -q "^\[legacy_sect\]" "$OPENSSL_CONF" 2>/dev/null; then
    echo "[+] Enabling OpenSSL legacy provider for MD4 support"
    cat >> "$OPENSSL_CONF" <<'LEGACY'

# Enable legacy provider for MD4 (required by impacket NTLM)
[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
LEGACY
    echo "[*] OpenSSL legacy provider enabled"
elif [ -f "$OPENSSL_CONF" ]; then
    echo "[*] OpenSSL legacy provider already configured, skipping"
else
    echo "[!] OpenSSL config not found at $OPENSSL_CONF, skipping MD4 fix"
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
