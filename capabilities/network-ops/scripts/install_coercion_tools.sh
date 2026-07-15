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

# -- Wordlists for password cracking -----------------------------------------
WORDLIST_DIR="/usr/share/wordlists"
mkdir -p "$WORDLIST_DIR"

# rockyou — the standard first-pass wordlist (14M passwords)
if [ -f "$WORDLIST_DIR/rockyou.txt" ]; then
    echo "[*] rockyou.txt already exists, skipping"
elif [ -f "$WORDLIST_DIR/rockyou.txt.gz" ]; then
    echo "[+] Decompressing rockyou.txt.gz"
    gunzip -k "$WORDLIST_DIR/rockyou.txt.gz"
else
    echo "[+] Downloading rockyou.txt"
    curl -fsSL "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
        -o "$WORDLIST_DIR/rockyou.txt"
fi

# SecLists common passwords (top 1M, good for spraying/fast cracks)
if [ -f "$WORDLIST_DIR/10-million-password-list-top-1000000.txt" ]; then
    echo "[*] SecLists top-1M already exists, skipping"
else
    echo "[+] Downloading SecLists top-1M password list"
    curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt" \
        -o "$WORDLIST_DIR/10-million-password-list-top-1000000.txt"
fi

# SecLists common usernames (for user enumeration / spraying)
if [ -f "$WORDLIST_DIR/xato-net-10-million-usernames.txt" ]; then
    echo "[*] SecLists usernames already exists, skipping"
else
    echo "[+] Downloading SecLists username list"
    curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt" \
        -o "$WORDLIST_DIR/xato-net-10-million-usernames.txt"
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
