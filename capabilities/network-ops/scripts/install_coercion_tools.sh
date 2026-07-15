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

# rockyou — the standard wordlist for cracking (14M passwords)
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

# Top 10k most common passwords — fast first-pass for spraying
if [ -f "$WORDLIST_DIR/10k-most-common.txt" ]; then
    echo "[*] 10k-most-common.txt already exists, skipping"
else
    echo "[+] Downloading SecLists 10k most common passwords"
    curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
        -o "$WORDLIST_DIR/10k-most-common.txt"
fi

# OneRuleToRuleThemAll — hashcat rules that multiply wordlist effectiveness
# Combines rules from Hob0Rules, KoreLogic, NSA, and hashcat generated rules
RULES_DIR="/usr/share/hashcat/rules"
if [ -d "$RULES_DIR" ] || mkdir -p "$RULES_DIR" 2>/dev/null; then
    if [ -f "$RULES_DIR/OneRuleToRuleThemAll.rule" ]; then
        echo "[*] OneRuleToRuleThemAll.rule already exists, skipping"
    else
        echo "[+] Downloading OneRuleToRuleThemAll hashcat rules"
        curl -fsSL "https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule" \
            -o "$RULES_DIR/OneRuleToRuleThemAll.rule"
    fi
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
