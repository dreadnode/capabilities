#!/usr/bin/env bash
# Fetch the network-ops runtime assets that apt and pip cannot: the
# password-cracking wordlists, the hashcat rule set, and the three NTLM
# coercion scripts. Binaries and Python packages are declared separately in
# capability.yaml (dependencies.packages / dependencies.python).
#
# The target system directories (/usr/share/wordlists, /usr/share/hashcat,
# /opt) are not writable by the unprivileged provisioning user, so every write
# goes through ensure_writable_dir and stays non-fatal: with no egress or no
# sudo the capability still loads, just without these optional assets. The
# matching checks: in capability.yaml report any asset that did not land.
set -euo pipefail

# Make a (possibly root-owned) system directory exist and be writable by the
# current user, escalating with `sudo -n` (non-interactive, like the SDK's own
# apt step) when a plain mkdir is not permitted. Returns non-zero without
# aborting the script when neither works, so callers skip the dependent write.
ensure_writable_dir() {
    local dir="$1"
    if mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ]; then
        return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
        if sudo -n mkdir -p "$dir" 2>/dev/null \
            && sudo -n chown "$(id -u):$(id -g)" "$dir" 2>/dev/null; then
            return 0
        fi
    fi
    echo "[!] Cannot create or write $dir (non-fatal, skipping)"
    return 1
}

# -- Wordlists for password cracking -----------------------------------------
WORDLIST_DIR="/usr/share/wordlists"
if ensure_writable_dir "$WORDLIST_DIR"; then
    # rockyou — the standard cracking wordlist (14M passwords)
    if [ -s "$WORDLIST_DIR/rockyou.txt" ]; then
        echo "[*] rockyou.txt already exists, skipping"
    elif [ -f "$WORDLIST_DIR/rockyou.txt.gz" ]; then
        echo "[+] Decompressing rockyou.txt.gz"
        rm -f "$WORDLIST_DIR/rockyou.txt"
        gunzip -k "$WORDLIST_DIR/rockyou.txt.gz" \
            || echo "[!] Failed to decompress rockyou.txt.gz (non-fatal)"
    else
        echo "[+] Downloading rockyou.txt"
        curl -fsSL --retry 3 --connect-timeout 10 "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
            -o "$WORDLIST_DIR/rockyou.txt" \
            || echo "[!] Failed to download rockyou.txt (non-fatal)"
    fi

    # Top 10k most common passwords — fast first-pass for spraying
    if [ -s "$WORDLIST_DIR/10k-most-common.txt" ]; then
        echo "[*] 10k-most-common.txt already exists, skipping"
    else
        echo "[+] Downloading SecLists 10k most common passwords"
        curl -fsSL --retry 3 --connect-timeout 10 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
            -o "$WORDLIST_DIR/10k-most-common.txt" \
            || echo "[!] Failed to download 10k-most-common.txt (non-fatal)"
    fi
fi

# OneRuleToRuleThemAll — hashcat rules that multiply wordlist effectiveness.
# Combines rules from Hob0Rules, KoreLogic, NSA, and hashcat generated rules.
RULES_DIR="/usr/share/hashcat/rules"
if ensure_writable_dir "$RULES_DIR"; then
    if [ -s "$RULES_DIR/OneRuleToRuleThemAll.rule" ]; then
        echo "[*] OneRuleToRuleThemAll.rule already exists, skipping"
    else
        echo "[+] Downloading OneRuleToRuleThemAll hashcat rules"
        curl -fsSL --retry 3 --connect-timeout 10 "https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule" \
            -o "$RULES_DIR/OneRuleToRuleThemAll.rule" \
            || echo "[!] Failed to download OneRuleToRuleThemAll.rule (non-fatal)"
    fi
fi

# -- NetExec (nxc) ----------------------------------------------------------
# Not on PyPI and awkward to build from source, so install the project's
# prebuilt standalone binary. v1.5.0 is pinned because it is the most recent
# release carrying a Linux build (v1.5.1 shipped none). The binary needs
# glibc >= 2.38, satisfied by the ubuntu:24.04 runtime base. The tools invoke
# it as `netexec`, so the single `nxc` binary is symlinked under both names.
NXC_BIN_DIR="$HOME/.local/bin"
NXC_URL="https://github.com/Pennyw0rth/NetExec/releases/download/v1.5.0/nxc-ubuntu-latest.zip"
if command -v nxc >/dev/null 2>&1; then
    echo "[*] nxc already present, skipping"
else
    echo "[+] Installing NetExec v1.5.0 (prebuilt binary)"
    if mkdir -p "$NXC_BIN_DIR" \
        && curl -fsSL --retry 3 --connect-timeout 10 "$NXC_URL" -o /tmp/nxc.zip \
        && unzip -o -q /tmp/nxc.zip -d /tmp/nxc-extract \
        && install -m 0755 /tmp/nxc-extract/nxc "$NXC_BIN_DIR/nxc"; then
        ln -sf nxc "$NXC_BIN_DIR/netexec" || echo "[!] netexec symlink failed (non-fatal)"
        ln -sf nxc "$NXC_BIN_DIR/NetExec" || echo "[!] NetExec symlink failed (non-fatal)"
        echo "[*] nxc installed to $NXC_BIN_DIR"
    else
        echo "[!] Failed to install NetExec (non-fatal)"
    fi
    rm -rf /tmp/nxc.zip /tmp/nxc-extract 2>/dev/null || true
fi

# -- certipy-ad ---------------------------------------------------------------
# Installed into its own isolated `uv tool` environment (not declared in
# dependencies.python) to avoid dependency conflicts with the shared
# capability virtualenv. Lands the `certipy`/`certipy-ad` command in
# $HOME/.local/bin.
if command -v certipy >/dev/null 2>&1 || command -v certipy-ad >/dev/null 2>&1; then
    echo "[*] certipy already present, skipping"
elif ! command -v uv >/dev/null 2>&1; then
    echo "[!] uv not found, cannot install certipy-ad (non-fatal)"
else
    echo "[+] Installing certipy-ad 5.1.0 (uv tool)"
    uv tool install certipy-ad==5.1.0 \
        || echo "[!] Failed to install certipy-ad (non-fatal)"
fi

# -- bloodyAD -------------------------------------------------------------
# Installed into its own isolated `uv tool` environment (not declared in
# dependencies.python) to avoid dependency conflicts with the shared
# capability virtualenv. Lands the `bloodyAD` command in $HOME/.local/bin.
if command -v bloodyAD >/dev/null 2>&1; then
    echo "[*] bloodyAD already present, skipping"
elif ! command -v uv >/dev/null 2>&1; then
    echo "[!] uv not found, cannot install bloodyAD (non-fatal)"
else
    echo "[+] Installing bloodyAD 2.5.5 (uv tool)"
    uv tool install bloodyAD==2.5.5 \
        || echo "[!] Failed to install bloodyAD (non-fatal)"
fi

# -- Coercion scripts -------------------------------------------------------
# These /opt paths are hardcoded in three places that must stay in sync: here,
# the coercion-script checks: in capability.yaml, and the path defaults in the
# coercion tools. Change one, change all three.
REPOS=(
    "https://github.com/topotam/PetitPotam /opt/PetitPotam"
    "https://github.com/Wh04m1001/DFSCoerce /opt/DFSCoerce"
    "https://github.com/ShutdownRepo/ShadowCoerce /opt/ShadowCoerce"
)

for entry in "${REPOS[@]}"; do
    read -r url dest <<< "$entry"
    if [ -d "$dest" ]; then
        echo "[*] $dest already exists, skipping"
        continue
    fi
    echo "[+] Cloning $(basename "$dest") to $dest"
    if git clone --depth 1 "$url" "$dest" 2>/dev/null; then
        continue
    fi
    if command -v sudo >/dev/null 2>&1 && sudo -n git clone --depth 1 "$url" "$dest" 2>/dev/null; then
        continue
    fi
    echo "[!] Failed to clone $(basename "$dest") to $dest (non-fatal)"
done
