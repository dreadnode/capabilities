"""Provisioning contract tests for the network-ops capability.

The manifest must declare every binary its toolsets invoke (so provisioning
installs them and a check surfaces any that are missing), and the install
script must treat every write to a root-owned system path as non-fatal (so a
sandbox that cannot write or reach the network still loads the capability).
"""

import os
import re
import stat
import subprocess
from pathlib import Path

import yaml

CAP_DIR = Path(__file__).resolve().parent.parent
MANIFEST = CAP_DIR / "capability.yaml"
INSTALL_SCRIPT = CAP_DIR / "scripts" / "install_coercion_tools.sh"


def _manifest() -> dict:
    return yaml.safe_load(MANIFEST.read_text())


def test_apt_tools_declared() -> None:
    packages = _manifest()["dependencies"].get("packages", [])
    for tool in ("nmap", "smbclient", "hashcat", "john"):
        assert tool in packages, f"{tool} must be declared in dependencies.packages"


def test_pip_tools_declared() -> None:
    python = _manifest()["dependencies"].get("python", [])
    joined = " ".join(python)
    for pkg in ("impacket", "certipy-ad", "bloodyAD"):
        assert pkg in joined, f"{pkg} must be declared in dependencies.python"
    # NetExec is not on PyPI; declaring it here hard-fails the SDK's combined
    # pip install and takes the whole capability down. It must stay out.
    assert "netexec" not in joined.lower(), "netexec is not pip-installable; provision it in the image"


def test_every_invoked_binary_has_a_check() -> None:
    check_names = {c["name"] for c in _manifest().get("checks", [])}
    # Binaries the toolsets shell out to: a missing one must show up in
    # pre-flight, not as a raw command-not-found mid-run.
    for name in ("nmap", "smbclient", "hashcat", "john", "netexec", "certipy", "bloodyad"):
        assert name in check_names, f"missing checks: entry for {name}"


def test_fetched_assets_have_a_check() -> None:
    check_names = {c["name"] for c in _manifest().get("checks", [])}
    # Every asset the install script fetches is optional (its download is
    # non-fatal), so each needs a check to report when it did not land.
    for name in (
        "rockyou-wordlist",
        "wordlist-10k",
        "hashcat-rules",
        "petitpotam",
        "dfscoerce",
        "shadowcoerce",
    ):
        assert name in check_names, f"missing checks: entry for {name}"


def test_install_script_defines_sudo_aware_helper() -> None:
    assert "ensure_writable_dir()" in INSTALL_SCRIPT.read_text()


def test_netexec_provisioned_by_script() -> None:
    # NetExec is not on PyPI, so the script fetches the prebuilt binary. The
    # tools call it as `netexec`, so the single `nxc` binary must be symlinked.
    script = INSTALL_SCRIPT.read_text()
    assert "nxc-ubuntu-latest.zip" in script, "script must fetch the NetExec prebuilt binary"
    assert "ln -sf nxc" in script, "the nxc binary must be symlinked to the `netexec` name"


def test_privilege_escalation_is_non_interactive() -> None:
    # Bare `sudo` blocks on a password prompt on an image whose sudoers is not
    # NOPASSWD; `sudo -n` fails fast instead, matching the SDK's apt step.
    for line in INSTALL_SCRIPT.read_text().splitlines():
        stripped = line.strip()
        if re.search(r"\bsudo\b", stripped) and stripped.startswith(("sudo", "if sudo", "&& sudo")):
            assert re.search(r"\bsudo -n\b", stripped), f"interactive sudo: {stripped!r}"


def test_no_unguarded_privileged_mkdir() -> None:
    # A bare `mkdir -p` of a system path aborts the load as the non-root user;
    # such paths may only be created inside ensure_writable_dir.
    for line in INSTALL_SCRIPT.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("mkdir ") and ("/usr/" in stripped or "/opt" in stripped):
            raise AssertionError(f"unguarded privileged mkdir: {stripped!r}")


def test_clones_are_conditional() -> None:
    # Every `git clone` must be the condition of an if/elif so a failure is
    # caught; a bare `git clone` or `sudo git clone` statement aborts the script.
    for line in INSTALL_SCRIPT.read_text().splitlines():
        stripped = line.strip()
        if "git clone" not in stripped:
            continue
        assert re.match(r"(if |elif )", stripped), f"unguarded git clone: {stripped!r}"


def test_script_is_non_fatal_when_every_privileged_op_fails(tmp_path: Path) -> None:
    """Run the real script with mkdir/sudo/git/curl stubbed to fail, so every
    privileged and network operation errors; the script must still exit 0.

    This is the behavioral guard the static checks above cannot give: a future
    unguarded command (a redirect, cp, tar -C /usr/local, ...) that reintroduces
    the load-failure bug fails here even if it dodges the text matchers.
    """
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    for name in ("mkdir", "sudo", "git", "curl", "gunzip"):
        stub = stub_dir / name
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    env = dict(os.environ, PATH=f"{stub_dir}:{os.environ['PATH']}")
    result = subprocess.run(
        ["bash", str(INSTALL_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert (
        result.returncode == 0
    ), f"script aborted (exit {result.returncode}) when privileged ops failed:\n{result.stderr}"
