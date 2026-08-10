"""Tests for the upstream Caido Go MCP server wiring (`caido-go`).

The web-security capability ships two Caido MCP servers:

  * ``caido``    — the lightweight Python wrapper over ``caido-sdk-client``.
  * ``caido-go`` — the full-surface upstream Go binary
                   (c0tton-fluff/caido-mcp-server), installed by
                   ``scripts/install_tools.sh``.

These tests lock the manifest wiring and the install-script contract so the
Go server is declared as a stdio MCP server, targets the local Caido
instance, is checked for presence, and is installed pinned + checksum
verified. They are pure static assertions over the manifest and script — no
network or binary required.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = yaml.safe_load((ROOT / "capability.yaml").read_text(encoding="utf-8"))
INSTALL_SCRIPT = (ROOT / "scripts" / "install_tools.sh").read_text(encoding="utf-8")

# Keep this in lock-step with scripts/install_tools.sh. If the pinned release
# is bumped, both the script and this constant must change together.
PINNED_VERSION = "4.3.0"


# =============================================================================
# Manifest wiring
# =============================================================================


class TestCaidoGoManifest:
    def test_caido_go_server_declared(self) -> None:
        servers = MANIFEST["mcp"]["servers"]
        assert "caido-go" in servers, "caido-go MCP server must be declared"

    def test_is_stdio_server_running_the_binary(self) -> None:
        server = MANIFEST["mcp"]["servers"]["caido-go"]
        # stdio transport is inferred from `command:`; `url:` would make it HTTP.
        assert server["command"] == "caido-mcp-server"
        assert "url" not in server
        assert server["args"] == ["serve"]

    def test_targets_local_caido_with_overridable_default(self) -> None:
        env = MANIFEST["mcp"]["servers"]["caido-go"]["env"]
        # Connect-time interpolation with a sane default so it works with no
        # extra config but can be redirected via CAIDO_URL.
        assert env["CAIDO_URL"] == "${CAIDO_URL:-http://127.0.0.1:8080}"

    def test_auth_and_redaction_env_are_optional(self) -> None:
        env = MANIFEST["mcp"]["servers"]["caido-go"]["env"]
        # Optional token + redaction toggle: default-empty so absence never
        # raises at connect time (the server falls back to the token file).
        assert env["CAIDO_ACCESS_TOKEN"] == "${CAIDO_ACCESS_TOKEN:-}"
        assert (
            env["CAIDO_ALLOW_SENSITIVE_HEADERS"]
            == "${CAIDO_ALLOW_SENSITIVE_HEADERS:-}"
        )

    def test_has_init_timeout(self) -> None:
        assert MANIFEST["mcp"]["servers"]["caido-go"]["init_timeout"] == 60

    def test_coexists_with_python_caido_server(self) -> None:
        servers = MANIFEST["mcp"]["servers"]
        # Both servers ship together; the Python one is unchanged.
        assert servers["caido"]["command"] == "uv"
        assert servers["caido"]["args"] == ["run", "${CAPABILITY_ROOT}/mcp/caido.py"]


class TestCaidoGoCheck:
    def test_presence_check_registered(self) -> None:
        checks = {c["name"]: c["command"] for c in MANIFEST["checks"]}
        assert "caido-mcp-server" in checks
        cmd = checks["caido-mcp-server"]
        # Accept a PATH install or the c0tton-fluff install.sh default (~/bin).
        assert "command -v caido-mcp-server" in cmd
        assert "$HOME/bin/caido-mcp-server" in cmd


# =============================================================================
# Install-script contract
# =============================================================================


class TestCaidoGoInstall:
    def test_installs_pinned_version(self) -> None:
        assert f'CAIDO_MCP_VERSION="{PINNED_VERSION}"' in INSTALL_SCRIPT

    def test_downloads_from_official_release_url(self) -> None:
        assert (
            "https://github.com/c0tton-fluff/caido-mcp-server/releases/download/"
            "v${CAIDO_MCP_VERSION}/caido-mcp-server-linux-${CAIDO_MCP_ARCH}"
        ) in INSTALL_SCRIPT

    def test_pins_both_arch_checksums(self) -> None:
        # arm64 + amd64 SHA-256 digests must both be present (64 hex chars).
        arm = re.search(
            r'CAIDO_MCP_ARCH="arm64"\s*\n\s*CAIDO_MCP_SHA256="([0-9a-f]{64})"',
            INSTALL_SCRIPT,
        )
        amd = re.search(
            r'CAIDO_MCP_ARCH="amd64"\s*\n\s*CAIDO_MCP_SHA256="([0-9a-f]{64})"',
            INSTALL_SCRIPT,
        )
        assert arm is not None, "arm64 checksum pin missing"
        assert amd is not None, "amd64 checksum pin missing"
        assert arm.group(1) != amd.group(1), "arch checksums must differ"

    def test_verifies_checksum_before_install(self) -> None:
        # The download must be checksum-verified with sha256sum -c before it is
        # placed on PATH — never install an unverified binary.
        assert "sha256sum -c -" in INSTALL_SCRIPT
        verify = INSTALL_SCRIPT.index("sha256sum -c -")
        install = INSTALL_SCRIPT.index("install -m 0755 /tmp/caido-mcp-server")
        assert verify < install, "checksum must be verified before install"

    def test_checksum_mismatch_skips_install(self) -> None:
        assert "checksum mismatch, skipping install" in INSTALL_SCRIPT

    def test_installs_onto_path(self) -> None:
        assert (
            "install -m 0755 /tmp/caido-mcp-server /usr/local/bin/caido-mcp-server"
            in INSTALL_SCRIPT
        )

    def test_idempotent_guard(self) -> None:
        # Skips the whole block if the binary is already present.
        assert "if ! command -v caido-mcp-server &>/dev/null; then" in INSTALL_SCRIPT

    def test_cleans_up_temp_download(self) -> None:
        assert "rm -f /tmp/caido-mcp-server" in INSTALL_SCRIPT
