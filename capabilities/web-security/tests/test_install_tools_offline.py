"""The install script must complete without reaching the network when its tools are present.

Self-hosted deployments run with no route to the internet, and this script
executes on every sandbox boot where the capability changed — not just the
first. An unguarded download is therefore a repeated outbound attempt that
cannot succeed, and on a disconnected install one failed fetch aborts the whole
script under ``set -e``, taking the rest of the tooling with it.

These pin the two properties that keep that from happening: every fetch is
guarded on the artefact it produces, and every version is pinned.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = (ROOT / "scripts" / "install_tools.sh").read_text(encoding="utf-8")
LINES = INSTALL_SCRIPT.splitlines()


def _preceding_context(index: int, span: int = 6) -> str:
    """The guard for a fetch sits on the same line or just above it."""
    return "\n".join(LINES[max(0, index - span) : index + 1])


def _surrounding_context(index: int, span: int = 4) -> str:
    """Lines around a match — useful for checking as_root wrapping."""
    return "\n".join(LINES[max(0, index - span) : min(len(LINES), index + span + 1)])


class TestVersionsArePinned:
    def test_no_unpinned_go_installs(self) -> None:
        # `go install ...@latest` re-resolves against the module proxy every
        # run, so it reaches the network even when the binary is already
        # present — and produces a different tool set on different days, which
        # no SBOM can describe.
        unpinned = [line.strip() for line in LINES if "@latest" in line and not line.strip().startswith("#")]
        assert not unpinned, f"unpinned installs: {unpinned}"

    def test_projectdiscovery_tools_use_explicit_versions(self) -> None:
        pins = {
            "nuclei": "v3.11.1",
            "httpx": "v1.12.0",
            "subfinder": "v2.16.0",
            "naabu": "v2.6.1",
            "dnsx": "v1.3.1",
            "uncover": "v1.2.1",
            "alterx": "v0.1.0",
            "tlsx": "v1.4.0",
            "asnmap": "v1.1.1",
        }
        for tool, version in pins.items():
            assert re.search(
                rf"install_pd_tool {tool} \S+ {re.escape(version)}$",
                INSTALL_SCRIPT,
                re.MULTILINE,
            ), f"missing {tool} pin {version}"

        assert "pdtm -install" not in INSTALL_SCRIPT

    def test_toolchain_and_kiterunner_versions_are_pinned(self) -> None:
        assert 'GO_VERSION="1.26.6"' in INSTALL_SCRIPT
        assert 'KITERUNNER_VERSION="v1.0.2"' in INSTALL_SCRIPT
        assert 'git clone --depth 1 --branch "$KITERUNNER_VERSION"' in INSTALL_SCRIPT


class TestFetchesAreGuarded:
    def test_every_go_install_is_guarded(self) -> None:
        unguarded = []
        for i, line in enumerate(LINES):
            if not line.strip().startswith(("go install", "  go install")):
                continue
            if "have " not in _preceding_context(i):
                unguarded.append(line.strip())
        assert not unguarded, f"unguarded go install: {unguarded}"

    def test_global_npm_install_is_guarded(self) -> None:
        for i, line in enumerate(LINES):
            if re.search(r"^\s*(as_root\s+)?npm install -g", line):
                assert "have " in _preceding_context(i), f"unguarded global npm install at line {i + 1}: {line.strip()}"

    def test_npm_installs_are_version_pinned(self) -> None:
        # Same SBOM argument as the go pins: an unpinned `npm install -g`
        # re-resolves against the registry on every boot even when the binary
        # is present, and installs a different tool on different days.
        unpinned = [
            line.strip()
            for line in LINES
            if re.search(r"^\s*(as_root\s+)?npm install -g", line)
            and not re.search(r"@\$?\{?[A-Za-z0-9_.-]+\}?", line.split("-g", 1)[-1])
            and not line.strip().startswith("#")
        ]
        assert not unpinned, f"unpinned npm installs: {unpinned}"

    def test_py_install_calls_are_guarded(self) -> None:
        # Every `py_install` call must be preceded by a `have` check so that
        # already-installed Python tools do not re-resolve against PyPI.
        unguarded = []
        for i, line in enumerate(LINES):
            stripped = line.strip()
            if not stripped.startswith("py_install") and "py_install" not in stripped:
                continue
            # Skip the py_install function definition and requirement file
            # installs (guarded by their parent clone check).
            if stripped.startswith(("if", "elif", "def", "#")) or "-r " in stripped or "py_install()" in stripped:
                continue
            if "have " not in _preceding_context(i):
                unguarded.append(stripped)
        assert not unguarded, f"unguarded py_install: {unguarded}"

    def test_only_missing_projectdiscovery_tools_are_installed(self) -> None:
        assert "$missing_pd_tools" in INSTALL_SCRIPT
        assert 'have_pd_tool "$tool" || missing_pd_tools=' in INSTALL_SCRIPT

    def test_httpx_guard_rejects_the_python_cli(self) -> None:
        assert "httpx -version >/dev/null 2>&1" in INSTALL_SCRIPT

    def test_katana_download_is_guarded(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "katana_${KATANA_VERSION}" in line)
        assert "have katana" in _preceding_context(idx, span=8)

    def test_caido_cli_download_is_guarded(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "caido.download/releases" in line)
        assert "command -v caido-cli" in _preceding_context(idx, span=10)

    def test_caido_mcp_server_download_is_guarded(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "caido-mcp-server-linux" in line)
        assert "command -v caido-mcp-server" in _preceding_context(idx, span=15)

    def test_kiterunner_build_is_guarded(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "assetnote/kiterunner" in line)
        assert "have kr" in _preceding_context(idx, span=4)

    def test_wrangler_install_is_guarded_and_pinned(self) -> None:
        # wrangler is fetched from npm, so the guard-and-pin discipline applies
        # exactly as it does to the go installs: present binary -> no registry
        # request; absent binary -> the pinned version, not @latest.
        idx = next(i for i, line in enumerate(LINES) if "wrangler@${WRANGLER_VERSION}" in line)
        assert "have wrangler" in _preceding_context(idx, span=6)
        pin = next(i for i, line in enumerate(LINES) if line.startswith("WRANGLER_VERSION="))
        assert re.fullmatch(
            r"WRANGLER_VERSION=\"[0-9]+\.[0-9]+\.[0-9]+\"",
            LINES[pin].strip(),
        ), f"unpinned wrangler version: {LINES[pin]}"

    def test_git_clones_are_guarded_on_target_dir(self) -> None:
        # Clones to persistent paths (fireprox, archivealchemist) are guarded
        # on the target directory existing. Clones to /tmp (kiterunner) are
        # guarded on the binary they produce.
        for i, line in enumerate(LINES):
            if "git clone" not in line or line.strip().startswith("#"):
                continue
            ctx = _preceding_context(i, span=6)
            has_dir_guard = "! -d " in ctx or "have " in ctx
            assert has_dir_guard, f"unguarded git clone at line {i + 1}: {line.strip()}"

    def test_go_toolchain_is_only_fetched_when_something_needs_building(self) -> None:
        # The toolchain is a ~150 MB download whose only purpose is building
        # the tools above. A runtime that already carries them must never ask
        # for it — which is what made the whole script abort at its first line
        # on a disconnected install.
        idx = next(i for i, line in enumerate(LINES) if "go.dev/dl/go" in line)
        context = _preceding_context(idx, span=10)
        assert "need_go" in context

    def test_go_cache_cleanup_only_runs_when_go_was_used(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "go clean -cache" in line)
        assert "need_go" in _preceding_context(idx, span=3)

    def test_node_24_floor_and_sealed_browser_guard(self) -> None:
        assert "setup_24.x" in INSTALL_SCRIPT
        assert "setup_22.x" not in INSTALL_SCRIPT
        assert "${DREADNODE_CAPABILITY_INSTALL:-}" in INSTALL_SCRIPT
        assert '!= "sealed"' in INSTALL_SCRIPT


class TestRootEscalation:
    """Writes to root-owned paths (/usr/local/bin, /opt) must use as_root."""

    def test_caido_cli_tar_uses_as_root(self) -> None:
        idx = next(
            i for i, line in enumerate(LINES) if "tar" in line and "caido-cli" in line and "/usr/local/bin" in line
        )
        assert "as_root" in LINES[idx]

    def test_caido_mcp_server_install_uses_as_root(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "install -m" in line and "caido-mcp-server" in line)
        assert "as_root" in LINES[idx]

    def test_kiterunner_mv_uses_as_root(self) -> None:
        idx = next(
            i for i, line in enumerate(LINES) if "/usr/local/bin/kr" in line and ("mv " in line or "install " in line)
        )
        assert "as_root" in LINES[idx]

    def test_burp_suite_uses_as_root(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "mkdir -p /opt/burp" in line)
        assert "as_root" in LINES[idx]

    def test_exiftool_apt_uses_as_root(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "apt-get" in line and "exiftool" in line)
        assert "as_root" in LINES[idx]

    def test_nodejs_apt_uses_as_root(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "apt-get" in line and "nodejs" in line)
        assert "as_root" in LINES[idx]


class TestFailuresStayNonFatal:
    def test_optional_vendor_downloads_do_not_abort_the_run(self) -> None:
        # Vendor downloads, system packages, and optional tooling all degrade
        # gracefully — a disconnected deployment must not have its entire
        # provision aborted because one optional tool could not be fetched.
        for marker in (
            "WARN: Caido CLI install failed",
            "WARN: Burp Suite download failed",
            "WARN: agent-browser browser download failed",
            "WARN: exiftool install failed",
            "WARN: Node.js install failed",
            "WARN: kiterunner clone failed",
            "WARN: fireprox clone failed",
            "WARN: fireprox requirements install failed",
            "WARN: archivealchemist clone failed",
            "WARN: ast-grep install failed",
            "WARN: waymore install failed",
            "WARN: pacu install failed",
            "WARN: agent-browser install failed",
            "WARN: wrangler install failed",
            "WARN: caido-mode npm install failed",
        ):
            assert marker in INSTALL_SCRIPT, f"missing non-fatal fallback: {marker}"
