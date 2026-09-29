"""Guarded installs, pinned versions, and recovery from partial provisioning.

Full-script tests stub external commands and redirect all writes into tmp_path.
No system packages or network access are needed.
"""

import os
import re
import subprocess
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


def _shell_function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", INSTALL_SCRIPT, re.M | re.S)
    assert match, f"{name}() not found in install_tools.sh"
    return match.group(0)


def _stub(path: Path, exit_code: int) -> None:
    """An executable whose `-version` succeeds only for ProjectDiscovery httpx."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
    path.chmod(0o755)


def _have_pd_httpx(tmp_path: Path) -> bool:
    (tmp_path / "home").mkdir(exist_ok=True)
    script = (
        _shell_function("have")
        + _shell_function("have_pd_tool")
        + "have_pd_tool httpx\n"
    )
    env = {
        "HOME": str(tmp_path / "home"),
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
    }
    return subprocess.run(["bash", "-c", script], env=env, check=False).returncode == 0


def test_existing_go_outside_initial_path_is_reused(tmp_path: Path) -> None:
    local = tmp_path / "usr-local"
    _stub(local / "go/bin/go", exit_code=0)
    result = _run_go_setup(tmp_path, local)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "sudo.log").exists()
    assert result.stdout.strip() == str(local / "go/bin/go")


def test_missing_go_extracts_with_noninteractive_sudo(tmp_path: Path) -> None:
    local = tmp_path / "usr-local"
    result = _run_go_setup(tmp_path, local)
    assert result.returncode == 0, result.stderr
    assert (
        tmp_path / "sudo.log"
    ).read_text().strip() == f"-n tar -xzf {tmp_path}/go.tar.gz -C {local}"


def _run_go_setup(tmp_path: Path, local: Path) -> subprocess.CompletedProcess[str]:
    """Run Go setup with temporary paths and stubbed system commands."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    commands = {
        "id": "printf '1000\\n'",
        "curl": "exit 0",
        "sudo": 'printf "%s\\n" "$*" > "$HOME/sudo.log"; shift; exec "$@"',
        "tar": '/bin/mkdir -p "$4/go/bin"; printf "#!/bin/bash\\nexit 0\\n" > "$4/go/bin/go"; /bin/chmod +x "$4/go/bin/go"',
    }
    for name, body in commands.items():
        executable = bindir / name
        executable.write_text(f"#!/bin/bash\n{body}\n")
        executable.chmod(0o755)
    path_line = next(line for line in LINES if line.startswith("export PATH="))
    go_setup = INSTALL_SCRIPT.split("need_go=false", 1)[1].split(
        "# -- ProjectDiscovery tools", 1
    )[0]
    script = (
        "set -euo pipefail\n"
        + path_line
        + "\n"
        + _shell_function("as_root")
        + _shell_function("have")
        + _shell_function("retry")
        + _shell_function("run_stage")
        + 'failed_stages=(); INSTALL_TMP="$HOME"\n'
        + "missing_go_tools=protoscope; missing_pd_tools=''; ARCH=x86_64; GO_VERSION=test\n"
        + "need_go=false"
        + go_setup
        + '\ntest "${#failed_stages[@]}" -eq 0; command -v go\n'
    ).replace("/usr/local", str(local))
    return subprocess.run(
        ["/bin/bash", "-c", script],
        env={"HOME": str(tmp_path), "PATH": str(bindir)},
        capture_output=True,
        text=True,
        check=False,
    )


class TestVersionsArePinned:
    def test_no_unpinned_go_installs(self) -> None:
        # `go install ...@latest` re-resolves against the module proxy every
        # run, so it reaches the network even when the binary is already
        # present — and produces a different tool set on different days, which
        # no SBOM can describe.
        unpinned = [
            line.strip()
            for line in LINES
            if "@latest" in line and not line.strip().startswith("#")
        ]
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
        assert '--branch "$KITERUNNER_VERSION"' in INSTALL_SCRIPT


class TestFetchesAreGuarded:
    def test_every_go_install_is_guarded(self) -> None:
        unguarded = []
        for i, line in enumerate(LINES):
            if not line.strip().startswith(("go install", "retry go install")):
                continue
            if "have " not in _preceding_context(i):
                unguarded.append(line.strip())
        assert not unguarded, f"unguarded go install: {unguarded}"

    def test_global_npm_install_is_guarded(self) -> None:
        for i, line in enumerate(LINES):
            if re.search(r"^\s*(retry\s+)?(as_root\s+)?npm install -g", line):
                assert "have " in _preceding_context(
                    i
                ), f"unguarded global npm install at line {i + 1}: {line.strip()}"

    def test_npm_installs_are_version_pinned(self) -> None:
        # Same SBOM argument as the go pins: an unpinned `npm install -g`
        # re-resolves against the registry on every boot even when the binary
        # is present, and installs a different tool on different days.
        unpinned = [
            line.strip()
            for line in LINES
            if re.search(r"^\s*(retry\s+)?(as_root\s+)?npm install -g", line)
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
            if (
                stripped.startswith(("if", "elif", "def", "#"))
                or "-r " in stripped
                or "py_install()" in stripped
            ):
                continue
            if "have " not in _preceding_context(i):
                unguarded.append(stripped)
        assert not unguarded, f"unguarded py_install: {unguarded}"

    def test_only_missing_projectdiscovery_tools_are_installed(self) -> None:
        assert "$missing_pd_tools" in INSTALL_SCRIPT
        assert 'have_pd_tool "$tool" || missing_pd_tools=' in INSTALL_SCRIPT

    def test_httpx_guard_accepts_projectdiscovery_httpx_on_path(
        self, tmp_path: Path
    ) -> None:
        _stub(tmp_path / "bin" / "httpx", exit_code=0)
        assert _have_pd_httpx(tmp_path)

    def test_httpx_guard_rejects_the_python_cli(self, tmp_path: Path) -> None:
        _stub(tmp_path / "bin" / "httpx", exit_code=2)
        assert not _have_pd_httpx(tmp_path)

    def test_httpx_guard_accepts_pdtm_httpx_behind_the_python_cli(
        self, tmp_path: Path
    ) -> None:
        _stub(tmp_path / "bin" / "httpx", exit_code=2)
        _stub(tmp_path / "home" / ".pdtm" / "go" / "bin" / "httpx", exit_code=0)
        assert _have_pd_httpx(tmp_path)

    def test_katana_download_is_guarded(self) -> None:
        idx = next(
            i for i, line in enumerate(LINES) if "katana_${KATANA_VERSION}" in line
        )
        assert "have katana" in _preceding_context(idx, span=8)

    def test_caido_cli_download_is_guarded(self) -> None:
        idx = next(
            i for i, line in enumerate(LINES) if "caido.download/releases" in line
        )
        assert "command -v caido-cli" in _preceding_context(idx, span=10)

    def test_caido_mcp_server_download_is_guarded(self) -> None:
        idx = next(
            i for i, line in enumerate(LINES) if "caido-mcp-server-linux" in line
        )
        assert "command -v caido-mcp-server" in _preceding_context(idx, span=15)

    def test_kiterunner_build_is_guarded(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "assetnote/kiterunner" in line)
        assert "have kr" in _preceding_context(idx, span=4)

    def test_wrangler_install_is_guarded_and_pinned(self) -> None:
        # wrangler is fetched from npm, so the guard-and-pin discipline applies
        # exactly as it does to the go installs: present binary -> no registry
        # request; absent binary -> the pinned version, not @latest.
        idx = next(
            i for i, line in enumerate(LINES) if "wrangler@${WRANGLER_VERSION}" in line
        )
        assert "have wrangler" in _preceding_context(idx, span=6)
        pin = next(
            i
            for i, line in enumerate(LINES)
            if line.strip().startswith("WRANGLER_VERSION=")
        )
        assert re.fullmatch(
            r"WRANGLER_VERSION=\"[0-9]+\.[0-9]+\.[0-9]+\"",
            LINES[pin].strip(),
        ), f"unpinned wrangler version: {LINES[pin]}"

    def test_git_clones_are_guarded_on_target_dir(self) -> None:
        # Clones to persistent paths (fireprox, archivealchemist) are guarded
        # on the target directory existing. Clones to /tmp (kiterunner) are
        # guarded on the binary they produce.
        for i, line in enumerate(LINES):
            if "retry clone_repo" not in line or line.strip().startswith("#"):
                continue
            ctx = _preceding_context(i, span=6)
            has_dir_guard = "! -d " in ctx or "have " in ctx
            assert has_dir_guard, f"unguarded git clone at line {i + 1}: {line.strip()}"

    def test_go_toolchain_is_only_fetched_when_something_needs_building(self) -> None:
        # Fetch the Go toolchain only when a missing tool requires compilation.
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
            i
            for i, line in enumerate(LINES)
            if "tar" in line and "caido-cli" in line and "/usr/local/bin" in line
        )
        assert "as_root" in LINES[idx]

    def test_caido_mcp_server_install_uses_as_root(self) -> None:
        idx = next(
            i
            for i, line in enumerate(LINES)
            if "install -m" in line and "caido-mcp-server" in line
        )
        assert "as_root" in LINES[idx]

    def test_kiterunner_mv_uses_as_root(self) -> None:
        idx = next(
            i
            for i, line in enumerate(LINES)
            if "/usr/local/bin/kr" in line and ("mv " in line or "install " in line)
        )
        assert "as_root" in LINES[idx]

    def test_burp_suite_uses_as_root(self) -> None:
        idx = next(i for i, line in enumerate(LINES) if "mkdir -p /opt/burp" in line)
        assert "as_root" in LINES[idx]

    def test_exiftool_apt_uses_as_root(self) -> None:
        idx = next(
            i
            for i, line in enumerate(LINES)
            if "apt-get" in line and "exiftool" in line
        )
        assert "as_root" in LINES[idx]

    def test_nodejs_apt_uses_as_root(self) -> None:
        idx = next(
            i for i, line in enumerate(LINES) if "apt-get" in line and "nodejs" in line
        )
        assert "as_root" in LINES[idx]


class TestStageFailureDiagnostics:
    def test_failed_stages_keep_actionable_diagnostics(self) -> None:
        # Stages retain a specific error in addition to the final failed-stage list.
        for marker in (
            "WARN: Caido CLI install failed",
            "WARN: Burp Suite download failed",
            "WARN: agent-browser browser download failed",
            "WARN: exiftool install failed",
            "WARN: Node.js install failed",
            "WARN: kiterunner clone failed",
            "WARN: archivealchemist clone failed",
            "WARN: ast-grep install failed",
            "WARN: waymore install failed",
            "WARN: pacu install failed",
            "WARN: agent-browser install failed",
            "WARN: wrangler install failed",
            "WARN: caido-mode npm install failed",
        ):
            assert marker in INSTALL_SCRIPT, f"missing stage diagnostic: {marker}"


def _command(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/bash\nset -eu\n{body}\n")
    path.chmod(0o755)


def _installer_fixture(tmp_path: Path) -> Path:
    """Run the complete installer with no host tools, network, or privileged writes."""
    import shutil

    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in (
        "bash",
        "mkdir",
        "mktemp",
        "rm",
        "mv",
        "chmod",
        "touch",
        "dirname",
        "install",
    ):
        executable = shutil.which(name)
        assert executable
        (bindir / name).symlink_to(executable)
    for name in (
        "httpx",
        "subfinder",
        "naabu",
        "dnsx",
        "uncover",
        "alterx",
        "tlsx",
        "asnmap",
        "katana",
        "protoscope",
        "interactsh-client",
        "2fa",
        "kr",
        "caido-cli",
        "caido-mcp-server",
        "burp",
        "exiftool",
        "ast-grep",
        "waymore",
        "pacu",
        "python3",
    ):
        _command(bindir / name, "exit 0")
    _command(
        bindir / "uname", 'if [ "$1" = -s ]; then echo Linux; else echo x86_64; fi'
    )
    _command(bindir / "node", "echo 24")
    _command(bindir / "sleep", "exit 0")
    # Any unexpected fetch is a hard failure, never a real network request.
    for name in ("curl", "git", "sudo", "apt-get", "uv", "pip"):
        _command(
            bindir / name, f'echo "unexpected {name}" >> "$HOME/commands"; exit 97'
        )
    _command(
        bindir / "go",
        """
if [ "$1" != install ]; then exit 0; fi
count=0
if [ -f "$HOME/go-attempts" ]; then read -r count < "$HOME/go-attempts"; fi
count=$((count + 1))
echo "$count" > "$HOME/go-attempts"
if [ "$count" -le "${GO_FAILURES:-0}" ]; then echo 'transient checksum fetch error' >&2; exit 1; fi
if [ "${GO_NO_ARTIFACT:-0}" = 1 ]; then exit 0; fi
mkdir -p "$GOBIN"
printf '#!/bin/bash\\nexit 0\\n' > "$GOBIN/nuclei"
chmod +x "$GOBIN/nuclei"
""",
    )
    _command(
        bindir / "npm",
        """
if [ "$1" = ls ]; then test -f node_modules/complete; exit; fi
if [ "${2:-}" = -g ]; then
  echo wrangler-install >> "$HOME/commands"
  printf '#!/bin/bash\\nexit 0\\n' > "$HOME/bin/wrangler"
  chmod +x "$HOME/bin/wrangler"
  exit 0
fi
echo npm-install >> "$HOME/commands"
mkdir -p node_modules
if [ "${NPM_FAIL:-0}" = 1 ]; then exit 1; fi
touch node_modules/complete
""",
    )
    _command(
        bindir / "agent-browser",
        """
echo browser-install >> "$HOME/commands"
mkdir -p "$HOME/.cache/agent-browser"
if [ "${BROWSER_FAIL:-0}" = 1 ]; then exit 1; fi
""",
    )
    # Wrangler is deliberately missing: prove a later installation runs after Go fails.
    _command(bindir / "id", "echo 0")
    for relative in (
        "opt/burp/burpsuite.jar",
        "git/fireprox/fire.py",
        "git/fireprox/requirements.txt",
        "git/fireprox/.dreadnode-deps-installed",
        "git/archivealchemist/archive-alchemist.py",
        "skills/caido-mode/package.json",
        "skills/caido-mode/node_modules/complete",
        ".cache/agent-browser/.dreadnode-installed",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("installed\n")
    script = tmp_path / "install.sh"
    script.write_text(
        INSTALL_SCRIPT.replace("/usr/local", str(tmp_path / "usr-local")).replace(
            "/opt/burp", str(tmp_path / "opt/burp")
        )
    )
    return script


def _run_installer(script: Path, **extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", str(script)],
        env={
            "HOME": str(script.parent),
            "PATH": str(script.parent / "bin"),
            "CAPABILITY_ROOT": str(script.parent),
            "TMPDIR": str(script.parent),
            **extra,
        },
        cwd=script.parent,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_transient_go_failure_recovers_with_bounded_retries(tmp_path: Path) -> None:
    script = _installer_fixture(tmp_path)
    result = _run_installer(script, GO_FAILURES="2")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "go-attempts").read_text().strip() == "3"
    assert "installed successfully" in result.stdout


def test_failed_stage_continues_and_rerun_repairs_only_missing_tools(
    tmp_path: Path,
) -> None:
    script = _installer_fixture(tmp_path)
    first = _run_installer(script, GO_FAILURES="3")
    assert first.returncode == 1, first.stderr
    assert "failed stages: nuclei validation" in first.stderr
    assert "installed successfully" not in first.stdout
    assert (tmp_path / "bin/wrangler").is_file()
    assert (tmp_path / "go-attempts").read_text().strip() == "3"
    second = _run_installer(script)
    assert second.returncode == 0, second.stderr
    third = _run_installer(script)
    assert third.returncode == 0, third.stderr
    assert (tmp_path / "go-attempts").read_text().strip() == "4"
    assert (tmp_path / "commands").read_text().splitlines() == ["wrangler-install"]


def test_zero_exit_without_required_binary_is_not_success(tmp_path: Path) -> None:
    script = _installer_fixture(tmp_path)
    result = _run_installer(script, GO_NO_ARTIFACT="1")
    assert result.returncode == 1
    assert "Missing required tool: nuclei" in result.stderr


def test_partial_browser_and_npm_directories_do_not_prevent_repair(
    tmp_path: Path,
) -> None:
    script = _installer_fixture(tmp_path)
    (tmp_path / ".cache/agent-browser/.dreadnode-installed").unlink()
    (tmp_path / "skills/caido-mode/node_modules/complete").unlink()
    first = _run_installer(script, BROWSER_FAIL="1", NPM_FAIL="1")
    assert first.returncode == 1
    assert "failed stages: browser caido_mode" in first.stderr
    second = _run_installer(script)
    assert second.returncode == 0, second.stderr
    assert (tmp_path / "skills/caido-mode/node_modules/complete").is_file()
    assert (tmp_path / ".cache/agent-browser/.dreadnode-installed").is_file()


def test_fireprox_requirements_retry_after_successful_clone(tmp_path: Path) -> None:
    script = _installer_fixture(tmp_path)
    (tmp_path / "git/fireprox/.dreadnode-deps-installed").unlink()
    first = _run_installer(script)
    assert first.returncode == 1
    assert "failed stages: fireprox" in first.stderr
    assert not (tmp_path / "git/fireprox/.dreadnode-deps-installed").exists()
    _command(tmp_path / "bin/uv", "exit 0")
    second = _run_installer(script)
    assert second.returncode == 0, second.stderr
    assert (tmp_path / "git/fireprox/.dreadnode-deps-installed").is_file()


def test_failed_burp_download_is_not_published_and_recovers(tmp_path: Path) -> None:
    script = _installer_fixture(tmp_path)
    jar = tmp_path / "opt/burp/burpsuite.jar"
    jar.unlink()
    _command(
        tmp_path / "bin/curl",
        """
while [ "$1" != -o ]; do shift; done
printf partial > "$2"
echo download >> "$HOME/downloads"
exit "${DOWNLOAD_FAIL:-0}"
""",
    )
    first = _run_installer(script, DOWNLOAD_FAIL="1")
    assert first.returncode == 1
    assert not jar.exists()
    assert len((tmp_path / "downloads").read_text().splitlines()) == 3
    second = _run_installer(script)
    assert second.returncode == 0, second.stderr
    assert jar.read_text() == "partial"


def test_sealed_install_does_not_download_missing_browser(tmp_path: Path) -> None:
    script = _installer_fixture(tmp_path)
    (tmp_path / ".cache/agent-browser/.dreadnode-installed").unlink()
    result = _run_installer(script, DREADNODE_CAPABILITY_INSTALL="sealed")
    assert result.returncode == 0, result.stderr
    assert "browser-install" not in (tmp_path / "commands").read_text()


def test_clone_retry_uses_fresh_staging_after_partial_failure(tmp_path: Path) -> None:
    script = _installer_fixture(tmp_path)
    # Model a new Fireprox install while retaining all other pre-baked tools.
    (tmp_path / "git/fireprox").rename(tmp_path / "saved-fireprox")
    _command(
        tmp_path / "bin/git",
        """
while [ "$#" -gt 1 ]; do shift; done
test ! -f "$1/partial"
echo partial > "$1/partial"
echo clone >> "$HOME/clones"
if [ ! -f "$HOME/clone-retried" ]; then touch "$HOME/clone-retried"; exit 1; fi
echo requirements > "$1/requirements.txt"
echo source > "$1/fire.py"
""",
    )
    _command(tmp_path / "bin/uv", "exit 0")
    result = _run_installer(script)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "clones").read_text().splitlines() == ["clone", "clone"]
    assert (tmp_path / "git/fireprox/.dreadnode-deps-installed").exists()
