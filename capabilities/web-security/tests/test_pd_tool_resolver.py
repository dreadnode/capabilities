from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


RESOLVER = Path(__file__).parents[1] / "scripts" / "pd-tool"


def _binary(path: Path, body: str) -> None:
    path.write_text(f"#!/usr/bin/env bash\n{body}\n")
    path.chmod(0o755)


def _run(tmp_path: Path, tool: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(tmp_path / "home")
    env["PATH"] = f"{tmp_path / 'path'}:/usr/bin:/bin"
    return subprocess.run(
        [str(RESOLVER), tool, *args],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_prefers_pdtm_httpx_over_path_collision(tmp_path: Path) -> None:
    pdtm = tmp_path / "home" / ".pdtm" / "go" / "bin"
    path_dir = tmp_path / "path"
    pdtm.mkdir(parents=True)
    path_dir.mkdir()
    _binary(pdtm / "httpx", 'echo "projectdiscovery:$*"')
    _binary(path_dir / "httpx", 'echo "python-httpx:$*"')

    result = _run(tmp_path, "httpx", "-version")

    assert result.returncode == 0
    assert result.stdout.strip() == "projectdiscovery:-version"


def test_rejects_ambiguous_path_httpx(tmp_path: Path) -> None:
    path_dir = tmp_path / "path"
    path_dir.mkdir()
    _binary(path_dir / "httpx", 'echo "The httpx command line client"')

    result = _run(tmp_path, "httpx", "-version")

    assert result.returncode == 126
    assert "refusing ambiguous httpx binary" in result.stderr


def test_runs_non_httpx_path_binary(tmp_path: Path) -> None:
    path_dir = tmp_path / "path"
    path_dir.mkdir()
    _binary(path_dir / "subfinder", 'echo "subfinder:$*"')

    result = _run(tmp_path, "subfinder", "-version")

    assert result.returncode == 0
    assert result.stdout.strip() == "subfinder:-version"


def test_rejects_unknown_tool(tmp_path: Path) -> None:
    result = _run(tmp_path, "definitely-not-pd")

    assert result.returncode == 2
    assert "unsupported ProjectDiscovery tool" in result.stderr


@pytest.mark.parametrize(
    "tool", ["subfinder", "httpx", "naabu", "dnsx", "katana", "nuclei"]
)
def test_supported_tool_without_binary_is_clear(tmp_path: Path, tool: str) -> None:
    (tmp_path / "path").mkdir()

    result = _run(tmp_path, tool, "-version")

    assert result.returncode == 127
    assert f"{tool} not found" in result.stderr
