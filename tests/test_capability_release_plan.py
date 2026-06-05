from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "capability_release_plan.py"
)
SPEC = importlib.util.spec_from_file_location("capability_release_plan", MODULE_PATH)
assert SPEC is not None
planner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = planner
SPEC.loader.exec_module(planner)


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def write_manifest(root: Path, *, version: str, description: str = "Demo") -> None:
    cap_dir = root / "capabilities" / "demo"
    cap_dir.mkdir(parents=True, exist_ok=True)
    (cap_dir / "capability.yaml").write_text(
        "\n".join(
            [
                "schema: 1",
                "name: demo",
                f'version: "{version}"',
                f"description: {description}",
                "author:",
                "  name: Dreadnode",
                "",
            ]
        )
    )


def commit_all(message: str) -> str:
    git("add", ".")
    git("commit", "-m", message)
    return git("rev-parse", "HEAD")


def init_repo(tmp_path: Path) -> None:
    git("init")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "Test User")
    write_manifest(tmp_path, version="1.0.0")
    commit_all("initial capability")


def test_plans_release_for_capability_version_bump(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    init_repo(tmp_path)
    git("tag", "capability/demo/v1.0.0")
    base = git("rev-parse", "HEAD")

    write_manifest(tmp_path, version="1.1.0")
    head = commit_all("bump demo capability")

    releases = planner.build_release_plan(base, head)

    assert len(releases) == 1
    assert releases[0].capability == "demo"
    assert releases[0].version == "1.1.0"
    assert releases[0].tag == "capability/demo/v1.1.0"
    assert releases[0].title == "demo v1.1.0"
    assert releases[0].previous_tag == "capability/demo/v1.0.0"


def test_skips_manifest_changes_without_version_bump(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    init_repo(tmp_path)
    base = git("rev-parse", "HEAD")

    write_manifest(tmp_path, version="1.0.0", description="Updated demo")
    head = commit_all("update description")

    assert planner.build_release_plan(base, head) == []


def test_skips_release_when_target_tag_already_exists(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    init_repo(tmp_path)
    base = git("rev-parse", "HEAD")

    write_manifest(tmp_path, version="1.1.0")
    head = commit_all("bump demo capability")
    git("tag", "capability/demo/v1.1.0")

    assert planner.build_release_plan(base, head) == []
