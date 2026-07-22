from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_agent_routes_broad_scopes_to_initial_recon() -> None:
    agent = (ROOT / "agents" / "web-security.md").read_text()

    assert "load `initial-recon`" in agent
    assert "`scripts/pd-tool`" in agent
    assert "with `curl`, `python`, `ffuf`" not in agent


def test_initial_recon_names_measured_funnel_and_ledger() -> None:
    skill = (ROOT / "skills" / "initial-recon" / "SKILL.md").read_text()

    for tool in ("subfinder", "dnsx", "naabu", "httpx", "tlsx", "katana", "nuclei"):
        assert f"`{tool}`" in skill
    assert "Coverage ledger" in skill
    assert "scheduled/completed denominators" in skill


def test_manifest_checks_the_recon_toolchain_through_resolver() -> None:
    manifest = yaml.safe_load((ROOT / "capability.yaml").read_text())
    checks = {entry["name"]: entry["command"] for entry in manifest["checks"]}

    for tool in (
        "subfinder",
        "httpx",
        "naabu",
        "dnsx",
        "katana",
        "tlsx",
        "alterx",
        "asnmap",
        "uncover",
        "nuclei",
    ):
        assert checks[tool].startswith(f"scripts/pd-tool {tool} ")
