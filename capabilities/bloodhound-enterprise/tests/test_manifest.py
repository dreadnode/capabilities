"""Sanity tests for the capability manifest, skills, and agents."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml


BASE = Path(__file__).resolve().parent.parent


class TestCapabilityManifest:
    def test_capability_yaml_valid(self) -> None:
        manifest = yaml.safe_load((BASE / "capability.yaml").read_text())
        assert manifest["schema"] == 1
        assert manifest["name"] == "bloodhound-enterprise"
        assert manifest["version"]
        assert manifest["description"]


class TestSkills:
    def test_at_least_six_skills(self) -> None:
        skill_dirs = [p for p in (BASE / "skills").iterdir() if p.is_dir()]
        assert len(skill_dirs) >= 6

    def test_every_skill_has_frontmatter(self) -> None:
        for skill_dir in (BASE / "skills").iterdir():
            if not skill_dir.is_dir():
                continue
            md = skill_dir / "SKILL.md"
            assert md.exists(), f"{skill_dir.name} missing SKILL.md"
            text = md.read_text()
            assert text.startswith("---"), f"{skill_dir.name} lacks frontmatter"
            end = text.find("---", 3)
            fm = yaml.safe_load(text[3:end])
            assert "name" in fm, f"{skill_dir.name} missing name"
            assert "description" in fm, f"{skill_dir.name} missing description"
            # Description must include trigger phrases for auto-discovery.
            assert len(fm["description"]) > 80, (
                f"{skill_dir.name} description too short for triggering"
            )


class TestAgents:
    def test_at_least_three_agents(self) -> None:
        agents = list((BASE / "agents").glob("*.md"))
        assert len(agents) >= 3

    def test_every_agent_has_frontmatter(self) -> None:
        for agent_md in (BASE / "agents").glob("*.md"):
            text = agent_md.read_text()
            assert text.startswith("---")
            end = text.find("---", 3)
            fm = yaml.safe_load(text[3:end])
            assert "name" in fm
            assert "description" in fm


class TestRuntimeImports:
    def test_runtime_modules_parse(self) -> None:
        for py in (BASE / "runtime").glob("*.py"):
            ast.parse(py.read_text())

    def test_tool_modules_parse(self) -> None:
        for py in (BASE / "tools").glob("*.py"):
            ast.parse(py.read_text())


class TestRuntimeImportable:
    """Re-import runtime modules to catch class-level errors that AST
    parsing misses (decorators, type annotations resolving)."""

    def test_runtime_client_imports(self) -> None:
        import importlib

        importlib.import_module("runtime.client")

    def test_runtime_types_imports(self) -> None:
        import importlib

        importlib.import_module("runtime.types")

    @pytest.mark.parametrize(
        "tool_module",
        [
            "tools.auth",
            "tools.cypher",
            "tools.attack_paths",
            "tools.asset_groups",
            "tools.entities",
            "tools.data_ingestion",
            "tools.posture",
        ],
    )
    def test_tool_modules_importable(self, tool_module: str) -> None:
        # tool modules import dreadnode.agents.tools which won't be
        # available in a bare CI env — skip with a clear marker.
        try:
            import importlib

            importlib.import_module(tool_module)
        except ImportError as exc:
            if "dreadnode" in str(exc):
                pytest.skip("dreadnode SDK not installed in this environment")
            raise
