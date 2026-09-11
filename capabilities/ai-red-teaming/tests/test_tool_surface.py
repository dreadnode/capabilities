"""Public tool-surface invariant for the ai-red-teaming capability.

Regression tests for ENG-8467. A tool written in ``tools/*.py`` that is
documented as a tool (agent prompt, skill ``allowed-tools``) but missing the
``@safe_tool`` (``@tool``) decorator is silently dropped by the capability
loader: ``_discover_python_tools`` (dreadnode-tiger
``packages/sdk/dreadnode/capabilities/loader.py``) only registers module
attributes that are ``Tool`` instances or ``Toolset`` instances. A bare
function is skipped with no error, so the agent is instructed to call a tool
that does not exist (``Tool '...' not found``).

These tests assert the invariant directly: every documented tool must be a
registered ``Tool`` with the expected name. Loading the modules is enough —
no tool is invoked, so no network or platform access is required.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

pytest.importorskip("dreadnode.agents.tools")

from dreadnode.agents.tools import Tool

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
CAP_DIR = Path(__file__).resolve().parents[1]


def _load_all_tool_modules() -> dict[str, object]:
    """Load every tools/*.py exactly like the runtime loader discovers files."""
    modules: dict[str, object] = {}
    for path in sorted(TOOLS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(
            f"airt_{path.stem}_under_test", path
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        modules[path.name] = mod
    return modules


_REGISTERED = _load_all_tool_modules()


def _tool_names(module) -> set[str]:
    return {value.name for value in vars(module).values() if isinstance(value, Tool)}


def _skills_with_allowed_tools() -> dict[str, set[str]]:
    """Map skill path -> allowed-tools names from frontmatter."""
    import yaml

    out: dict[str, set[str]] = {}
    for skill in sorted((CAP_DIR / "skills").rglob("SKILL.md")):
        text = skill.read_text()
        if not text.startswith("---\n"):
            continue
        end = text.find("\n---", 4)
        if end == -1:
            continue
        try:
            meta = yaml.safe_load(text[4:end])
        except yaml.YAMLError as exc:
            # A skill with broken frontmatter must fail the invariant loudly,
            # not silently drop its allowed-tools list from coverage.
            raise AssertionError(f"{skill}: malformed frontmatter: {exc}") from exc
        if not isinstance(meta, dict):
            continue
        allowed = (meta or {}).get("allowed-tools", "")
        if isinstance(allowed, str):
            names = {n for n in re.split(r"[,\s]+", allowed) if n}
        elif isinstance(allowed, list):
            names = set(allowed)
        else:
            continue
        if names:
            out[str(skill.relative_to(CAP_DIR))] = names
    return out


EXPECTED_SURFACE = {
    # ENG-8467: provision_environment was defined without @safe_tool and never
    # registered, so agents hit `Tool 'ai_red_teaming__provision_environment'
    # not found` on the first step of every hosted-target run.
    "environments.py": {
        "list_environments",
        "provision_environment",
        "teardown_environment",
    },
    # Same root cause: generate_agentic_suite_attack is documented as a tool in
    # agents/ai-red-teaming-agent.md but was never decorated, so the "run all
    # possible attacks" path shipped with no executable tool.
    "attacks.py": {"generate_agentic_suite_attack"},
}


class TestRegressionENG8467:
    @pytest.mark.parametrize("module_name, expected", EXPECTED_SURFACE.items())
    def test_documented_tools_are_registered(self, module_name, expected) -> None:
        registered = _tool_names(_REGISTERED[module_name])
        missing = expected - registered
        assert not missing, (
            f"{module_name}: documented tools not registered: {sorted(missing)}. "
            "A tools/*.py function is only registered if it carries @safe_tool "
            "(which applies @tool internally) or is a Toolset instance."
        )

    def test_provision_environment_is_a_tool_instance(self) -> None:
        attr = getattr(_REGISTERED["environments.py"], "provision_environment")
        assert isinstance(attr, Tool), (
            "provision_environment must be a registered Tool; a bare function is "
            "invisible to the capability loader and agents get 'Tool not found'."
        )
        assert attr.name == "provision_environment"


# Skill tools that are intentionally NOT implemented in this capability: they
# are documented for the platform-hosted ClickHouse analytics service
# (trace-analysis-advisor) that the runtime exposes in analytics contexts.
# The allowlist keeps the invariant below able to assert the FULL rule: every
# skill allowed-tools name must be a registered Tool OR be explicitly listed
# here. A phantom tool (documented but defined nowhere) fails the test.
PLATFORM_PROVIDED_TOOLS = frozenset(
    {
        "analyze_attack_effectiveness",
        "suggest_optimal_transforms",
        "predict_attack_success",
        "identify_vulnerability_patterns",
        "get_historical_metrics",
    }
)


class TestSkillAllowedToolsInvariant:
    """Every skill-listed tool name must resolve somewhere: it is either a
    registered Tool in this capability's tools/, or explicitly allowlisted as
    platform-provided (PLATFORM_PROVIDED_TOOLS). A defined-but-undecorated tool
    (the ENG-8467 failure mode) and a documented-but-nowhere tool both fail
    immediately."""

    def test_all_allowed_tools_resolve_or_are_allowlisted(self) -> None:
        # Name -> module of every attribute the tools modules expose.
        attrs: dict[str, str] = {}
        for rel_path, module in _REGISTERED.items():
            for name in vars(module):
                if not name.startswith("_"):
                    attrs.setdefault(
                        name, rel_path
                    )  # first module wins (loader dedups)
        registered_names = set()
        for module in _REGISTERED.values():
            registered_names |= _tool_names(module)

        problems: list[str] = []
        for skill, allowed in _skills_with_allowed_tools().items():
            for name in sorted(allowed):
                if name in attrs and name not in registered_names:
                    problems.append(
                        f"{skill}: '{name}' (defined in {attrs[name]}) is not a registered Tool"
                    )
                elif (
                    name not in registered_names and name not in PLATFORM_PROVIDED_TOOLS
                ):
                    problems.append(
                        f"{skill}: '{name}' is documented as a tool but defined "
                        "nowhere in tools/ and not in PLATFORM_PROVIDED_TOOLS"
                    )
        assert not problems, (
            "Skill allowed-tools references unresolved tools:\n" + "\n".join(problems)
        )


class TestProvisionErrorContract:
    """provision_environment's failure modes, now that it is a live tool.

    The not-found path must return a plain ``Error:`` string (skill §5 semantics:
    adjust params, don't blind-retry) instead of raising, so the @safe_tool
    wrapper does not mislabel a user-input error as an internal tool fault.
    Non-not-found failures must still be caught by the wrapper and surfaced as a
    formatted ``Error:`` string (never a raw traceback).
    """

    def test_not_found_returns_error_string_with_hint(self, monkeypatch) -> None:
        env = _REGISTERED["environments.py"]
        pytest.importorskip("dreadnode.app.api.client")
        pytest.importorskip("dreadnode.core.environment")
        from dreadnode.app.api.client import NotFoundError

        class _FakeEnv:
            def setup(self):
                raise NotFoundError("task not found (404)")

        def _fake_configured():
            return None, object(), "my-org", "main"

        import dreadnode.core.environment as core_env

        monkeypatch.setattr(env, "_configured", _fake_configured)
        monkeypatch.setattr(core_env, "TaskEnvironment", lambda api, **kw: _FakeEnv())

        out = env.provision_environment("ml-extraction-fraud-tabular")
        assert isinstance(out, str)
        assert out.startswith("Error: Task 'ml-extraction-fraud-tabular' not found.")
        assert "<org>/<name>" in out

    def test_other_failures_surface_via_safe_tool_not_raise(self, monkeypatch) -> None:
        env = _REGISTERED["environments.py"]
        pytest.importorskip("dreadnode.core.environment")

        class _BoomEnv:
            def setup(self):
                raise ValueError("provider exploded")

        def _fake_configured():
            return None, object(), "my-org", "main"

        import dreadnode.core.environment as core_env

        monkeypatch.setattr(env, "_configured", _fake_configured)
        monkeypatch.setattr(core_env, "TaskEnvironment", lambda api, **kw: _BoomEnv())

        out = env.provision_environment("ml-extraction-fraud-tabular")
        assert isinstance(out, str)
        assert out.startswith("Error:")
        assert "'provision_environment'" in out
        assert "could not complete" in out
        assert "provider exploded" in out
