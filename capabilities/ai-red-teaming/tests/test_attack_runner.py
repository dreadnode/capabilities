"""Tests for AI Red Teaming attack_runner.py — script generation engine.

Tests cover: attack resolution, transform resolution, scorer resolution,
model alias mapping, goal category mapping, script generation for all modes
(single, campaign, transform study), and generated script compilation.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from dreadnode.app.env import resolve_python_executable

# ---------------------------------------------------------------------------
# Load attack_runner as a module (it's not a package, just a script)
# ---------------------------------------------------------------------------

RUNNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "attack_runner.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("attack_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


def _generate(params: dict) -> dict:
    """Call attack_runner via subprocess and return JSON result."""
    payload = json.dumps({"name": "generate_attack", "parameters": params})
    env = {**os.environ, "AIRT_WORKFLOWS_DIR": "/tmp/airt_test_workflows"}
    python_executable = resolve_python_executable()
    print(f"[INFO] Running test with Python: {python_executable}", file=sys.stderr)
    result = subprocess.run(
        [python_executable, str(RUNNER_PATH)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    return json.loads(result.stdout)


# =============================================================================
# Attack resolution
# =============================================================================


class TestAttackResolution:
    """All 12 attack types + aliases must resolve."""

    @pytest.mark.parametrize(
        "name",
        [
            "tap",
            "pair",
            "crescendo",
            "goat",
            "prompt",
            "rainbow",
            "gptfuzzer",
            "autodan_turbo",
            "renellm",
            "beast",
            "drattack",
            "deep_inception",
        ],
    )
    def test_canonical_attack_resolves(self, name: str) -> None:
        result = runner._resolve_attack(name)
        assert result is not None
        assert "function" in result
        assert "module" in result

    @pytest.mark.parametrize(
        "alias,canonical",
        [
            ("fuzzer", "gptfuzzer_attack"),
            ("inception", "deep_inception_attack"),
            ("autodan", "autodan_turbo_attack"),
        ],
    )
    def test_attack_alias_resolves(self, alias: str, canonical: str) -> None:
        result = runner._resolve_attack(alias)
        assert result["canonical_name"] == canonical

    def test_unknown_attack_returns_error(self) -> None:
        with pytest.raises((ValueError, KeyError)):
            runner._resolve_attack("nonexistent_attack")

class TestNormalizeAttackNames:
    """Regression: generate_category_attack must not iterate a bare string
    character-by-character (which produced 'Unknown attack: t' errors)."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("tap", ["tap"]),
            ("tap,goat", ["tap", "goat"]),
            ("tap, goat , pair", ["tap", "goat", "pair"]),
            (["tap"], ["tap"]),
            (["tap", "goat"], ["tap", "goat"]),
            ("tap_attack", ["tap_attack"]),
            ("['tap']", ["tap"]),
            ("['tap','goat']", ["tap", "goat"]),
            ("", []),
            (None, []),
        ],
    )
    def test_normalize(self, raw, expected) -> None:
        assert runner._normalize_attack_names(raw) == expected

    def test_bare_string_does_not_split_to_chars(self) -> None:
        # The exact bug: "tap" must NOT become ['t', 'a', 'p'].
        result = runner._normalize_attack_names("tap")
        assert result == ["tap"]
        assert "t" not in result



# =============================================================================
# Transform resolution
# =============================================================================


class TestTransformResolution:
    """Transforms must resolve to valid SDK import paths."""

    @pytest.mark.parametrize(
        "name",
        [
            "base64",
            "hex",
            "leetspeak",
            "rot13",
            "atbash",
            "morse",
            "braille",
            "zalgo",
            "role_play_wrapper",
            "ascii_art",
            "authority",
            "social_proof",
            "skeleton_key_framing",
            "direct_extraction",
            "boundary_probe",
            "reflection_probe",
            "reasoning_hijack",
            "cot_backdoor",
            "payload_split",
            "emoji_smuggle",
            "nested_fiction",
        ],
    )
    def test_common_transform_resolves(self, name: str) -> None:
        result = runner._resolve_transform(name)
        assert result is not None
        assert "module" in result
        assert "name" in result
        assert "code" in result

    def test_parameterized_transform(self) -> None:
        result = runner._resolve_transform("caesar(5)")
        assert result is not None

    def test_unknown_transform_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown transform"):
            runner._resolve_transform("completely_fake_transform")

    def test_transform_count_above_180(self) -> None:
        """Capability should have 180+ transforms registered."""
        assert len(runner._TRANSFORM_DEFS) >= 180


# =============================================================================
# Scorer resolution
# =============================================================================


class TestScorerResolution:
    """All registered scorers must resolve."""

    @pytest.mark.parametrize(
        "name",
        [
            "refusal",
            "credential_leakage",
            "system_prompt_leaked",
            "detect_pii",
            "detect_bias",
            "goal_hijacking",
            "rce",
            "tool_invoked",
            "cascade_propagation",
            "sentiment",
            "readability",
            "length_in_range",
            "training_data_memorization",
        ],
    )
    def test_scorer_resolves(self, name: str) -> None:
        assert name in runner.SCORER_REGISTRY

    def test_scorer_count_above_80(self) -> None:
        """Capability should have 80+ scorers registered."""
        assert len(runner.SCORER_REGISTRY) >= 80

    def test_new_scorers_present(self) -> None:
        """Scorers added in this PR must be present."""
        new_scorers = [
            "sentiment",
            "readability",
            "character_consistency",
            "type_token_ratio",
            "training_data_memorization",
            "length_in_range",
            "length_ratio",
            "length_target",
            "env_var_exfiltration",
            "favicon_exfiltration",
            "hidden_documentation_injection",
            "package_readme_poisoning",
            "resource_hint_exfil",
            "detect_refusal_zero_shot",
            "zero_shot_classification",
            "detect_pii_presidio",
            "contains",
            "detect_sensitive_keywords",
            "detect_unsafe_shell_content",
            "detect_ansi_escapes",
            "memory_poisoning",
        ]
        for name in new_scorers:
            assert name in runner.SCORER_REGISTRY, f"Scorer '{name}' missing"


# =============================================================================
# Model alias resolution
# =============================================================================


class TestModelAliases:
    """Model aliases must resolve to valid litellm paths."""

    @pytest.mark.parametrize(
        "alias,expected_prefix",
        [
            ("gpt-4o", "openai/"),
            ("gpt-4.1", "openai/"),
            ("o4-mini", "openai/"),
            ("claude", "anthropic/"),
            ("claude-opus", "anthropic/"),
            ("claude-haiku", "anthropic/"),
            ("groq", "groq/"),
            ("groq scout", "groq/"),
            ("gemini", "gemini/"),
            ("mistral", "mistral/"),
            ("deepseek", "deepseek/"),
        ],
    )
    def test_model_alias_prefix(self, alias: str, expected_prefix: str) -> None:
        resolved = runner.MODEL_ALIASES.get(alias, alias)
        assert resolved.startswith(
            expected_prefix
        ), f"'{alias}' → '{resolved}' doesn't start with '{expected_prefix}'"

    def test_model_alias_count(self) -> None:
        """Should have 100+ model aliases."""
        assert len(runner.MODEL_ALIASES) >= 100


# =============================================================================
# Goal category resolution
# =============================================================================


class TestGoalCategories:
    """Goal categories must match SDK GoalCategory enum."""

    @pytest.mark.parametrize(
        "category",
        [
            "harmful_content",
            "credential_leak",
            "system_prompt_leak",
            "pii_extraction",
            "tool_misuse",
            "jailbreak_general",
            "refusal_bypass",
            "bias_fairness",
            "content_policy",
        ],
    )
    def test_valid_category_resolves(self, category: str) -> None:
        result = runner._resolve_goal_category(category)
        assert result != "JAILBREAK_GENERAL" or category == "jailbreak_general"

    def test_empty_category_defaults(self) -> None:
        assert runner._resolve_goal_category(None) == "JAILBREAK_GENERAL"
        assert runner._resolve_goal_category("") == "JAILBREAK_GENERAL"


# =============================================================================
# Script generation — end-to-end
# =============================================================================


class TestScriptGeneration:
    """Generated scripts must be valid Python that compiles."""

    def test_single_attack(self) -> None:
        result = _generate(
            {"attack_type": "tap", "goal": "test", "target_model": "groq"}
        )
        assert "error" not in result

    def test_campaign(self) -> None:
        result = _generate(
            {"attack_type": "tap,goat", "goal": "test", "target_model": "groq"}
        )
        assert "error" not in result

    def test_transform_study(self) -> None:
        result = _generate(
            {
                "attack_type": "tap",
                "goal": "test",
                "target_model": "groq",
                "transforms": ["base64", "leetspeak"],
                "compare_transforms": True,
            }
        )
        assert "error" not in result

    def test_with_scorer(self) -> None:
        result = _generate(
            {
                "attack_type": "tap",
                "goal": "test",
                "target_model": "groq",
                "scorers": ["credential_leakage"],
            }
        )
        assert "error" not in result

    def test_with_goal_category(self) -> None:
        result = _generate(
            {
                "attack_type": "tap",
                "goal": "test",
                "target_model": "groq",
                "goal_category": "harmful_content",
            }
        )
        assert "error" not in result

    def test_campaign_with_transforms(self) -> None:
        result = _generate(
            {
                "attack_type": "tap,goat",
                "goal": "test",
                "target_model": "groq",
                "transforms": ["base64"],
            }
        )
        assert "error" not in result

    def test_all_12_attack_types_generate(self) -> None:
        """Every attack type must generate a valid script."""
        for atk in [
            "tap",
            "pair",
            "crescendo",
            "goat",
            "prompt",
            "rainbow",
            "gptfuzzer",
            "autodan_turbo",
            "renellm",
            "beast",
            "drattack",
            "deep_inception",
        ]:
            result = _generate(
                {"attack_type": atk, "goal": "test", "target_model": "groq"}
            )
            assert (
                "error" not in result
            ), f"Attack '{atk}' failed: {result.get('error', '')}"


# =============================================================================
# Generated script quality
# =============================================================================


class TestGeneratedScriptQuality:
    """Generated scripts must compile and contain expected patterns."""

    def _get_script(self, params: dict) -> str:
        result = _generate(params)
        assert "error" not in result, result
        filepath = result.get("filepath") or result.get("workflow_file") or ""
        assert (
            filepath and Path(filepath).exists()
        ), f"Generated script missing: {result}"
        return Path(filepath).read_text()

    def test_script_compiles(self) -> None:
        script = self._get_script(
            {"attack_type": "tap", "goal": "test", "target_model": "groq"}
        )
        compile(script, "test.py", "exec")  # Raises SyntaxError if invalid

    def test_script_has_retry_logic(self) -> None:
        script = self._get_script(
            {"attack_type": "tap", "goal": "test", "target_model": "groq"}
        )
        assert (
            "for attempt in range(3)" in script
        ), "Target function should have 3-attempt retry"

    def test_script_has_assessment(self) -> None:
        script = self._get_script(
            {"attack_type": "tap", "goal": "test", "target_model": "groq"}
        )
        assert "Assessment(" in script

    def test_script_has_sdk_configure(self) -> None:
        script = self._get_script(
            {"attack_type": "tap", "goal": "test", "target_model": "groq"}
        )
        assert "dn.configure(" in script

    def test_campaign_script_has_multiple_attacks(self) -> None:
        script = self._get_script(
            {"attack_type": "tap,goat", "goal": "test", "target_model": "groq"}
        )
        assert "tap_attack(" in script
        assert "goat_attack(" in script


class TestUniqueWorkflowPath:
    """Collision-safe workflow saving (ENG-6813).

    Regeneration must never overwrite an existing workflow file — a user may
    have hand-patched it after generation.
    """

    def test_returns_original_when_no_collision(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(runner, "WORKFLOWS_DIR", tmp_path)
        path, name = runner._unique_workflow_path("attack.py")
        assert name == "attack.py"
        assert path == tmp_path / "attack.py"

    def test_does_not_overwrite_hand_patched_file(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(runner, "WORKFLOWS_DIR", tmp_path)
        existing = tmp_path / "attack.py"
        existing.write_text("# hand-patched, do not clobber")

        path, name = runner._unique_workflow_path("attack.py")

        assert name == "attack_v2.py"
        assert path == tmp_path / "attack_v2.py"
        # Original is left untouched.
        assert existing.read_text() == "# hand-patched, do not clobber"

    def test_increments_version_until_free(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(runner, "WORKFLOWS_DIR", tmp_path)
        (tmp_path / "a.py").write_text("x")
        (tmp_path / "a_v2.py").write_text("x")

        path, name = runner._unique_workflow_path("a.py")

        assert name == "a_v3.py"
        assert path == tmp_path / "a_v3.py"


class TestGeneratedWorkflowAssessmentMethods:
    """Generated workflows must only call methods that exist on the SDK
    ``Assessment`` class (ENG-6777).

    Older templates called ``assessment.record_attack()``, ``analyze()``,
    ``push_analytics()``, ``generate_report()`` and ``push_report()`` — none
    of which exist on the current ``Assessment`` — so the TUI's primary path
    crashed with ``AttributeError`` on a fresh install. These tests guard
    against that class of regression.
    """

    # The five methods named in the ticket that no longer exist.
    DEAD_METHODS = (
        "record_attack",
        "analyze",
        "push_analytics",
        "generate_report",
        "push_report",
    )

    def test_runner_source_has_no_dead_methods(self) -> None:
        """No generator template (any mode) emits a dead Assessment call."""
        source = RUNNER_PATH.read_text()
        for method in self.DEAD_METHODS:
            assert ".{}(".format(method) not in source, (
                "attack_runner references removed Assessment method "
                "'{}' — generated workflows will crash (ENG-6777)".format(method)
            )

    def _generate_script(self, tmp_path, monkeypatch, params: dict) -> str:
        monkeypatch.setattr(runner, "WORKFLOWS_DIR", tmp_path)
        result = runner.generate_attack({**params, "generate_only": True})
        assert "error" not in result, result
        return Path(result["filepath"]).read_text()

    def test_single_attack_calls_exist_on_assessment(
        self, tmp_path, monkeypatch
    ) -> None:
        """Every ``assessment.<m>()`` in the template is a real Assessment attr.

        Checks dynamically against the installed SDK so the test also fails if
        the SDK renames/removes a method the template still relies on.
        """
        from dreadnode.airt.assessment import Assessment

        script = self._generate_script(
            tmp_path,
            monkeypatch,
            {"attack_type": "tap", "goal": "test", "target_model": "groq"},
        )
        called = set(re.findall(r"\bassessment\.(\w+)\s*\(", script))
        assert called, "expected assessment.<method>() calls in generated script"
        missing = sorted(m for m in called if not hasattr(Assessment, m))
        assert not missing, (
            "generated workflow calls Assessment methods that do not exist: "
            "{}".format(missing)
        )


# =============================================================================
# ATLAS multi-agent campaign generation
# =============================================================================


def _generate_method(method: str, params: dict, timeout: int = 30) -> dict:
    """Call attack_runner via subprocess for an arbitrary method and return JSON."""
    payload = json.dumps({"name": method, "parameters": params})
    env = {**os.environ, "AIRT_WORKFLOWS_DIR": "/tmp/airt_test_workflows"}
    python_executable = resolve_python_executable()
    result = subprocess.run(
        [python_executable, str(RUNNER_PATH)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return json.loads(result.stdout)


_ATLAS_BASE = {
    "agent_url": "http://localhost:8000/attack",
    "attacker_model": "groq scout",
    "scenario_name": "finops",
    "total_budget": 8,
    "generate_only": True,
}


class TestAtlasGeneration:
    def test_generates_without_error(self):
        result = _generate_method("generate_atlas_attack", _ATLAS_BASE)
        assert "error" not in result, result.get("error")
        assert result["filename"].startswith("atlas_")

    def test_generated_script_compiles_and_has_expected_pieces(self):
        result = _generate_method("generate_atlas_attack", _ATLAS_BASE)
        assert "error" not in result, result.get("error")
        script = Path(result["filepath"]).read_text()
        # Compiles cleanly.
        compile(script, result["filepath"], "exec")
        # Wires the SDK ATLAS entrypoint and a 3-surface agent target.
        assert "from dreadnode.airt.atlas import atlas_attack" in script
        assert "async def target(prompt: str, *, surface: str" in script
        assert '"surface": surface' in script
        assert '"tool_calls": tool_calls' in script
        assert "await atlas_attack(" in script
        assert 'SCENARIO_NAME = "finops"' in script
        assert "TOTAL_BUDGET = 8" in script
        # Default objective catalog is embedded with category coverage.
        assert "OBJECTIVES = " in script
        for cat in ("TW", "EA", "CB", "DE", "GH", "MP", "TB", "RP"):
            assert "'category': '{}'".format(cat) in script

    def test_custom_objectives_are_embedded(self):
        params = {
            **_ATLAS_BASE,
            "objectives": [{"id": "X1", "category": "TW", "goal": "do the bad thing"}],
        }
        result = _generate_method("generate_atlas_attack", params)
        assert "error" not in result, result.get("error")
        script = Path(result["filepath"]).read_text()
        assert "'id': 'X1'" in script
        assert "do the bad thing" in script

    def test_bearer_auth_injects_header(self):
        params = {**_ATLAS_BASE, "agent_auth_type": "bearer", "agent_auth_env_var": "ENV_TOK"}
        result = _generate_method("generate_atlas_attack", params)
        assert "error" not in result, result.get("error")
        script = Path(result["filepath"]).read_text()
        assert 'os.environ.get("ENV_TOK"' in script
        assert "Authorization" in script


class TestAtlasValidation:
    def test_missing_agent_url_errors(self):
        params = {k: v for k, v in _ATLAS_BASE.items() if k != "agent_url"}
        result = _generate_method("generate_atlas_attack", params)
        assert "error" in result
        assert "agent_url" in result["error"]

    def test_missing_attacker_model_errors(self):
        params = {k: v for k, v in _ATLAS_BASE.items() if k != "attacker_model"}
        result = _generate_method("generate_atlas_attack", params)
        assert "error" in result
        assert "attacker_model" in result["error"]

    def test_malformed_objective_errors(self):
        params = {**_ATLAS_BASE, "objectives": [{"id": "X1", "category": "TW"}]}  # no goal
        result = _generate_method("generate_atlas_attack", params)
        assert "error" in result
        assert "goal" in result["error"]

    def test_zero_budget_errors(self):
        params = {**_ATLAS_BASE, "total_budget": 0}
        result = _generate_method("generate_atlas_attack", params)
        assert "error" in result
        assert "total_budget" in result["error"]
