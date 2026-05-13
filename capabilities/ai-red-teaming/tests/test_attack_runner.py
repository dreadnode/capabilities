"""Tests for AI Red Teaming attack_runner.py — script generation engine.

Tests cover: attack resolution, transform resolution, scorer resolution,
model alias mapping, goal category mapping, script generation for all modes
(single, campaign, transform study), and generated script compilation.
"""

from __future__ import annotations

import importlib.util
import json
import os
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
    env = {**os.environ, "DREADNODE_WORKSPACE_DIR": "/tmp/airt_test"}
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
        assert resolved.startswith(expected_prefix), f"'{alias}' → '{resolved}' doesn't start with '{expected_prefix}'"

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
        result = _generate({"attack_type": "tap", "goal": "test", "target_model": "groq"})
        assert "error" not in result

    def test_campaign(self) -> None:
        result = _generate({"attack_type": "tap,goat", "goal": "test", "target_model": "groq"})
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
            result = _generate({"attack_type": atk, "goal": "test", "target_model": "groq"})
            assert "error" not in result, f"Attack '{atk}' failed: {result.get('error', '')}"


# =============================================================================
# Generated script quality
# =============================================================================


class TestGeneratedScriptQuality:
    """Generated scripts must compile and contain expected patterns."""

    def _get_script(self, params: dict) -> str:
        result = _generate(params)
        assert "error" not in result
        # Read the generated file
        workflow_file = result.get("workflow_file", "")
        if workflow_file and Path(workflow_file).exists():
            return Path(workflow_file).read_text()
        # Fallback: find most recent file
        wf_dir = Path("/tmp/airt_test/airt/workflows")
        if not wf_dir.exists():
            wf_dir = Path(os.path.expanduser("~/workspace/airt/workflows"))
        files = sorted(wf_dir.glob("*.py"), key=lambda f: f.stat().st_mtime, reverse=True)
        return files[0].read_text() if files else ""

    def test_script_compiles(self) -> None:
        script = self._get_script({"attack_type": "tap", "goal": "test", "target_model": "groq"})
        compile(script, "test.py", "exec")  # Raises SyntaxError if invalid

    def test_script_has_retry_logic(self) -> None:
        script = self._get_script({"attack_type": "tap", "goal": "test", "target_model": "groq"})
        assert "for attempt in range(3)" in script, "Target function should have 3-attempt retry"

    def test_script_has_assessment(self) -> None:
        script = self._get_script({"attack_type": "tap", "goal": "test", "target_model": "groq"})
        assert "Assessment(" in script

    def test_script_has_sdk_configure(self) -> None:
        script = self._get_script({"attack_type": "tap", "goal": "test", "target_model": "groq"})
        assert "dn.configure(" in script

    def test_campaign_script_has_multiple_attacks(self) -> None:
        script = self._get_script({"attack_type": "tap,goat", "goal": "test", "target_model": "groq"})
        assert "tap_attack(" in script
        assert "goat_attack(" in script
