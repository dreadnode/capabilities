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


class TestCustomHttpTarget:
    """Custom HTTP endpoint targets for standard attacks (any URL, not a model)."""

    def _script(self, tmp_path, monkeypatch, params: dict) -> str:
        monkeypatch.setattr(runner, "WORKFLOWS_DIR", tmp_path)
        monkeypatch.setattr(runner, "METADATA_FILE", tmp_path / ".workflow_metadata.json")
        result = runner.generate_attack({**params, "generate_only": True})
        assert "error" not in result, result
        return Path(result["filepath"]).read_text()

    def test_custom_url_generates_compiling_http_target(self, tmp_path, monkeypatch) -> None:
        script = self._script(
            tmp_path,
            monkeypatch,
            {
                "attack_type": "tap",
                "goal": "probe the endpoint",
                "custom_url": "https://api.example.com/chat",
                "custom_auth_type": "bearer",
                "custom_auth_env_var": "MY_API_KEY",
                "custom_request_template": '{"input": "{prompt}"}',
                "custom_response_text_path": "$.output.text",
                "attacker_model": "groq",
            },
        )
        compile(script, "workflow.py", "exec")
        assert "async def target(prompt: str) -> str:" in script
        assert "https://api.example.com/chat" in script
        assert "import httpx" in script
        assert "jsonpath_ng" in script
        assert "Bearer" in script
        assert "MY_API_KEY" in script
        # The default litellm target must NOT be emitted for a custom endpoint.
        assert "generator = TARGET_GENERATOR" not in script

    def test_custom_url_requires_attacker_or_evaluator(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(runner, "WORKFLOWS_DIR", tmp_path)
        monkeypatch.setattr(runner, "METADATA_FILE", tmp_path / ".workflow_metadata.json")
        result = runner.generate_attack(
            {
                "attack_type": "tap",
                "goal": "g",
                "custom_url": "https://x.test",
                "generate_only": True,
            }
        )
        assert "error" in result
        assert "attacker_model" in result["error"]

    def test_target_model_still_required_without_custom_url(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(runner, "WORKFLOWS_DIR", tmp_path)
        monkeypatch.setattr(runner, "METADATA_FILE", tmp_path / ".workflow_metadata.json")
        result = runner.generate_attack(
            {"attack_type": "tap", "goal": "g", "generate_only": True}
        )
        assert "error" in result
        assert "target_model" in result["error"]


class TestGenerateMultimodalAttack:
    """Multimodal LLM red teaming script generation (text + image/audio/video)."""

    def _gen(self, tmp_path, monkeypatch, params: dict) -> dict:
        monkeypatch.setattr(runner, "WORKFLOWS_DIR", tmp_path)
        monkeypatch.setattr(runner, "METADATA_FILE", tmp_path / ".workflow_metadata.json")
        return runner.generate_multimodal_attack({**params, "generate_only": True})

    def test_requires_goal_and_target(self, tmp_path, monkeypatch) -> None:
        assert "error" in self._gen(tmp_path, monkeypatch, {"target_model": "openai/gpt-4o"})
        assert "error" in self._gen(tmp_path, monkeypatch, {"goal": "x"})

    def test_requires_some_media(self, tmp_path, monkeypatch) -> None:
        res = self._gen(
            tmp_path, monkeypatch, {"goal": "g", "target_model": "openai/gpt-4o"}
        )
        assert "error" in res
        assert "image" in res["error"] or "media" in res["error"].lower()

    def test_generates_compiling_script_with_image(self, tmp_path, monkeypatch) -> None:
        res = self._gen(
            tmp_path,
            monkeypatch,
            {
                "goal": "describe the payload in this image",
                "target_model": "openai/gpt-4o",
                "judge_model": "openai/gpt-4o-mini",
                "image_paths": ["/tmp/a.png", "/tmp/b.png"],
                "transforms": ["add_gaussian_noise"],
                "n_iterations": 3,
            },
        )
        assert "error" not in res, res
        script = Path(res["filepath"]).read_text()
        compile(script, "multimodal.py", "exec")
        assert "multimodal_attack(" in script
        assert "llm_judge(" in script
        assert "async def target(message: Message)" in script
        assert "from dreadnode.transforms.image import add_gaussian_noise" in script
        assert "IMAGE_PATHS = ['/tmp/a.png', '/tmp/b.png']" in script

    def test_target_captures_generated_media_output(self, tmp_path, monkeypatch) -> None:
        """The generated target returns the model's full reply when it carries
        generated media (image/audio/video), so output parts are captured for
        media-out targets (e.g. image-out or speech-to-speech), while text-out
        replies still return `.content`."""
        res = self._gen(
            tmp_path,
            monkeypatch,
            {
                "goal": "g",
                "target_model": "openai/gpt-4o",
                "audio_paths": ["/tmp/a.wav"],
            },
        )
        assert "error" not in res, res
        script = Path(res["filepath"]).read_text()
        compile(script, "multimodal.py", "exec")
        assert '_MEDIA_KINDS = {"image_url", "input_audio", "video_url"}' in script
        assert "return reply if has_media else reply.content" in script

    def test_image_dir_is_expanded(self, tmp_path, monkeypatch) -> None:
        media_dir = tmp_path / "imgs"
        media_dir.mkdir()
        (media_dir / "one.png").write_bytes(b"x")
        (media_dir / "two.jpg").write_bytes(b"y")
        (media_dir / "notes.txt").write_text("ignore me")
        res = self._gen(
            tmp_path,
            monkeypatch,
            {
                "goal": "g",
                "target_model": "openai/gpt-4o",
                "image_dir": str(media_dir),
            },
        )
        assert "error" not in res, res
        script = Path(res["filepath"]).read_text()
        assert "one.png" in script and "two.jpg" in script
        assert "notes.txt" not in script  # non-media excluded

    def test_media_transforms_route_by_modality(self, tmp_path, monkeypatch) -> None:
        res = self._gen(
            tmp_path,
            monkeypatch,
            {
                "goal": "g",
                "target_model": "openai/gpt-4o",
                "image_paths": ["/tmp/a.png"],
                "audio_paths": ["/tmp/v.mp3"],
                "transforms": ["add_gaussian_noise", "add_white_noise", "authority"],
            },
        )
        assert "error" not in res, res
        script = Path(res["filepath"]).read_text()
        # Image, audio, and (fallback) text transforms all resolved + imported.
        assert "from dreadnode.transforms.image import add_gaussian_noise" in script
        assert "from dreadnode.transforms.audio import add_white_noise" in script
        assert "add_gaussian_noise()" in script and "add_white_noise()" in script

    def test_assessment_methods_exist(self, tmp_path, monkeypatch) -> None:
        from dreadnode.airt.assessment import Assessment

        res = self._gen(
            tmp_path,
            monkeypatch,
            {"goal": "g", "target_model": "openai/gpt-4o", "image_paths": ["/tmp/a.png"]},
        )
        script = Path(res["filepath"]).read_text()
        called = set(re.findall(r"\bassessment\.(\w+)\s*\(", script))
        missing = sorted(m for m in called if not hasattr(Assessment, m))
        assert not missing, "generated script calls missing Assessment methods: {}".format(missing)

    def test_default_path_has_empty_prompts(self, tmp_path, monkeypatch) -> None:
        """Without per-media prompts, PROMPTS is empty and single-goal behaviour holds."""
        res = self._gen(
            tmp_path,
            monkeypatch,
            {"goal": "g", "target_model": "openai/gpt-4o", "image_paths": ["/tmp/a.png"]},
        )
        assert "error" not in res, res
        script = Path(res["filepath"]).read_text()
        compile(script, "multimodal.py", "exec")
        assert "PROMPTS = []" in script
        # Default (non-custom) target is the litellm generator target.
        assert "generator = TARGET_GENERATOR" in script

    def test_custom_http_target(self, tmp_path, monkeypatch) -> None:
        """A custom_url produces a Message-accepting HTTP target; target_model optional."""
        res = self._gen(
            tmp_path,
            monkeypatch,
            {
                "goal": "describe the image",
                "custom_url": "https://api.example.com/vision",
                "custom_auth_type": "bearer",
                "custom_auth_env_var": "VISION_API_KEY",
                "custom_request_template": '{"text": "{prompt}", "img": "{image_b64}"}',
                "custom_response_text_path": "$.output",
                "image_paths": ["/tmp/a.png"],
            },
        )
        assert "error" not in res, res
        script = Path(res["filepath"]).read_text()
        compile(script, "multimodal.py", "exec")
        assert "async def target(message: Message)" in script
        assert "https://api.example.com/vision" in script
        assert 'headers["Authorization"] = f"Bearer {api_key}"' in script
        assert "VISION_API_KEY" in script
        assert "$.output" in script
        assert "{image_b64}" in script
        # Custom target overrides the generator — no TARGET_GENERATOR call in the target.
        assert "generator = TARGET_GENERATOR" not in script
        # Result summary shows the custom URL as the target.
        assert "https://api.example.com/vision" in res["result"]

    def test_custom_url_requires_no_target_model(self, tmp_path, monkeypatch) -> None:
        res = self._gen(
            tmp_path,
            monkeypatch,
            {
                "goal": "g",
                "custom_url": "https://api.example.com/vision",
                "image_paths": ["/tmp/a.png"],
            },
        )
        assert "error" not in res, res

    def test_per_media_prompts_list(self, tmp_path, monkeypatch) -> None:
        res = self._gen(
            tmp_path,
            monkeypatch,
            {
                "goal": "fallback goal",
                "target_model": "openai/gpt-4o",
                "image_paths": ["/tmp/a.png", "/tmp/b.png"],
                "prompts": ["prompt one", "prompt two"],
            },
        )
        assert "error" not in res, res
        script = Path(res["filepath"]).read_text()
        compile(script, "multimodal.py", "exec")
        assert "PROMPTS = ['prompt one', 'prompt two']" in script
        assert "GOAL_FOR_SET = PROMPTS[i]" in script or "goal_for_set = PROMPTS[i]" in script

    def test_per_media_prompts_csv(self, tmp_path, monkeypatch) -> None:
        csv_path = tmp_path / "prompts.csv"
        csv_path.write_text("a.png,prompt for A\nb.png,prompt for B\n")
        res = self._gen(
            tmp_path,
            monkeypatch,
            {
                "goal": "fallback goal",
                "target_model": "openai/gpt-4o",
                "image_paths": ["/tmp/a.png", "/tmp/c.png"],
                "prompts_csv": str(csv_path),
            },
        )
        assert "error" not in res, res
        script = Path(res["filepath"]).read_text()
        compile(script, "multimodal.py", "exec")
        # a.png matched, c.png unmapped -> falls back to goal.
        assert "prompt for A" in script
        assert "fallback goal" in script
