"""Attack generation for AI red team assessments.

Thin @tool wrappers around the attack_runner code generator.
Generates and auto-executes Python workflow scripts using the
Dreadnode AIRT SDK.

The attack_runner (scripts/attack_runner.py) is a 2500+ line code
generator that produces async Python scripts. These wrappers call
it via subprocess with JSON stdin/stdout dispatch.
"""

from __future__ import annotations

import json
import subprocess
import sys
import typing as t
from pathlib import Path

# Load the shared safe_tool wrapper by file path. Capability tool files are
# loaded as flat modules (no parent package), so relative imports do not work.
import importlib.util as _ilu
from pathlib import Path as _Path
_errors_path = _Path(__file__).resolve().parent / "errors.py"
_spec = _ilu.spec_from_file_location("airt_tools_errors", _errors_path)
_errors_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_errors_mod)
safe_tool = _errors_mod.safe_tool
from dreadnode.app.env import resolve_python_executable

_RUNNER_SCRIPT = Path(__file__).parent.parent / "scripts" / "attack_runner.py"
_MANIFEST_SCRIPT = Path(__file__).parent.parent / "scripts" / "media_manifest.py"
_MEDIA_GENERATOR_SCRIPT = Path(__file__).parent.parent / "scripts" / "media_generator.py"


def _call_runner(name: str, params: dict) -> str:
    """Call attack_runner.py via subprocess with JSON dispatch."""
    payload = json.dumps({"name": name, "parameters": params})
    try:
        python_executable = resolve_python_executable()
        print(f"[INFO] Executing attack runner with Python: {python_executable}", file=sys.stderr)
        result = subprocess.run(
            [python_executable, str(_RUNNER_SCRIPT)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=3660,  # 61min: runner has 60min internal timeout + overhead
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if output:
                # Runner may print error JSON even on non-zero exit
                try:
                    data = json.loads(output)
                    if "error" in data:
                        return f"Error: {data['error']}"
                except json.JSONDecodeError:
                    pass
            return f"Error: Runner failed (code {result.returncode}): {stderr[:2000]}"

        try:
            data = json.loads(output)
            if "error" in data:
                return f"Error: {data['error']}"
            return data.get("result", output)
        except json.JSONDecodeError:
            return output[:50_000]
    except subprocess.TimeoutExpired:
        return "Error: Attack generation timed out (660s)."
    except FileNotFoundError:
        return f"Error: Runner script not found at {_RUNNER_SCRIPT}"
    except Exception as e:
        return f"Error: {e}"


@safe_tool
def generate_attack(
    attack_type: t.Annotated[
        str,
        "Attack type(s), comma-separated. Options: tap, pair, crescendo, goat, "
        "prompt, rainbow, gptfuzzer (or fuzzer), autodan (or autodan_turbo), "
        "renellm, beast, drattack, inception (or deep_inception). "
        "Use comma-separated for campaigns: 'tap,goat,crescendo'",
    ],
    goal: t.Annotated[str, "The attack goal/objective"],
    target_model: t.Annotated[
        str,
        "Target LLM model. Aliases: gpt-4o, gpt-4.1, claude, claude-opus, claude-haiku, "
        "gemini, groq, groq scout, groq 70b, mistral, ollama, deepseek — "
        "or full litellm path (e.g., openai/gpt-4o, groq/meta-llama/llama-4-scout-17b-16e-instruct)",
    ],
    attacker_model: t.Annotated[str, "Attacker LLM for generating prompts"] = "",
    evaluator_model: t.Annotated[str, "Judge LLM for scoring"] = "",
    transform_model: t.Annotated[str, "LLM for transform operations"] = "",
    transforms: t.Annotated[
        list[str] | None,
        "Transform names to apply (e.g., ['base64', 'caesar(5)', 'role_play_wrapper']). "
        "200+ available: encoding (base64, hex, leetspeak, morse, braille), "
        "cipher (rot13, atbash, caesar), persuasion (authority_appeal, emotional_appeal), "
        "stylistic (ascii_art, role_play_wrapper), guardrail_bypass (payload_split, emoji_smuggle), "
        "system_prompt_extraction (direct_extraction, boundary_probe), "
        "reasoning_attacks (reasoning_hijack, cot_backdoor), "
        "perturbation (zalgo, unicode_confusable, simulate_typos), "
        "injection (skeleton_key_framing, many_shot_examples), "
        "advanced_jailbreak, mcp_attacks, multi_agent_attacks, exfiltration, and more.",
    ] = None,
    compare_transforms: t.Annotated[bool, "If True with transforms, creates N+1 comparison study"] = False,
    scorers: t.Annotated[list[str] | None, "Custom scorer names"] = None,
    n_iterations: t.Annotated[int | None, "Iterations per attack"] = None,
    goal_category: t.Annotated[str, "Goal category for scoring"] = "",
    assessment_name: t.Annotated[str, "Human-readable assessment name"] = "",
    custom_url: t.Annotated[
        str,
        "Target a custom HTTP endpoint instead of a litellm model. When set, "
        "target_model is optional and the attacker/judge use real models.",
    ] = "",
    custom_auth_type: t.Annotated[str, "Auth scheme for custom_url: 'none', 'bearer', or 'api_key'"] = "none",
    custom_auth_env_var: t.Annotated[str, "Env var holding the custom endpoint credential"] = "TARGET_API_KEY",
    custom_request_template: t.Annotated[str, "JSON request template with a {prompt} placeholder"] = "",
    custom_response_text_path: t.Annotated[str, "JSONPath to the response text (e.g. $.response)"] = "",
) -> str:
    """Generate, save, and execute a single attack workflow.

    Supports 12+ attack types, 200+ transforms (encoding, cipher,
    persuasion, agentic, MCP, multi-agent, exfiltration, and more),
    and configurable scorers. The generated Python script is saved to
    ~/workspace/airt/workflows/ and auto-executed.

    Multiple attacks (comma-separated) create a campaign. Adding
    compare_transforms=True with transforms creates an N+1 study.
    """
    params: dict[str, t.Any] = {
        "attack_type": attack_type,
        "goal": goal,
        "target_model": target_model,
    }
    if attacker_model:
        params["attacker_model"] = attacker_model
    if evaluator_model:
        params["evaluator_model"] = evaluator_model
    if transform_model:
        params["transform_model"] = transform_model
    if transforms:
        params["transforms"] = transforms
    if compare_transforms:
        params["compare_transforms"] = True
    if scorers:
        params["scorers"] = scorers
    if n_iterations is not None:
        params["n_iterations"] = n_iterations
    if goal_category:
        params["goal_category"] = goal_category
    if assessment_name:
        params["assessment_name"] = assessment_name
    if custom_url:
        params["custom_url"] = custom_url
    if custom_auth_type:
        params["custom_auth_type"] = custom_auth_type
    if custom_auth_env_var:
        params["custom_auth_env_var"] = custom_auth_env_var
    if custom_request_template:
        params["custom_request_template"] = custom_request_template
    if custom_response_text_path:
        params["custom_response_text_path"] = custom_response_text_path

    return _call_runner("generate_attack", params)


@safe_tool
def generate_category_attack(
    attacks: t.Annotated[
        list[str] | str,
        "Attack type(s): a list like ['tap', 'goat'] or a comma-separated string like 'tap,goat'",
    ],
    target_model: t.Annotated[str, "Target LLM model"],
    categories: t.Annotated[
        list[str] | None,
        "Sub-category slugs (e.g., ['cybersecurity', 'credential_extraction']) " "or ['all'] for all categories",
    ] = None,
    goal_ids: t.Annotated[list[str] | None, "Specific goal IDs (overrides categories)"] = None,
    goals_per_category: t.Annotated[int | None, "Max goals to sample per category"] = None,
    attacker_model: t.Annotated[str, "Attacker LLM"] = "",
    evaluator_model: t.Annotated[str, "Judge LLM"] = "",
    transform_model: t.Annotated[str, "Transform LLM"] = "",
    transforms: t.Annotated[list[str] | None, "Transform names to apply"] = None,
    n_iterations: t.Annotated[int | None, "Iterations per attack"] = None,
    assessment_name: t.Annotated[str, "Assessment name"] = "",
) -> str:
    """Generate a multi-goal attack across bundled harm categories.

    Sweeps attacks across entire goal sub-categories from the bundled
    dataset (260 goals across 25 sub-categories in safety/security/agentic
    tiers). Goal text is embedded in the generated script — never
    returned to the agent.

    Categories: cybersecurity, weapons, financial_crimes, identity_theft,
    violence, hate_speech, misinformation, self_harm, bias_fairness,
    content_policy, credential_extraction, pii_extraction, system_prompt_leak,
    tool_misuse, refusal_bypass, agentic_tool_misuse, agentic_data_exfil,
    agentic_privilege_escalation, agentic_goal_hijacking,
    agentic_prompt_extraction, agentic_memory_poisoning,
    agentic_code_execution, agentic_supply_chain, agentic_cascading_failure,
    agentic_trust_exploitation.
    """
    params: dict[str, t.Any] = {
        "attacks": attacks,
        "target_model": target_model,
    }
    if categories:
        params["categories"] = categories
    if goal_ids:
        params["goal_ids"] = goal_ids
    if goals_per_category is not None:
        params["goals_per_category"] = goals_per_category
    if attacker_model:
        params["attacker_model"] = attacker_model
    if evaluator_model:
        params["evaluator_model"] = evaluator_model
    if transform_model:
        params["transform_model"] = transform_model
    if transforms:
        params["transforms"] = transforms
    if n_iterations is not None:
        params["n_iterations"] = n_iterations
    if assessment_name:
        params["assessment_name"] = assessment_name

    return _call_runner("generate_category_attack", params)


@safe_tool
def generate_agentic_attack(
    goal: t.Annotated[str, "Attack goal"],
    agent_url: t.Annotated[str, "HTTP endpoint of the target agent"],
    attacker_model: t.Annotated[str, "LLM generating attack prompts"],
    attack_type: t.Annotated[str, "Attack type (default: tap)"] = "tap",
    agent_auth_type: t.Annotated[str, "Auth scheme: 'none', 'bearer', or 'api_key'"] = "none",
    agent_auth_env_var: t.Annotated[str, "Env var name for auth credential"] = "AGENT_API_KEY",
    agent_request_template: t.Annotated[str, "JSON request template with {prompt} placeholder"] = "",
    agent_response_text_path: t.Annotated[str, "JSONPath to extract response text"] = "",
    agent_response_tool_calls_path: t.Annotated[str, "JSONPath for tool calls in response"] = "",
    agent_dangerous_tools: t.Annotated[list[str] | None, "Dangerous tool names to target for agentic scoring"] = None,
    agent_safe_tools: t.Annotated[list[str] | None, "Safe tool whitelist for agentic scoring"] = None,
    agent_preset: t.Annotated[str, "Preset: 'openai_assistants', 'anthropic', or 'custom'"] = "custom",
    evaluator_model: t.Annotated[str, "Judge LLM"] = "",
    transform_model: t.Annotated[str, "Transform LLM"] = "",
    transforms: t.Annotated[list[str] | None, "Transforms to apply"] = None,
    scorers: t.Annotated[list[str] | None, "Custom scorers"] = None,
    n_iterations: t.Annotated[int | None, "Iterations"] = None,
    goal_category: t.Annotated[str, "Goal category"] = "",
    assessment_name: t.Annotated[str, "Assessment name"] = "",
) -> str:
    """Generate an attack targeting an external agent HTTP API.

    Creates a workflow that attacks a remote agent endpoint via HTTP
    instead of a direct LLM. Supports OpenAI, Anthropic, and custom
    API formats with configurable auth and response parsing.

    Presets auto-configure request/response templates:
    - openai_assistants: OpenAI Chat Completions format
    - anthropic: Anthropic Messages API format
    - custom: Provide your own request_template and response_text_path
    """
    params: dict[str, t.Any] = {
        "goal": goal,
        "agent_url": agent_url,
        "attacker_model": attacker_model,
        "attack_type": attack_type,
        "agent_auth_type": agent_auth_type,
        "agent_auth_env_var": agent_auth_env_var,
        "agent_preset": agent_preset,
    }
    if agent_request_template:
        params["agent_request_template"] = agent_request_template
    if agent_response_text_path:
        params["agent_response_text_path"] = agent_response_text_path
    if agent_response_tool_calls_path:
        params["agent_response_tool_calls_path"] = agent_response_tool_calls_path
    if agent_dangerous_tools:
        params["agent_dangerous_tools"] = agent_dangerous_tools
    if agent_safe_tools:
        params["agent_safe_tools"] = agent_safe_tools
    if evaluator_model:
        params["evaluator_model"] = evaluator_model
    if transform_model:
        params["transform_model"] = transform_model
    if transforms:
        params["transforms"] = transforms
    if scorers:
        params["scorers"] = scorers
    if n_iterations is not None:
        params["n_iterations"] = n_iterations
    if goal_category:
        params["goal_category"] = goal_category
    if assessment_name:
        params["assessment_name"] = assessment_name

    return _call_runner("generate_agentic_attack", params)


@safe_tool
def generate_atlas_attack(
    agent_url: t.Annotated[str, "HTTP /attack endpoint of the deployed multi-agent environment"],
    attacker_model: t.Annotated[str, "LLM that generates adversarial prompts (e.g. groq scout, gpt-4.1)"],
    objectives: t.Annotated[
        list[dict] | None,
        "Campaign objectives, each {id, category, goal}. Categories: TW, EA, TB, "
        "CB, DE, GH, RP, MP. Defaults to one objective per category if omitted.",
    ] = None,
    scenario_name: t.Annotated[
        str, "Scenario for scenario-specific probes: finops, devsecops, healthcare, soc"
    ] = "",
    total_budget: t.Annotated[int, "Total attack episodes across the campaign"] = 64,
    evaluator_model: t.Annotated[str, "Judge LLM (defaults to attacker_model)"] = "",
    agent_auth_type: t.Annotated[str, "Auth scheme: 'none', 'bearer', or 'api_key'"] = "none",
    agent_auth_env_var: t.Annotated[str, "Env var holding the auth credential"] = "AGENT_API_KEY",
    goal_category: t.Annotated[str, "Default goal category for span labeling"] = "",
    assessment_name: t.Annotated[str, "Assessment name"] = "",
) -> str:
    """Generate an ATLAS multi-agent red-teaming campaign workflow.

    ATLAS (Adaptive Topology-Level Attack Synthesis, ICML AI-WILD 2026) treats
    the target as a topology of agents and runs Probe -> Route -> Learn over a
    budget of episodes, driving GOAT/Crescendo through three injection surfaces
    (direct / tool_output / peer_message) and gating success on *real tool
    execution* (not just verbal compliance). Point it at a deployed multi-agent
    environment that exposes POST /attack {prompt, surface, injection} ->
    {content, tool_calls, ...}.
    """
    params: dict[str, t.Any] = {
        "agent_url": agent_url,
        "attacker_model": attacker_model,
        "scenario_name": scenario_name,
        "total_budget": total_budget,
        "agent_auth_type": agent_auth_type,
        "agent_auth_env_var": agent_auth_env_var,
    }
    if objectives:
        params["objectives"] = objectives
    if evaluator_model:
        params["evaluator_model"] = evaluator_model
    if goal_category:
        params["goal_category"] = goal_category
    if assessment_name:
        params["assessment_name"] = assessment_name

    return _call_runner("generate_atlas_attack", params)


@safe_tool
def generate_image_attack(
    attack_type: t.Annotated[
        str,
        "ML adversarial attack type: hopskipjump (or hsj), simba, nes, zoo. "
        "These are black-box attacks that perturb inputs to fool classifiers.",
    ] = "hopskipjump",
    input_type: t.Annotated[
        str,
        "Input data type: 'image' (load from URL, perturb pixels) or " "'tabular' (feature array + API endpoint)",
    ] = "image",
    # --- Image-specific params ---
    image_url: t.Annotated[
        str,
        "URL of the source image (for input_type='image'). " "Can also be a local file path.",
    ] = "",
    # --- Tabular-specific params ---
    features: t.Annotated[
        list[float] | None,
        "Source feature array (for input_type='tabular'), e.g. [0.1, -0.5, ...]",
    ] = None,
    api_url: t.Annotated[
        str,
        "Target classifier API URL (for input_type='tabular'). "
        "Expects POST with JSON body {instances: [{features: [...]}]} "
        "and returns {predictions: [{class: int, confidence: float}]}",
    ] = "",
    api_key: t.Annotated[str, "API key for x-api-key header (optional)"] = "",
    target_class: t.Annotated[int, "Class to flip TO (adversarial target), e.g. 1 for fraud"] = 1,
    original_class: t.Annotated[
        int | str,
        "Original class of the source input, e.g. 0 for legitimate",
    ] = 0,
    # --- Common params ---
    norm: t.Annotated[
        str,
        "Distance norm for perturbation: 'l1', 'l2', or 'linf'",
    ] = "l2",
    max_iterations: t.Annotated[int | None, "Max attack iterations"] = None,
    goal: t.Annotated[str, "Attack goal description"] = "",
    assessment_name: t.Annotated[str, "Human-readable assessment name"] = "",
) -> str:
    """Generate and execute an adversarial ML attack workflow.

    Supports both image and tabular (numeric feature array) inputs.
    For image attacks, provide image_url. For tabular attacks, provide
    features array + api_url (+ optional api_key).

    Uses the Dreadnode SDK's black-box adversarial samplers (HopSkipJump,
    SimBA, NES, ZOO) integrated with the Study pipeline for full OTEL
    tracing and platform visibility. Results appear in the platform
    under AI Red Teaming with adversarial ML metrics.

    Examples:
      # Tabular: attack a fraud detection API
      generate_image_attack(
          attack_type="hopskipjump",
          input_type="tabular",
          features=[0.0, -1.36, ...],  # 30 feature values
          api_url="https://my-api.com/predict",
          api_key="...",
          target_class=1,
          original_class=0,
      )

      # Image: attack an image classifier
      generate_image_attack(
          attack_type="simba",
          input_type="image",
          image_url="https://example.com/cat.png",
      )
    """
    params: dict[str, t.Any] = {
        "attack_type": attack_type,
        "input_type": input_type,
    }
    if image_url:
        params["image_url"] = image_url
    if features:
        params["features"] = features
    if api_url:
        params["api_url"] = api_url
    if api_key:
        params["api_key"] = api_key
    if target_class != 1:
        params["target_class"] = target_class
    if original_class not in (0, "0", ""):
        params["original_class"] = original_class
    if norm != "l2":
        params["norm"] = norm
    if max_iterations is not None:
        params["max_iterations"] = max_iterations
    if goal:
        params["goal"] = goal
    if assessment_name:
        params["assessment_name"] = assessment_name

    return _call_runner("generate_image_attack", params)


@safe_tool
def generate_extraction_attack(
    attack_type: t.Annotated[
        str,
        "Model-extraction attack: equation_solving (exact for linear models), "
        "jacobian, copycat (hard-label), or knockoff (soft-label, highest fidelity).",
    ] = "knockoff",
    api_url: t.Annotated[str, "Target classifier predict endpoint (POST)."] = "",
    api_key: t.Annotated[str, "API key for the x-api-key header (optional)."] = "",
    pool_url: t.Annotated[
        str, "GET endpoint returning {inputs: [...]} — the unlabeled query pool."
    ] = "",
    query_pool: t.Annotated[
        list | None, "Inline query pool (used if pool_url is not given)."
    ] = None,
    request_template: t.Annotated[
        str, "Request body with a single {input} placeholder."
    ] = '{"features": {input}}',
    probabilities_path: t.Annotated[str, "JSONPath to the probability vector."] = "$.probabilities",
    input_format: t.Annotated[str, "json_array | image_b64 | text."] = "json_array",
    num_classes: t.Annotated[int, "Number of classes."] = 2,
    query_budget: t.Annotated[int, "Max target queries."] = 1000,
    modality: t.Annotated[str, "tabular | image | text."] = "tabular",
    assessment_name: t.Annotated[str, "Human-readable assessment name."] = "",
) -> str:
    """Steal a classifier's decision boundary via black-box queries.

    Trains a surrogate on the target's predictions and reports fidelity/agreement.
    Provide api_url and a query pool (pool_url or query_pool). Results appear in the
    platform under AI Red Teaming with model-extraction metrics.
    """
    params: dict[str, t.Any] = {
        "attack_type": attack_type,
        "api_url": api_url,
        "num_classes": num_classes,
        "query_budget": query_budget,
        "modality": modality,
        "request_template": request_template,
        "probabilities_path": probabilities_path,
        "input_format": input_format,
    }
    if api_key:
        params["api_key"] = api_key
    if pool_url:
        params["pool_url"] = pool_url
    if query_pool:
        params["query_pool"] = query_pool
    if assessment_name:
        params["assessment_name"] = assessment_name
    return _call_runner("generate_extraction_attack", params)


@safe_tool
def generate_membership_attack(
    attack_type: t.Annotated[
        str, "Membership-inference attack: threshold (confidence/loss) or label_only."
    ] = "threshold",
    api_url: t.Annotated[str, "Target classifier predict endpoint (POST)."] = "",
    api_key: t.Annotated[str, "API key for the x-api-key header (optional)."] = "",
    members_url: t.Annotated[
        str, "GET endpoint returning {records: [...], labels: [...]} for training members."
    ] = "",
    nonmembers_url: t.Annotated[str, "GET endpoint for held-out non-members."] = "",
    members: t.Annotated[list | None, "Inline member records (if no members_url)."] = None,
    nonmembers: t.Annotated[list | None, "Inline non-member records (if no nonmembers_url)."] = None,
    request_template: t.Annotated[
        str, "Request body with a single {input} placeholder."
    ] = '{"features": {input}}',
    probabilities_path: t.Annotated[str, "JSONPath to the probability vector."] = "$.probabilities",
    input_format: t.Annotated[str, "json_array | image_b64 | text."] = "json_array",
    num_classes: t.Annotated[int, "Number of classes."] = 2,
    signal: t.Annotated[str, "Threshold signal: confidence | entropy | loss."] = "confidence",
    modality: t.Annotated[str, "tabular | image | text."] = "tabular",
    assessment_name: t.Annotated[str, "Human-readable assessment name."] = "",
) -> str:
    """Determine whether records were in the target's training set.

    Reports AUC, TPR@1%FPR, advantage, and count re-identified. Provide api_url and
    member/non-member records (via *_url or inline). Results appear in the platform
    under AI Red Teaming with membership-inference metrics.
    """
    params: dict[str, t.Any] = {
        "attack_type": attack_type,
        "api_url": api_url,
        "num_classes": num_classes,
        "signal": signal,
        "modality": modality,
        "request_template": request_template,
        "probabilities_path": probabilities_path,
        "input_format": input_format,
    }
    if api_key:
        params["api_key"] = api_key
    if members_url:
        params["members_url"] = members_url
    if nonmembers_url:
        params["nonmembers_url"] = nonmembers_url
    if members:
        params["members"] = members
    if nonmembers:
        params["nonmembers"] = nonmembers
    if assessment_name:
        params["assessment_name"] = assessment_name
    return _call_runner("generate_membership_attack", params)


@safe_tool
def generate_multimodal_attack(
    goal: t.Annotated[
        str,
        "The text prompt to send alongside the media (the harmful objective).",
    ],
    target_model: t.Annotated[
        str,
        "A vision/audio/video-capable target model, e.g. openai/gpt-4o, "
        "dn/claude-sonnet-4-6, anthropic/claude-3-5-sonnet.",
    ],
    image_paths: t.Annotated[
        list[str] | None,
        "Explicit image file paths to probe with (one attack per file).",
    ] = None,
    image_dir: t.Annotated[
        str,
        "Directory of images — every image file inside is used (recursively).",
    ] = "",
    audio_paths: t.Annotated[list[str] | None, "Explicit audio file paths."] = None,
    audio_dir: t.Annotated[str, "Directory of audio files."] = "",
    video_paths: t.Annotated[list[str] | None, "Explicit video file paths."] = None,
    video_dir: t.Annotated[str, "Directory of video files."] = "",
    transforms: t.Annotated[
        list[str] | None,
        "Modality-typed transforms applied per attack. Image: add_gaussian_noise, "
        "add_text_overlay('PWNED'), image_steganography, blur, rotate, jpeg_compression, "
        "overlay_emoji, solarize, posterize, invert_colors, adversarial_patch('IGNORE'), "
        "shuffle_pixels, color_jitter. Audio: add_white_noise, pitch_shift, time_stretch, "
        "change_speed, add_reverb, add_echo, apply_band_pass_filter, ultrasonic_shift, "
        "spectral_inversion, bit_crush, add_tone, audio_steganography('PWNED'). Video: "
        "video_frame_inject, subliminal_frame, frame_brightness_flicker, temporal_shuffle, "
        "frame_dropout, keyframe_replace('INJECT'), per_frame_text_scroll('secret'). Text "
        "transforms also work (applied to the prompt). The SDK routes each by modality.",
    ] = None,
    judge_model: t.Annotated[
        str,
        "Model used to score jailbreak success (defaults to the target model).",
    ] = "",
    goal_category: t.Annotated[
        str,
        "Harm category slug, e.g. jailbreak_general, harmful_content, refusal_bypass.",
    ] = "jailbreak_general",
    n_iterations: t.Annotated[int | None, "Iterations per media set (default 4)."] = None,
    assessment_name: t.Annotated[str, "Human-readable assessment name."] = "",
    prompts: t.Annotated[
        list[str] | None,
        "Per-media prompts aligned with media order (image files, then audio, then "
        "video). Each media set uses its own prompt; falls back to `goal` when absent.",
    ] = None,
    prompts_csv: t.Annotated[
        str,
        "Path to a CSV of `media_filename,prompt` rows. Each media file is paired with "
        "its prompt (matched by basename); unmapped media fall back to `goal`.",
    ] = "",
    prompt_matrix: t.Annotated[
        list[str] | None,
        "Cross-product text prompts: run EVERY prompt against EVERY media item. With N "
        "prompts here and M media files, this produces N*M trials (e.g. 4 prompts x 5 "
        "images = 20). Any transforms are applied to every combination. Distinct from "
        "`prompts`/`prompts_csv`, which pair one prompt per media (1:1).",
    ] = None,
    custom_url: t.Annotated[
        str,
        "Target a custom multimodal HTTP endpoint instead of a litellm model. When "
        "set, target_model is optional; the endpoint receives the text + base64 media.",
    ] = "",
    custom_auth_type: t.Annotated[
        str,
        "Auth scheme for custom_url: 'none', 'bearer', 'api_key', or 'aws_sigv4' "
        "(SigV4-signed, e.g. an Amazon SageMaker /invocations endpoint — set "
        "custom_region and custom_service).",
    ] = "none",
    custom_auth_env_var: t.Annotated[str, "Env var holding the custom endpoint credential"] = "TARGET_API_KEY",
    custom_request_template: t.Annotated[
        str,
        "JSON request template with {prompt}/{image_b64}/{audio_b64}/{video_b64} placeholders.",
    ] = "",
    custom_response_text_path: t.Annotated[str, "JSONPath to the response text (e.g. $.response)"] = "",
    custom_transport: t.Annotated[
        str,
        "Target transport: 'http' (default) or 'streaming' for a realtime speech-to-speech "
        "target. With 'streaming', set custom_protocol (no custom_url needed).",
    ] = "http",
    custom_protocol: t.Annotated[
        str,
        "Streaming protocol when custom_transport='streaming'. Supported: 'nova_sonic' "
        "(Amazon Nova Sonic S2S over Bedrock). The input audio is spoken to the model and "
        "its spoken reply (audio + transcript) is scored.",
    ] = "",
    custom_region: t.Annotated[
        str, "AWS region for a streaming (Nova Sonic) or aws_sigv4 target (default us-east-1)."
    ] = "",
    custom_service: t.Annotated[
        str, "AWS service for an aws_sigv4 HTTP target (default 'sagemaker')."
    ] = "",
    custom_request_format: t.Annotated[
        str,
        "Request body encoding for custom_url: 'json' (default, renders the request "
        "template) or 'audio_bytes' (posts the raw audio file with custom_audio_content_type "
        "— for SageMaker ASR/audio endpoints like Whisper that take an audio body, not JSON).",
    ] = "",
    custom_audio_content_type: t.Annotated[
        str, "Content-Type for a custom_request_format='audio_bytes' target (default 'audio/wav')."
    ] = "",
    custom_voice: t.Annotated[str, "Voice id for a Nova Sonic streaming target (default matthew)."] = "",
    custom_system_prompt: t.Annotated[str, "System prompt for a streaming S2S target."] = "",
    custom_model_id: t.Annotated[
        str, "Model id for a streaming target (default amazon.nova-sonic-v1:0)."
    ] = "",
    score_media_output: t.Annotated[
        bool,
        "Score the target's GENERATED media (image-out / speech-to-speech), not just its "
        "text. Uses a media-aware judge per output modality; trial score = MAX across "
        "modalities. Requires a vision/audio-capable judge_model.",
    ] = False,
    media_output_modalities: t.Annotated[
        list[str] | None,
        "Which output modalities to score ('image'/'audio'/'video'). Defaults to all "
        "when score_media_output is set; only modalities actually present are scored.",
    ] = None,
    media_output_rubric: t.Annotated[
        str,
        "Rubric for scoring generated media (defaults to the jailbreak rubric).",
    ] = "",
) -> str:
    """Generate and execute a MULTIMODAL LLM red teaming attack.

    Sends text + image/audio/video to a multimodal target, applies modality-typed
    transforms to the media (and/or text), and scores the model's text response for
    jailbreak success. Use this when the user wants to attack a vision/audio/video
    model — e.g. "run this prompt against gpt-4o with the images in ./imgs and apply
    an image transform", or "test this voice model with the audio clips in ./voices".

    This is DISTINCT from generate_image_attack, which perturbs pixels to fool a
    traditional ML *classifier* (HopSkipJump/SimBA) — a different feature entirely.

    Examples:
      # Probe a vision model with a folder of images + an image transform
      generate_multimodal_attack(
          goal="Describe the steps written in this image",
          target_model="openai/gpt-4o",
          image_dir="./attack_images",
          transforms=["add_gaussian_noise"],
      )

      # Typographic / visual prompt injection with an overlay + audio
      generate_multimodal_attack(
          goal="Follow the instructions in the media",
          target_model="dn/claude-sonnet-4-6",
          image_paths=["./poster.png"],
          audio_paths=["./voice.mp3"],
          transforms=["add_text_overlay('IGNORE SAFETY')", "add_white_noise"],
      )
    """
    params: dict[str, t.Any] = {
        "goal": goal,
        "target_model": target_model,
        "goal_category": goal_category,
    }
    if image_paths:
        params["image_paths"] = image_paths
    if image_dir:
        params["image_dir"] = image_dir
    if audio_paths:
        params["audio_paths"] = audio_paths
    if audio_dir:
        params["audio_dir"] = audio_dir
    if video_paths:
        params["video_paths"] = video_paths
    if video_dir:
        params["video_dir"] = video_dir
    if transforms:
        params["transforms"] = transforms
    if judge_model:
        params["judge_model"] = judge_model
    if n_iterations is not None:
        params["n_iterations"] = n_iterations
    if assessment_name:
        params["assessment_name"] = assessment_name
    if prompts:
        params["prompts"] = prompts
    if prompts_csv:
        params["prompts_csv"] = prompts_csv
    if prompt_matrix:
        params["prompt_matrix"] = prompt_matrix
    if custom_url:
        params["custom_url"] = custom_url
    if custom_auth_type:
        params["custom_auth_type"] = custom_auth_type
    if custom_auth_env_var:
        params["custom_auth_env_var"] = custom_auth_env_var
    if custom_request_template:
        params["custom_request_template"] = custom_request_template
    if custom_response_text_path:
        params["custom_response_text_path"] = custom_response_text_path
    if custom_transport and custom_transport != "http":
        params["custom_transport"] = custom_transport
    if custom_protocol:
        params["custom_protocol"] = custom_protocol
    if custom_region:
        params["custom_region"] = custom_region
    if custom_service:
        params["custom_service"] = custom_service
    if custom_request_format:
        params["custom_request_format"] = custom_request_format
    if custom_audio_content_type:
        params["custom_audio_content_type"] = custom_audio_content_type
    if custom_voice:
        params["custom_voice"] = custom_voice
    if custom_system_prompt:
        params["custom_system_prompt"] = custom_system_prompt
    if custom_model_id:
        params["custom_model_id"] = custom_model_id
    if score_media_output:
        params["score_media_output"] = True
    if media_output_modalities:
        params["media_output_modalities"] = media_output_modalities
    if media_output_rubric:
        params["media_output_rubric"] = media_output_rubric

    return _call_runner("generate_multimodal_attack", params)


@safe_tool
def generate_multimodal_category_attack(
    goal_category: t.Annotated[
        str,
        "Harm sub-category to sweep (e.g. weapons, cybersecurity, harmful_content). "
        "Goals are sampled from the bundled dataset.",
    ],
    goals_per_category: t.Annotated[int, "How many goals to sample from the category (default 5)."] = 5,
    render_from_goals: t.Annotated[
        bool,
        "Auto-render each sampled goal into a typographic injection image (turnkey — no "
        "user media needed). One attack per goal. Use when the user has no media.",
    ] = False,
    target_model: t.Annotated[str, "Vision/audio/video-capable target model."] = "",
    image_dir: t.Annotated[str, "User media: directory of images to pair with the goals."] = "",
    image_paths: t.Annotated[list[str] | None, "User media: explicit image paths."] = None,
    audio_dir: t.Annotated[str, "User media: directory of audio files."] = "",
    audio_paths: t.Annotated[list[str] | None, "User media: explicit audio paths."] = None,
    video_dir: t.Annotated[str, "User media: directory of video files."] = "",
    video_paths: t.Annotated[list[str] | None, "User media: explicit video paths."] = None,
    transforms: t.Annotated[list[str] | None, "Modality-typed transforms to apply."] = None,
    judge_model: t.Annotated[str, "Model used to score jailbreak success."] = "",
    n_iterations: t.Annotated[int | None, "Iterations per media set."] = None,
    score_media_output: t.Annotated[bool, "Also score the target's generated media output."] = False,
    assessment_name: t.Annotated[str, "Human-readable assessment name."] = "",
) -> str:
    """Sweep a MULTIMODAL attack across sampled goals from a harm category.

    A multimodal category sweep needs media. Provide ONE of:
      - `render_from_goals=True` — turnkey: each sampled goal is rendered into a
        typographic prompt-injection image (harmful text in the image, benign framing
        prompt). No user media required.
      - user media (`image_dir`/`image_paths`/audio/video) — each sampled goal is paired
        1:1 with a media file; provide one media per goal you want to test.

    If the user wants a media-input sweep but gives no paths, ASK them for the media
    folder/paths (or offer render_from_goals). You never view the goals or media.
    """
    if not goal_category:
        return "Error: goal_category is required (e.g. weapons, cybersecurity, harmful_content)"
    params: dict[str, t.Any] = {"goal_category": goal_category, "goals_per_category": goals_per_category}
    if render_from_goals:
        params["render_from_goals"] = True
    if target_model:
        params["target_model"] = target_model
    if image_dir:
        params["image_dir"] = image_dir
    if image_paths:
        params["image_paths"] = image_paths
    if audio_dir:
        params["audio_dir"] = audio_dir
    if audio_paths:
        params["audio_paths"] = audio_paths
    if video_dir:
        params["video_dir"] = video_dir
    if video_paths:
        params["video_paths"] = video_paths
    if transforms:
        params["transforms"] = transforms
    if judge_model:
        params["judge_model"] = judge_model
    if n_iterations is not None:
        params["n_iterations"] = n_iterations
    if score_media_output:
        params["score_media_output"] = True
    if assessment_name:
        params["assessment_name"] = assessment_name

    return _call_runner("generate_multimodal_category_attack", params)


@safe_tool
def build_media_manifest(
    directory: t.Annotated[
        str,
        "Directory of media files to inventory (recursively). Use this for "
        '"the images in ./imgs" style requests.',
    ] = "",
    paths: t.Annotated[
        list[str] | None,
        "Explicit media file paths to inventory.",
    ] = None,
) -> str:
    """Inventory a folder/list of media into a reference manifest for planning.

    Returns a compact, byte-free inventory (id, kind, mime, size, image dimensions)
    plus a summary so you can choose modality-typed transforms and pass the
    paths/dir to generate_multimodal_attack — WITHOUT loading raw media into context.
    The media is attack content: never open, view, or reason about what it depicts.
    Plan from the inventory metadata alone (kind/size/dimensions/paths), then hand the
    paths + transforms + models to generate_multimodal_attack, which loads and probes
    the media at runtime inside the workflow.
    """
    params: dict[str, t.Any] = {}
    if directory:
        params["directory"] = directory
    if paths:
        params["paths"] = paths

    payload = json.dumps({"name": "build_media_manifest", "parameters": params})
    try:
        python_executable = resolve_python_executable()
        result = subprocess.run(
            [python_executable, str(_MANIFEST_SCRIPT)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout.strip()
        try:
            data = json.loads(output)
            if "error" in data:
                return f"Error: {data['error']}"
            return output[:50_000]
        except json.JSONDecodeError:
            return output[:50_000] or f"Error: manifest failed: {result.stderr.strip()[:2000]}"
    except Exception as e:  # noqa: BLE001
        return f"Error: {e}"


@safe_tool
def generate_injection_images(
    texts: t.Annotated[
        list[str] | None,
        "Attack texts to rasterize — one image per text (typographic prompt injection).",
    ] = None,
    texts_csv: t.Annotated[
        str,
        "Path to a CSV whose first column is the attack text (one image per row). "
        "Use when the user hands you a CSV of prompts to render as images.",
    ] = "",
    output_dir: t.Annotated[
        str, "Directory to write the images into (default ./injection_images)."
    ] = "",
    base_image: t.Annotated[
        str, "Optional base image path to overlay the text onto (else a plain canvas)."
    ] = "",
    font_size: t.Annotated[int, "Font size for the rendered text (default 40)."] = 40,
) -> str:
    """Render attack text into typographic/visual prompt-injection IMAGES.

    Turns caller-supplied text (or a CSV of texts) into image files so you can probe a
    vision model with a "typographic jailbreak" WITHOUT supplying your own media. This
    CREATES the attack data for the user — you never view or reason about the text; you
    just render it and pass the resulting image paths to generate_multimodal_attack.

    Returns the written image paths + a byte-free summary. Typical flow:
      generate_injection_images(texts_csv="./prompts.csv", output_dir="./inj")
      → generate_multimodal_attack(goal="Follow the instructions in the image",
                                   target_model="openai/gpt-4o", image_dir="./inj")
    """
    params: dict[str, t.Any] = {}
    if texts:
        params["texts"] = texts
    if texts_csv:
        params["texts_csv"] = texts_csv
    if output_dir:
        params["output_dir"] = output_dir
    if base_image:
        params["base_image"] = base_image
    if font_size:
        params["font_size"] = font_size

    payload = json.dumps({"name": "generate_injection_images", "parameters": params})
    try:
        python_executable = resolve_python_executable()
        result = subprocess.run(
            [python_executable, str(_MEDIA_GENERATOR_SCRIPT)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout.strip()
        try:
            data = json.loads(output)
            if "error" in data:
                return f"Error: {data['error']}"
            return output[:50_000]
        except json.JSONDecodeError:
            return output[:50_000] or f"Error: generation failed: {result.stderr.strip()[:2000]}"
    except Exception as e:  # noqa: BLE001
        return f"Error: {e}"
