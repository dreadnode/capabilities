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

from dreadnode.agents.tools import tool
from dreadnode.app.env import resolve_python_executable

_RUNNER_SCRIPT = Path(__file__).parent.parent / "scripts" / "attack_runner.py"


def _call_runner(name: str, params: dict) -> str:
    """Call attack_runner.py via subprocess with JSON dispatch."""
    payload = json.dumps({"name": name, "parameters": params})
    try:
        python_executable = resolve_python_executable()
        print(
            f"[INFO] Executing attack runner with Python: {python_executable}",
            file=sys.stderr,
        )
        result = subprocess.run(
            [python_executable, str(_RUNNER_SCRIPT)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=660,  # 11min: runner has 9min internal timeout + overhead
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


@tool
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
    compare_transforms: t.Annotated[
        bool, "If True with transforms, creates N+1 comparison study"
    ] = False,
    scorers: t.Annotated[list[str] | None, "Custom scorer names"] = None,
    n_iterations: t.Annotated[int | None, "Iterations per attack"] = None,
    goal_category: t.Annotated[str, "Goal category for scoring"] = "",
    assessment_name: t.Annotated[str, "Human-readable assessment name"] = "",
) -> str:
    """Generate, save, and execute a single attack workflow.

    Supports 12+ attack types, 200+ transforms (encoding, cipher,
    persuasion, agentic, MCP, multi-agent, exfiltration, and more),
    and configurable scorers. The generated Python script is saved to
    ~/.dreadnode/airt/[org]/[workspace]/workflows/ and auto-executed.

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

    return _call_runner("generate_attack", params)


@tool
def generate_category_attack(
    attacks: t.Annotated[str, "Attack type(s), comma-separated"],
    target_model: t.Annotated[str, "Target LLM model"],
    categories: t.Annotated[
        list[str] | None,
        "Sub-category slugs (e.g., ['cybersecurity', 'credential_extraction']) "
        "or ['all'] for all categories",
    ] = None,
    goal_ids: t.Annotated[
        list[str] | None, "Specific goal IDs (overrides categories)"
    ] = None,
    goals_per_category: t.Annotated[
        int | None, "Max goals to sample per category"
    ] = None,
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


@tool
def generate_agentic_attack(
    goal: t.Annotated[str, "Attack goal"],
    agent_url: t.Annotated[str, "HTTP endpoint of the target agent"],
    attacker_model: t.Annotated[str, "LLM generating attack prompts"],
    attack_type: t.Annotated[str, "Attack type (default: tap)"] = "tap",
    agent_auth_type: t.Annotated[
        str, "Auth scheme: 'none', 'bearer', or 'api_key'"
    ] = "none",
    agent_auth_env_var: t.Annotated[
        str, "Env var name for auth credential"
    ] = "AGENT_API_KEY",
    agent_request_template: t.Annotated[
        str, "JSON request template with {prompt} placeholder"
    ] = "",
    agent_response_text_path: t.Annotated[
        str, "JSONPath to extract response text"
    ] = "",
    agent_response_tool_calls_path: t.Annotated[
        str, "JSONPath for tool calls in response"
    ] = "",
    agent_dangerous_tools: t.Annotated[
        list[str] | None, "Dangerous tool names to target for agentic scoring"
    ] = None,
    agent_safe_tools: t.Annotated[
        list[str] | None, "Safe tool whitelist for agentic scoring"
    ] = None,
    agent_preset: t.Annotated[
        str, "Preset: 'openai_assistants', 'anthropic', or 'custom'"
    ] = "custom",
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


@tool
def generate_image_attack(
    attack_type: t.Annotated[
        str,
        "ML adversarial attack type: hopskipjump (or hsj), simba, nes, zoo. "
        "These are black-box attacks that perturb inputs to fool classifiers.",
    ] = "hopskipjump",
    input_type: t.Annotated[
        str,
        "Input data type: 'image' (load from URL, perturb pixels) or "
        "'tabular' (feature array + API endpoint)",
    ] = "image",
    # --- Image-specific params ---
    image_url: t.Annotated[
        str,
        "URL of the source image (for input_type='image'). "
        "Can also be a local file path.",
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
    target_class: t.Annotated[
        int, "Class to flip TO (adversarial target), e.g. 1 for fraud"
    ] = 1,
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
