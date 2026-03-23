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
import typing as t
from pathlib import Path

from dreadnode.agents.tools import tool

_RUNNER_SCRIPT = Path(__file__).parent.parent / "scripts" / "attack_runner.py"


def _call_runner(name: str, params: dict) -> str:
    """Call attack_runner.py via subprocess with JSON dispatch."""
    payload = json.dumps({"name": name, "parameters": params})
    try:
        result = subprocess.run(
            ["python3", str(_RUNNER_SCRIPT)],
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
        "prompt, rainbow, gptfuzzer, autodan, renellm, beast, drattack, inception",
    ],
    goal: t.Annotated[str, "The attack goal/objective"],
    target_model: t.Annotated[
        str,
        "Target LLM model. Aliases: gpt-4o, claude, claude-opus, gemini, "
        "mistral, groq, ollama — or full litellm path (e.g., openai/gpt-4o)",
    ],
    attacker_model: t.Annotated[str, "Attacker LLM for generating prompts"] = "",
    evaluator_model: t.Annotated[str, "Judge LLM for scoring"] = "",
    transform_model: t.Annotated[str, "LLM for transform operations"] = "",
    transforms: t.Annotated[
        list[str] | None,
        "Transform names to apply (e.g., ['base64', 'caesar(5)', 'role_play_wrapper']). "
        "200+ available across encoding, cipher, persuasion, agentic, MCP, and more.",
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
