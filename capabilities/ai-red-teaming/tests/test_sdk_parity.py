"""SDK <-> capability parity (V&V).

Ensures the AI-Red-Teaming capability keeps functional parity with the installed
dreadnode SDK so everything a user names in the TUI / agent actually resolves.

- Attacks auto-discover from the SDK (``_discover_attack_defs``); this test asserts
  EVERY SDK ``*_attack`` factory is either discovered, an image attack, or
  explicitly exempt (handled by a dedicated ``generate_*`` tool) - so a new SDK
  attack that no path covers fails CI.
- Transforms / scorers use manual registries; this test asserts the category
  coverage + count floors so a dropped family or a gross regression fails CI.

When the SDK adds something new, this test forces a deliberate choice: wire it into
the capability, or add it to the exempt map with a reason.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import dreadnode.airt as airt

RUNNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "attack_runner.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("attack_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()

# SDK *_attack factories intentionally NOT in the generic auto-discovery because each
# has a DEDICATED generate_* tool (different signature / target shape).
ATTACK_EXEMPT = {
    "agentvigil_attack": "generate_agentvigil_attack (indirect-injection MCTS search)",
    "atlas_attack": "generate_atlas_attack (multi-agent environment)",
    "eva_attack": "generate_eva_attack (GUI overlay injection)",
    "multimodal_attack": "generate_multimodal_attack (media inputs)",
    "multistep_tool_attack": "generate_multistep_tool_attack (tool-chain search)",
    "slip_attack": "generate_slip_attack (single-model self-jailbreak)",
}

WHITE_BOX_ATTACKS = {
    "gcg_attack", "faster_gcg_attack", "i_gcg_attack", "attngcg_attack", "mask_gcg_attack",
    "arca_attack", "gbda_attack", "pez_attack", "cold_attack", "soft_gcg_attack",
    "amplegcg_attack", "refusal_ablation_attack", "soft_prompt_attack", "latentbreak_attack",
    "adaptive_random_search_attack",
}


def test_every_sdk_attack_is_covered():
    """Every SDK ``*_attack`` resolves via generic discovery, image defs, or a
    dedicated tool - no SDK attack is silently unreachable from the TUI/agent."""
    discovered = set(runner._ATTACK_DEFS)
    image = set(getattr(runner, "_IMAGE_ATTACK_DEFS", {}))
    sdk_attacks = {x for x in airt.__all__ if x.endswith("_attack")}
    uncovered = sorted(
        a for a in sdk_attacks if a not in discovered and a not in image and a not in ATTACK_EXEMPT
    )
    assert not uncovered, (
        "SDK attacks not reachable from the capability (wire into _ATTACK_DEFS / "
        f"_IMAGE_ATTACK_DEFS or add to ATTACK_EXEMPT with a reason): {uncovered}"
    )


def test_white_box_attacks_present():
    """All 15 white-box attacks are auto-discovered + flagged requires_surrogate."""
    missing = sorted(a for a in WHITE_BOX_ATTACKS if a not in runner._ATTACK_DEFS)
    assert not missing, f"white-box attacks missing from the capability: {missing}"
    not_flagged = sorted(
        a for a in WHITE_BOX_ATTACKS if not runner._ATTACK_DEFS[a].get("requires_surrogate")
    )
    assert not not_flagged, f"white-box attacks not flagged requires_surrogate: {not_flagged}"


def test_attack_count_floor():
    assert len(runner._ATTACK_DEFS) >= 70, f"only {len(runner._ATTACK_DEFS)} attacks discovered"


def test_transform_category_coverage():
    """Every transform family is represented (catches a dropped category)."""
    names = {
        (v.get("name") or "")
        for v in list(runner._TRANSFORM_DEFS.values())
        + list(runner._MULTIMODAL_TRANSFORM_DEFS.values())
    }
    required = {
        "encoding": "base64_encode",
        "cipher": "caesar_cipher",
        "persuasion": "authority_appeal",
        "mcp": "cross_server_shadow",
        "multi_agent": "prompt_infection",
        "exfiltration": "dns_exfil_injection",
        "reasoning": "reasoning_hijack",
        "guardrail": "classifier_evasion",
        "browser": "visual_prompt_injection",
    }
    missing = {cat: fn for cat, fn in required.items() if fn not in names}
    assert not missing, f"transform categories missing a representative: {missing}"


def test_transform_count_floor():
    total = len(runner._TRANSFORM_DEFS) + len(runner._MULTIMODAL_TRANSFORM_DEFS)
    assert total >= 590, f"only {total} transforms registered"


def test_scorer_count_floor_and_key_scorers():
    assert len(runner.SCORER_REGISTRY) >= 140, f"only {len(runner.SCORER_REGISTRY)} scorers"
    for key in ("data_exfil", "memory_poisoning", "refusal"):
        assert key in runner.SCORER_REGISTRY, f"key scorer '{key}' missing from SCORER_REGISTRY"
