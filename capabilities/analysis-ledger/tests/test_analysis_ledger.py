import asyncio
from hashlib import sha256
import importlib.util
import sys
import typing as t
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
import yaml

from dreadnode.items.config import selected_builtin_item_types
from dreadnode.packaging.manifest import CapabilityManifest
from dreadnode.tools.report_items import build_capability_report_item

CAPABILITY_ROOT = Path(__file__).parents[1]


def _load_module(name: str, relative_path: str) -> t.Any:
    path = CAPABILITY_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeApi:
    """Stand-in ApiClient serving the built-in list_items surface per item type."""

    def __init__(self, by_type: dict[str, list[dict[str, t.Any]]]) -> None:
        self.by_type = by_type
        self.calls: list[dict[str, t.Any]] = []

    def list_items(
        self,
        org: str,
        workspace: str,
        project: str,
        **params: t.Any,
    ) -> dict[str, t.Any]:
        self.calls.append(params)
        items = self.by_type.get(params.get("item_type"), [])
        if params.get("ref") is not None:
            items = [item for item in items if item.get("ref") == params["ref"]]
        return {"items": items, "total": len(items), "has_next": False}


def _run(ref: str = "run-auth") -> dict[str, t.Any]:
    return {
        "id": f"id-{ref}",
        "ref": ref,
        "item_type": "analysis_run",
        "title": "Authentication analysis",
        "data": {
            "title": "Authentication analysis",
            "run_key": "0123456789abcdef01234567",
            "objective": "Find authentication bypasses",
            "repository": "/repo",
            "revision": "deadbeef",
            "run_state": "running",
            "max_targets": 50,
            "max_depth": 8,
            "iterations_completed": 2,
            "non_expanding_iterations": 0,
            "targets_discovered": 3,
        },
    }


def _target(
    ref: str,
    *,
    run_ref: str = "run-auth",
    state: str = "queued",
    priority: int = 50,
    depth: int = 0,
) -> dict[str, t.Any]:
    return {
        "id": f"id-{ref}",
        "ref": ref,
        "item_type": "analysis_target",
        "title": ref,
        "data": {
            "title": ref,
            "run_ref": run_ref,
            "target_key": f"src/auth.py::{ref}",
            "kind": "function",
            "location": f"src/auth.py::{ref}",
            "priority": priority,
            "rationale": "Authentication boundary",
            "target_state": state,
            "depth": depth,
        },
        "updated_at": "2026-07-15T12:00:00Z",
    }


def _claim(run_ref: str, disposition: str) -> dict[str, t.Any]:
    return {
        "item_type": "analysis_claim",
        "data": {"run_ref": run_ref, "disposition": disposition},
    }


def test_item_schemas_reject_unknown_fields() -> None:
    items = _load_module("analysis_ledger_models", "items.py")
    run_material = "/repo\ndeadbeef\nFind authentication bypasses"
    run_key = sha256(run_material.encode()).hexdigest()[:24]
    run = items.AnalysisRun.model_validate(
        {
            "title": "Authentication analysis",
            "run_key": run_key,
            "objective": "Find authentication bypasses",
            "repository": "/repo",
            "revision": "deadbeef",
        }
    )
    assert run.run_key == run_key

    with pytest.raises(ValueError, match="run_key must be"):
        items.AnalysisRun.model_validate(
            {
                "title": "Authentication analysis",
                "run_key": "0123456789abcdef01234567",
                "objective": "Find authentication bypasses",
                "repository": "/repo",
                "revision": "deadbeef",
            }
        )

    target = items.AnalysisTarget.model_validate(
        {
            "title": "Validate login",
            "run_ref": "run-auth",
            "target_key": "src/auth.py::login",
            "kind": "function",
            "location": "src/auth.py:40",
            "rationale": "Externally reachable authentication path",
        }
    )
    assert target.target_state == "queued"
    assert target.priority == 50

    claim = items.AnalysisClaim.model_validate(
        {
            "title": "SQLi in login",
            "run_ref": "run-auth",
            "target_ref": "run-auth-target-login",
            "claim_category": "vulnerability",
            "statement": "Login query concatenates user input.",
            "weakness": "CWE-89",
            "severity": "high",
            "evidence_refs": ["src/auth.py:42"],
        }
    )
    assert claim.weakness == "CWE-89"
    assert claim.severity == "high"

    with pytest.raises(ValueError, match="evidence_refs"):
        items.AnalysisClaim.model_validate(
            {
                "title": "Verified token validation",
                "run_ref": "run-auth",
                "target_ref": "run-auth-target-login",
                "claim_category": "behavior",
                "statement": "Tokens are signed.",
                "disposition": "verified",
            }
        )

    with pytest.raises(ValueError):
        items.AnalysisClaim.model_validate(
            {
                "title": "Token validation",
                "run_ref": "run-auth",
                "target_ref": "run-auth-target-login",
                "claim_category": "behavior",
                "statement": "Tokens are signed.",
                "unknown": True,
            }
        )


def test_exported_json_schemas_enforce_terminal_invariants() -> None:
    items = _load_module("analysis_ledger_json_schemas", "items.py")

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "title": "Authentication analysis",
                "run_key": "0123456789abcdef01234567",
                "objective": "Find authentication bypasses",
                "repository": "/repo",
                "revision": "deadbeef",
                "run_state": "completed",
            },
            items.AnalysisRun.model_json_schema(),
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "title": "Verified SQL injection",
                "run_ref": "run-auth",
                "target_ref": "run-auth-target-login",
                "claim_category": "vulnerability",
                "statement": "User input reaches the query.",
                "disposition": "verified",
                "evidence_refs": ["src/auth.py:42"],
            },
            items.AnalysisClaim.model_json_schema(),
        )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "title": "Analyze login",
                "run_ref": "run-auth",
                "target_key": "src/auth.py::login",
                "kind": "function",
                "location": "src/auth.py:40",
                "rationale": "Externally reachable authentication path",
                "target_state": "analyzed",
                "summary": "No bypass found.",
            },
            items.AnalysisTarget.model_json_schema(),
        )


def test_manifest_builds_combined_report_item_schema() -> None:
    manifest_data = yaml.safe_load((CAPABILITY_ROOT / "capability.yaml").read_text())
    manifest = CapabilityManifest.model_validate(manifest_data)
    capability = SimpleNamespace(path=CAPABILITY_ROOT, manifest=manifest)

    report_tool = build_capability_report_item(
        capability,
        builtin_types=selected_builtin_item_types(manifest),
    )

    assert report_tool is not None
    item_types = report_tool.parameters_schema["properties"]["item_type"]["enum"]
    assert set(item_types) == {
        "finding",
        "analysis_run",
        "analysis_target",
        "analysis_claim",
    }
    properties = report_tool.parameters_schema["properties"]
    assert properties["run_state"]["enum"] == [
        "planned",
        "running",
        "paused",
        "completed",
        "exhausted",
        "stale",
    ]
    assert properties["target_state"]["enum"] == [
        "queued",
        "in-progress",
        "analyzed",
        "blocked",
        "skipped",
        "stale",
    ]
    assert properties["claim_category"]["enum"] == [
        "behavior",
        "trust-boundary",
        "vulnerability",
        "assumption",
        "coverage-gap",
    ]
    assert properties["evidence_refs"]["type"] == "array"


def test_next_targets_uses_stable_best_first_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("analysis_ledger_tools_next", "tools/analysis_items.py")
    api = FakeApi(
        {
            "analysis_run": [_run()],
            "analysis_target": [
                _target("target-low", priority=20),
                _target("target-deep", priority=90, depth=3),
                _target("target-shallow", priority=90, depth=1),
                _target("target-done", state="analyzed", priority=100),
            ],
        }
    )
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    result = asyncio.run(tools.analysis_next_targets.fn(run_ref="run-auth", limit=3))

    assert [target["ref"] for target in result["targets"]] == [
        "target-shallow",
        "target-deep",
        "target-low",
    ]
    assert result["eligible_in_scan"] == 3
    assert result["selection_complete"] is True
    assert api.calls[0]["item_type"] == "analysis_run"
    assert api.calls[1]["item_type"] == "analysis_target"
    assert api.calls[1]["q"] == "run-auth"


def test_progress_counts_target_and_claim_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("analysis_ledger_tools_progress", "tools/analysis_items.py")
    api = FakeApi(
        {
            "analysis_run": [_run()],
            "analysis_target": [
                _target("target-queued", priority=80),
                _target("target-done", state="analyzed"),
                _target("target-other", run_ref="other-run"),
            ],
            "analysis_claim": [
                _claim("run-auth", "verified"),
                _claim("run-auth", "refuted"),
            ],
        }
    )
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    result = asyncio.run(tools.analysis_progress.fn(run_ref="run-auth"))

    assert result["targets"]["by_state"] == {"analyzed": 1, "queued": 1}
    assert result["targets"]["highest_queued_priority"] == 80
    assert result["claims"]["by_disposition"] == {"refuted": 1, "verified": 1}
    assert result["frontier_exhausted"] is False
    assert result["scan"]["complete"] is True
    assert result["stop_ready"] is False


def test_next_targets_recovers_in_progress_before_queued(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("analysis_ledger_tools_recovery", "tools/analysis_items.py")
    api = FakeApi(
        {
            "analysis_run": [_run()],
            "analysis_target": [
                _target("target-queued", priority=100),
                _target("target-resume", state="in-progress", priority=10),
            ],
        }
    )
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    result = asyncio.run(tools.analysis_next_targets.fn(run_ref="run-auth"))

    assert [target["ref"] for target in result["targets"]] == ["target-resume"]
    assert result["targets"][0]["target_state"] == "in-progress"
    assert result["resuming_in_progress"] == 1


def test_missing_run_is_not_reported_as_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("analysis_ledger_tools_missing_run", "tools/analysis_items.py")
    api = FakeApi({})
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    with pytest.raises(ValueError, match="was not found"):
        asyncio.run(tools.analysis_progress.fn(run_ref="missing-run"))


def test_unseeded_run_is_not_reported_as_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("analysis_ledger_tools_unseeded", "tools/analysis_items.py")
    run = _run()
    run["data"]["targets_discovered"] = 0
    api = FakeApi(
        {
            "analysis_run": [run],
            "analysis_target": [],
            "analysis_claim": [],
        }
    )
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    result = asyncio.run(tools.analysis_progress.fn(run_ref="run-auth"))

    assert result["initialized"] is False
    assert result["frontier_exhausted"] is False
    assert result["stop_ready"] is False


def test_truncated_scan_never_selects_or_stops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("analysis_ledger_tools_truncated", "tools/analysis_items.py")
    monkeypatch.setattr(tools, "_MAX_SCAN", 2)
    api = FakeApi(
        {
            "analysis_run": [_run()],
            "analysis_target": [
                _target("target-one", priority=100),
                _target("target-two", priority=90),
                _target("target-three", priority=80),
            ],
            "analysis_claim": [],
        }
    )
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    selected = asyncio.run(tools.analysis_next_targets.fn(run_ref="run-auth"))
    progress = asyncio.run(tools.analysis_progress.fn(run_ref="run-auth"))

    assert selected["targets"] == []
    assert selected["selection_complete"] is False
    assert selected["scan_truncated"] is True
    assert progress["frontier_exhausted"] is False
    assert progress["stop_ready"] is False
    assert progress["scan"]["complete"] is False
