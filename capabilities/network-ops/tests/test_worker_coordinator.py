from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


def _load_coordinator():
    runtime = types.ModuleType("dreadnode.capabilities.worker")

    class Worker:
        def __init__(self, name: str):
            self.name = name

        def on_event(self, _event: str):
            def decorator(func):
                return func

            return decorator

        def run(self):
            return None

    runtime.EventEnvelope = object
    runtime.RuntimeClient = object
    runtime.Worker = Worker

    sys.modules.setdefault("dreadnode", types.ModuleType("dreadnode"))
    sys.modules.setdefault(
        "dreadnode.capabilities", types.ModuleType("dreadnode.capabilities")
    )
    sys.modules["dreadnode.capabilities.worker"] = runtime

    loguru = types.ModuleType("loguru")

    class _StubLogger:
        def exception(self, *args, **kwargs):
            pass

    loguru.logger = _StubLogger()
    sys.modules.setdefault("loguru", loguru)

    path = Path(__file__).resolve().parents[1] / "workers" / "coordinator.py"
    spec = importlib.util.spec_from_file_location("netops_worker_coordinator", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- _normalize_scope_payload ---


def test_normalize_scope_payload_passes_through_optional_fields():
    coordinator = _load_coordinator()
    scope = coordinator._normalize_scope_payload(
        {
            "target": "10.10.10.0/24",
            "domain": "corp.local",
            "credentials": {"username": "admin", "password": "pass"},
            "exclusions": ["vagrant", "ansible"],
            "dc_ips": ["10.10.10.5"],
        }
    )
    assert scope["target"] == "10.10.10.0/24"
    assert scope["domain"] == "corp.local"
    assert scope["credentials"] == {"username": "admin", "password": "pass"}
    assert scope["exclusions"] == ["vagrant", "ansible"]
    assert scope["dc_ips"] == ["10.10.10.5"]


def test_normalize_scope_payload_drops_empty_values():
    coordinator = _load_coordinator()
    scope = coordinator._normalize_scope_payload(
        {"target": "10.10.10.0/24", "domain": "", "notes": None}
    )
    assert "domain" not in scope
    assert "notes" not in scope


def test_normalize_scope_payload_rejects_missing_target():
    coordinator = _load_coordinator()
    try:
        coordinator._normalize_scope_payload({})
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_normalize_scope_payload_rejects_whitespace_target():
    coordinator = _load_coordinator()
    try:
        coordinator._normalize_scope_payload({"target": "   "})
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


# --- _extract_findings ---


def test_extract_findings_keeps_credentials_hashes_weaknesses():
    coordinator = _load_coordinator()
    findings = coordinator._extract_findings(
        [
            {"name": "report_item", "arguments": {"item": {"text": "admin:pass", "type": "username_password"}}},
            {"name": "network_ops__report_item", "arguments": {"item": {"hash_value": "aabb", "hash_type": "ntlm"}}},
            {"name": "report_item", "arguments": {"item": {"title": "Weak ACL", "severity": "high"}}},
        ]
    )
    assert len(findings) == 3
    assert findings[0]["id"] == "NETOPS-FINDING-001"
    assert findings[2]["severity"] == "high"


def test_extract_findings_drops_enumeration_items():
    coordinator = _load_coordinator()
    findings = coordinator._extract_findings(
        [
            {"name": "report_item", "arguments": {"item": {"ip": "10.0.0.1"}}},
            {"name": "report_item", "arguments": {"item": {"username": "jsmith", "domain": "corp.local"}}},
            {"name": "report_item", "arguments": {"item": {"hash_value": "aabb", "hash_type": "ntlm"}}},
        ]
    )
    assert len(findings) == 1
    assert findings[0]["hash_value"] == "aabb"


def test_extract_findings_survives_malformed_calls():
    coordinator = _load_coordinator()
    findings = coordinator._extract_findings(
        [
            None,
            {"name": 123},
            {"name": "report_item"},
            {"name": "report_item", "arguments": "not a dict"},
            "not a dict at all",
        ]
    )
    assert len(findings) == 0


def test_extract_findings_preserves_existing_id():
    coordinator = _load_coordinator()
    findings = coordinator._extract_findings(
        [{"name": "report_item", "arguments": {"item": {"id": "CUSTOM-001", "severity": "critical", "title": "x"}}}]
    )
    assert findings[0]["id"] == "CUSTOM-001"


# --- _stage_budget ---


def test_stage_budget_clamps_to_cap():
    coordinator = _load_coordinator()
    assert coordinator._stage_budget(240, 6) == 6


def test_stage_budget_clamps_to_max_steps():
    coordinator = _load_coordinator()
    assert coordinator._stage_budget(3, 10) == 3


def test_stage_budget_floors_at_one():
    coordinator = _load_coordinator()
    assert coordinator._stage_budget(0, 10) == 1


# --- utilities ---


def test_truncate_cuts_and_marks():
    coordinator = _load_coordinator()
    result = coordinator._truncate("a" * 200, 50)
    assert result.startswith("a" * 50)
    assert "truncated" in result
    assert len(result) < 200


def test_label_safe_sanitizes_special_chars():
    coordinator = _load_coordinator()
    assert coordinator._label_safe("10.10.10.0/24") == "10.10.10.0_24"


def test_label_safe_caps_length_and_handles_empty():
    coordinator = _load_coordinator()
    assert len(coordinator._label_safe("a" * 200)) == 120
    assert coordinator._label_safe("") == "unknown"


# --- stage guard ---


def test_worker_stage_guard_names_pipeline_tool():
    coordinator = _load_coordinator()
    assert "run_netops_pipeline" in coordinator._worker_stage_guard()


# --- prompt data threading ---


def test_prompts_thread_prior_stage_reports_forward():
    """Each stage prompt must include reports from all prior stages."""
    coordinator = _load_coordinator()

    scope_prompt = coordinator._scope_prompt('{"target":"x"}', 6)
    assert "target" in scope_prompt

    discovery_prompt = coordinator._discovery_prompt('{"target":"x"}', "SCOPE_OUT", 10)
    assert "SCOPE_OUT" in discovery_prompt

    enum_prompt = coordinator._enumeration_prompt(
        '{"target":"x"}', "SCOPE_OUT", "DISCO_OUT", 12
    )
    assert "SCOPE_OUT" in enum_prompt
    assert "DISCO_OUT" in enum_prompt

    exploit_prompt = coordinator._exploit_prompt(
        '{"target":"x"}', "SCOPE_OUT", "DISCO_OUT", "ENUM_OUT", 20
    )
    assert "ENUM_OUT" in exploit_prompt

    harvest_prompt = coordinator._harvest_prompt(
        '{"target":"x"}', "SCOPE_OUT", "DISCO_OUT", "ENUM_OUT", "EXPLOIT_OUT", 10
    )
    assert "EXPLOIT_OUT" in harvest_prompt

    synthesis_prompt = coordinator._synthesis_prompt(
        scope_context='{"target":"x"}',
        scope_report="SCOPE_OUT",
        discovery_report="DISCO_OUT",
        enumeration_report="ENUM_OUT",
        exploit_report="EXPLOIT_OUT",
        harvest_report="HARVEST_OUT",
        findings=[{"id": "F-001"}],
        max_steps=6,
    )
    assert "HARVEST_OUT" in synthesis_prompt
    assert "F-001" in synthesis_prompt


# --- fallback synthesis ---


def test_fallback_synthesis_includes_all_stages():
    coordinator = _load_coordinator()
    report = coordinator._fallback_synthesis_report(
        scope_context='{"target": "10.0.0.0/24"}',
        scope_report="SCOPE",
        discovery_report="DISCO",
        enumeration_report="ENUM",
        exploit_report="EXPLOIT",
        harvest_report="HARVEST",
        findings=[],
    )
    assert "# Network Operations Engagement Report" in report
    for stage in ("SCOPE", "DISCO", "ENUM", "EXPLOIT", "HARVEST"):
        assert stage in report


def test_fallback_synthesis_serializes_findings():
    coordinator = _load_coordinator()
    report = coordinator._fallback_synthesis_report(
        scope_context="{}",
        scope_report="",
        discovery_report="",
        enumeration_report="",
        exploit_report="",
        harvest_report="",
        findings=[{"id": "NETOPS-FINDING-001", "type": "Credential"}],
    )
    assert "NETOPS-FINDING-001" in report


# --- naming conventions ---


def test_agent_constants_use_netops_prefix():
    coordinator = _load_coordinator()
    for name in (
        coordinator.SCOPE_NORMALIZER,
        coordinator.DISCOVERY_OPERATOR,
        coordinator.AD_ENUMERATOR,
        coordinator.EXPLOIT_OPERATOR,
        coordinator.CREDENTIAL_HARVESTER,
        coordinator.REPORT_SYNTHESIZER,
    ):
        assert name.startswith("netops-"), name


def test_event_constants_use_netops_prefix():
    coordinator = _load_coordinator()
    for event in (
        coordinator.REQUEST_EVENT,
        coordinator.PROGRESS_EVENT,
        coordinator.REPORT_READY_EVENT,
        coordinator.COMPLETED_EVENT,
        coordinator.FAILED_EVENT,
    ):
        assert event.startswith("netops."), event
