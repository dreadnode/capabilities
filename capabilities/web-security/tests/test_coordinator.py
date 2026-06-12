from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


def _install_worker_stub() -> None:
    dreadnode = sys.modules.get("dreadnode") or types.ModuleType("dreadnode")
    sys.modules["dreadnode"] = dreadnode
    capabilities = types.ModuleType("dreadnode.capabilities")
    worker_mod = types.ModuleType("dreadnode.capabilities.worker")

    class Worker:
        def __init__(self, name: str) -> None:
            self.name = name

        def on_event(self, _event: str):
            def decorator(fn):
                return fn

            return decorator

        def run(self) -> None:
            return None

    worker_mod.EventEnvelope = object
    worker_mod.RuntimeClient = object
    worker_mod.Worker = Worker
    capabilities.worker = worker_mod
    dreadnode.capabilities = capabilities
    sys.modules["dreadnode.capabilities"] = capabilities
    sys.modules["dreadnode.capabilities.worker"] = worker_mod


def _install_loguru_stub() -> None:
    if "loguru" in sys.modules:
        return
    loguru = types.ModuleType("loguru")

    class Logger:
        def __getattr__(self, _name: str):
            def log_method(*_args, **_kwargs) -> None:
                return None

            return log_method

    loguru.logger = Logger()
    sys.modules["loguru"] = loguru


_install_loguru_stub()
_install_worker_stub()


_COORDINATOR_PATH = Path(__file__).resolve().parents[1] / "workers" / "coordinator.py"
_SPEC = importlib.util.spec_from_file_location(
    "web_security_coordinator", _COORDINATOR_PATH
)
assert _SPEC and _SPEC.loader
coordinator = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(coordinator)


def test_extract_recon_verdict_from_heading_and_inline_fallback() -> None:
    assert (
        coordinator._extract_recon_verdict("## Verdict\nproceed_with_caution")
        == "proceed_with_caution"
    )
    assert (
        coordinator._extract_recon_verdict("Verdict: DEFER because auth missing")
        == "defer"
    )
    assert coordinator._extract_recon_verdict("No explicit verdict here") == "proceed"


def test_select_specialists_keeps_core_and_adds_conditionals_once() -> None:
    selected = coordinator._select_specialists(
        "React app using OAuth behind Apache",
        "Has file upload, JWT auth, and JavaScript-heavy profile pages",
    )

    assert selected[:4] == coordinator.ALWAYS_SPECIALISTS
    assert "ws-client-side-specialist" in selected
    assert "ws-auth-access-specialist" in selected
    assert "ws-file-path-specialist" in selected
    assert "ws-platform-specialist" in selected
    assert len(selected) == len(set(selected))


def test_select_specialists_returns_only_core_when_no_conditionals_match() -> None:
    assert (
        coordinator._select_specialists("static brochure site", "home and about pages")
        == coordinator.ALWAYS_SPECIALISTS
    )


def test_extract_session_snapshot_finds_json_block_with_session_keys() -> None:
    text = """
    ## Session Snapshot
    ```json
    {"cookies": {"session": "redacted"}, "base_url": "https://target.example"}
    ```
    """

    assert coordinator._extract_session_snapshot(text) == {
        "cookies": {"session": "redacted"},
        "base_url": "https://target.example",
    }


def test_extract_session_snapshot_returns_none_without_json_block() -> None:
    assert (
        coordinator._extract_session_snapshot(
            "## Session Snapshot\nNo reusable auth state."
        )
        is None
    )


def test_extract_findings_accepts_bare_and_namespaced_high_critical_only() -> None:
    calls = [
        {"name": "record_ws_finding", "arguments": {"id": "A", "severity": "high"}},
        {
            "name": "web_security__record_ws_finding",
            "arguments": {"id": "B", "severity": "critical"},
        },
        {"name": "record_ws_finding", "arguments": {"id": "C", "severity": "medium"}},
        {"name": "other", "arguments": {"id": "D", "severity": "critical"}},
    ]

    findings = coordinator._extract_findings(calls)

    assert [finding["id"] for finding in findings] == ["A", "B"]
    assert [finding["severity"] for finding in findings] == ["high", "critical"]


def test_extract_findings_ignores_malformed_tool_calls() -> None:
    calls = [
        "not a dict",
        {"name": 123, "arguments": {"severity": "critical"}},
        {"name": "record_ws_finding", "arguments": "not a dict"},
        {"name": "record_ws_finding", "arguments": {"severity": "critical"}},
    ]

    findings = coordinator._extract_findings(calls)

    assert findings == [{"severity": "critical", "id": "WS-FINDING-001"}]


def test_safe_payload_redacts_secret_like_keys() -> None:
    assert coordinator._safe_payload(
        {"target_url": "https://example.com", "api_token": "secret"}
    ) == {
        "target_url": "https://example.com",
        "api_token": "<redacted>",
    }


def test_safe_payload_redacts_nested_secret_like_keys() -> None:
    payload = {
        "target_url": "https://example.com",
        "credentials": {
            "username": "alice",
            "password": "pw",
            "headers": {"Authorization": "Bearer abc", "Cookie": "sid=123"},
        },
        "items": [{"session_token": "abc"}],
    }

    assert coordinator._safe_payload(payload) == {
        "target_url": "https://example.com",
        "credentials": "<redacted>",
        "items": [{"session_token": "<redacted>"}],
    }


def test_coerce_max_steps_defaults_validates_and_clamps() -> None:
    assert coordinator._coerce_max_steps(None) == coordinator.DEFAULT_MAX_STEPS
    assert coordinator._coerce_max_steps("7") == 7
    assert coordinator._coerce_max_steps(0) == 1

    try:
        coordinator._coerce_max_steps("nope")
    except ValueError as exc:
        assert "invalid max_steps" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_worker_stage_guard_mentions_recursive_pipeline_ban() -> None:
    assert "Do not call" in coordinator._worker_stage_guard()
    assert "worker" in coordinator._worker_stage_guard()


def test_is_http_url_accepts_http_https_only() -> None:
    assert coordinator._is_http_url("https://example.com/path?q=1#frag")
    assert coordinator._is_http_url("http://127.0.0.1:8080")
    assert not coordinator._is_http_url("ftp://example.com")
    assert not coordinator._is_http_url("https:// bad")


def test_specialist_budget_has_floor_and_scales_by_specialist_count() -> None:
    assert coordinator._specialist_budget(20, coordinator.ALWAYS_SPECIALISTS) == 6
    assert coordinator._specialist_budget(240, coordinator.ALWAYS_SPECIALISTS) == 45


def test_fallback_synthesis_report_includes_findings_and_validators() -> None:
    report = coordinator._fallback_synthesis_report(
        "# Triage",
        [{"id": "WS-HIGH-001", "title": "SSRF"}],
        {"WS-HIGH-001": "confirmed"},
    )

    assert "# Triage" in report
    assert "### WS-HIGH-001: SSRF" in report
    assert "confirmed" in report


def test_label_safe_strips_url_delimiters_and_limits_length() -> None:
    label = coordinator._label_safe("https://example.com/path?a=1&b=2#frag" * 10)

    assert "?" not in label
    assert "&" not in label
    assert "#" not in label
    assert len(label) <= 120


def test_compact_tool_call_summary_renders_arguments_and_result() -> None:
    summary = coordinator._compact_tool_call_summary(
        [
            {
                "name": "execute_http",
                "arguments": {"url": "https://example.com"},
                "result": "HTTP 200",
            }
        ]
    )

    assert "execute_http" in summary
    assert "https://example.com" in summary

    assert "HTTP 200" in summary


class _FakePublisher:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.events = []

    async def publish(self, event, payload):
        if self.fail:
            raise RuntimeError("bus down")
        self.events.append((event, payload))


def test_safe_publish_swallows_event_bus_errors() -> None:
    import asyncio

    asyncio.run(
        coordinator._safe_publish(_FakePublisher(fail=True), "event", {"ok": True})
    )


def test_safe_publish_records_successful_publish() -> None:
    import asyncio

    publisher = _FakePublisher()
    asyncio.run(coordinator._safe_publish(publisher, "event", {"ok": True}))

    assert publisher.events == [("event", {"ok": True})]
