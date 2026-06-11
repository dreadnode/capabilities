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

    path = Path(__file__).resolve().parents[1] / "workers" / "coordinator.py"
    spec = importlib.util.spec_from_file_location("asm_worker_coordinator", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_normalize_scope_payload_accepts_json_wildcards():
    coordinator = _load_coordinator()

    scope = coordinator._normalize_scope_payload(
        {
            "target": "example",
            "wildcards": '["*.example.com", "*.example.net"]',
            "graph_api_url": "http://graph.local",
        }
    )

    assert scope["target"] == "example"
    assert scope["wildcards"] == ["*.example.com", "*.example.net"]
    assert scope["graph_api_url"] == "http://graph.local"


def test_extract_findings_keeps_only_high_and_critical_tool_calls():
    coordinator = _load_coordinator()

    findings = coordinator._extract_findings(
        [
            {
                "name": "attack_surface_management__record_asm_finding",
                "arguments": {"id": "ASM-HIGH-001", "severity": "high"},
            },
            {
                "name": "record_asm_finding",
                "arguments": {"id": "ASM-MED-001", "severity": "medium"},
            },
            {
                "name": "record_asm_finding",
                "arguments": {"id": "ASM-CRIT-001", "severity": "critical"},
            },
        ]
    )

    assert [finding["id"] for finding in findings] == [
        "ASM-HIGH-001",
        "ASM-CRIT-001",
    ]
