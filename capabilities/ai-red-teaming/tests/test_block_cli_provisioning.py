"""Tests for the block_cli_provisioning guardrail hook (ENG-8477)."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

_HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "block_cli_provisioning.py"
_spec = importlib.util.spec_from_file_location("airt_block_cli_provisioning", _HOOK_PATH)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
# Register before exec so dataclasses can resolve the module namespace under
# `from __future__ import annotations` (dataclasses looks the module up in sys.modules).
sys.modules[_spec.name] = _mod
_spec.loader.exec_module(_mod)


class _Fn:
    def __init__(self, arguments: str) -> None:
        self.arguments = arguments


class _Call:
    def __init__(self, name: str, arguments: str, call_id: str = "call_1") -> None:
        self.name = name
        self.id = call_id
        self.function = _Fn(arguments)


class _Event:
    def __init__(self, name: str, arguments: str) -> None:
        self.tool_call = _Call(name, arguments)


def _run(name: str, arguments: str):
    # The @hook decorator wraps the function in a Hook; call the underlying func.
    hook_obj = _mod.block_cli_provisioning
    fn = getattr(hook_obj, "func", hook_obj)
    return asyncio.run(fn(_Event(name, arguments)))


def test_blocks_dreadnode_env_provision_via_bash() -> None:
    r = _run("bash", json.dumps({"command": "dreadnode env provision finops-mesh"}))
    assert r is not None
    assert type(r).__name__ == "RetryWithFeedback"
    assert "provision_environment" in r.feedback


def test_blocks_dn_env_and_environment_variants() -> None:
    assert _run("bash", json.dumps({"command": "dn env create soc-mesh"})) is not None
    assert _run("shell", json.dumps({"command": "dreadnode environment up x"})) is not None
    assert _run("python", json.dumps({"code": "os.system('dreadnode env provision m')"})) is not None


def test_blocks_teardown_via_cli_and_redirects_to_teardown_tool() -> None:
    r = _run("bash", json.dumps({"command": "dreadnode env teardown finops-mesh"}))
    assert r is not None
    assert "teardown_environment" in r.feedback
    # destroy/delete variants also redirect to the teardown tool
    assert "teardown_environment" in _run("bash", json.dumps({"command": "dn env delete soc-mesh"})).feedback


def test_allows_non_provisioning_shell_commands() -> None:
    assert _run("bash", json.dumps({"command": "ls -la /home/user"})) is None
    # dn airt run is a permitted CLI (no skill forbids it) - must not be blocked
    assert _run("bash", json.dumps({"command": "dn airt run --goal x --attack tap"})) is None
    assert _run("bash", json.dumps({"command": "python attack.py"})) is None


def test_ignores_non_shell_tools() -> None:
    # A real provision_environment call must never be blocked.
    assert _run("provision_environment", json.dumps({"name": "finops-mesh"})) is None
