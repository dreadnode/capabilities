"""Tests for workflow_helper.py — script saving, listing, validation."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "dreadnode" / "ai-red-teaming" / "scripts" / "workflow_helper.py"


@pytest.fixture(autouse=True)
def temp_workflows_dir(tmp_path, monkeypatch):
    wf_dir = tmp_path / "workflows"
    monkeypatch.setenv("AIRT_WORKFLOWS_DIR", str(wf_dir))
    spec = importlib.util.spec_from_file_location("workflow_helper", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    mod.WORKFLOWS_DIR = wf_dir
    mod.METADATA_FILE = wf_dir / ".workflow_metadata.json"
    sys.modules["workflow_helper"] = mod
    spec.loader.exec_module(mod)
    yield mod, wf_dir


class TestSaveWorkflow:
    def test_saves_valid_script(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        result = helper.save_workflow({
            "filename": "test.py",
            "content": "print('hello')",
            "description": "test script",
        })
        assert "error" not in result
        assert (wf_dir / "test.py").exists()

    def test_rejects_syntax_error(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        result = helper.save_workflow({
            "filename": "bad.py",
            "content": "def foo(\n  invalid syntax here",
        })
        assert "error" in result

    def test_rejects_path_traversal(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        result = helper.save_workflow({
            "filename": "../../../etc/passwd",
            "content": "print('hack')",
        })
        assert "error" in result

    def test_adds_py_extension(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        result = helper.save_workflow({
            "filename": "noext",
            "content": "x = 1",
        })
        assert "error" not in result
        assert (wf_dir / "noext.py").exists()


class TestListWorkflows:
    def test_empty_directory(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        wf_dir.mkdir(parents=True, exist_ok=True)
        result = helper.list_workflows({})
        assert "result" in result

    def test_lists_saved_scripts(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        helper.save_workflow({"filename": "a.py", "content": "x=1"})
        helper.save_workflow({"filename": "b.py", "content": "y=2"})
        result = helper.list_workflows({})
        assert "result" in result
        # Result may be a string summary or a dict — just verify it's present
        assert result["result"]
