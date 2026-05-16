"""Tests for workflow_helper.py — script saving, listing, validation."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "workflow_helper.py"


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
        result = helper.save_workflow(
            {
                "filename": "test.py",
                "content": "print('hello')",
                "description": "test script",
            }
        )
        assert "error" not in result
        assert (wf_dir / "test.py").exists()

    def test_rejects_syntax_error(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        result = helper.save_workflow(
            {
                "filename": "bad.py",
                "content": "def foo(\n  invalid syntax here",
            }
        )
        assert "error" in result

    def test_rejects_path_traversal(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        result = helper.save_workflow(
            {
                "filename": "../../../etc/passwd",
                "content": "print('hack')",
            }
        )
        assert "error" in result

    def test_adds_py_extension(self, temp_workflows_dir) -> None:
        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"
        result = helper.save_workflow(
            {
                "filename": "noext",
                "content": "x = 1",
            }
        )
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

    def test_save_workflow_overwrite_verification(self, temp_workflows_dir) -> None:
        """Test that save_workflow properly verifies file overwrite."""
        import unittest.mock
        from pathlib import Path

        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"

        # Create initial file
        initial_content = "print('original')"
        wf_dir.mkdir(parents=True, exist_ok=True)
        test_file = wf_dir / "test.py"
        test_file.write_text(initial_content)

        # Test normal overwrite (should work)
        result = helper.save_workflow({
            "filename": "test.py",
            "content": "print('updated')",
            "description": "test overwrite"
        })
        assert "error" not in result
        assert "updated" in result["result"]
        assert test_file.read_text() == "print('updated')"

        # Test scenario where write appears to succeed but content doesn't change
        # This simulates the bug reported by the user
        original_content = test_file.read_text()

        with unittest.mock.patch.object(Path, 'write_text') as mock_write, \
             unittest.mock.patch.object(Path, 'read_text') as mock_read:

            # Mock write_text to do nothing (simulate silent failure)
            mock_write.return_value = None

            # Mock read_text to return the original content (simulating no change)
            mock_read.return_value = original_content

            result = helper.save_workflow({
                "filename": "test.py",
                "content": "print('new content')",
                "description": "test silent failure"
            })

            # Should detect that content didn't actually change
            assert "error" in result
            assert "incomplete" in result["error"] or "unchanged" in result["error"]

    def test_save_workflow_content_verification(self, temp_workflows_dir) -> None:
        """Test that save_workflow verifies written content matches expected."""
        import unittest.mock
        from pathlib import Path

        helper, wf_dir = temp_workflows_dir
        helper.WORKFLOWS_DIR = wf_dir
        helper.METADATA_FILE = wf_dir / ".workflow_metadata.json"

        # Test scenario where write operation writes partial/incorrect content
        with unittest.mock.patch.object(Path, 'write_text') as mock_write:
            mock_write.return_value = None

            # Mock read_text to return different content than expected
            with unittest.mock.patch.object(Path, 'read_text') as mock_read:
                mock_read.return_value = "print('partial"  # Truncated content

                result = helper.save_workflow({
                    "filename": "test.py",
                    "content": "print('complete content')",
                    "description": "test verification"
                })

                # Should detect that written content doesn't match expected
                assert "error" in result
                assert "incomplete" in result["error"]
