"""Tests for results_inspector.py — result file reading and analytics aggregation."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "results_inspector.py"


@pytest.fixture(autouse=True)
def temp_results_dir(tmp_path, monkeypatch):
    results_dir = tmp_path / "airt"
    results_dir.mkdir()
    monkeypatch.setenv("AIRT_RESULTS_DIR", str(results_dir))
    spec = importlib.util.spec_from_file_location("results_inspector", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    mod.AIRT_DIR = results_dir
    sys.modules["results_inspector"] = mod
    spec.loader.exec_module(mod)
    yield mod, results_dir


class TestInspectResults:
    def test_empty_directory(self, temp_results_dir) -> None:
        inspector, results_dir = temp_results_dir
        inspector.AIRT_DIR = results_dir
        result = inspector.inspect_results({"file_type": "all"})
        assert "result" in result or "error" not in result

    def test_reads_analytics_file(self, temp_results_dir) -> None:
        inspector, results_dir = temp_results_dir
        inspector.AIRT_DIR = results_dir
        analytics_dir = results_dir / "analytics"
        analytics_dir.mkdir()
        (analytics_dir / "test_analytics.json").write_text(
            json.dumps(
                {
                    "asr": 0.45,
                    "risk_score": 6.5,
                    "attack_name": "tap_attack",
                }
            )
        )
        result = inspector.inspect_results({"file_type": "analytics"})
        assert "result" in result


class TestGetAnalyticsSummary:
    def test_returns_dict(self, temp_results_dir) -> None:
        inspector, _ = temp_results_dir
        result = inspector.get_analytics_summary({})
        assert isinstance(result, dict)
        # Either has "result" (found files) or "error" (no files)
        assert "result" in result or "error" in result
