"""Tests for assessment_tracker.py — assessment lifecycle and state persistence."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "assessment_tracker.py"


@pytest.fixture(autouse=True)
def temp_state_file(tmp_path, monkeypatch):
    state_file = tmp_path / "assessment.json"
    monkeypatch.setenv("AIRT_ASSESSMENT_PATH", str(state_file))
    # Reload module with new env
    spec = importlib.util.spec_from_file_location("assessment_tracker", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    mod.STATE_FILE = state_file
    sys.modules["assessment_tracker"] = mod
    spec.loader.exec_module(mod)
    yield mod, state_file


class TestRegisterAssessment:
    def test_register_creates_state(self, temp_state_file) -> None:
        tracker, state_file = temp_state_file
        tracker.STATE_FILE = state_file
        result = tracker.register_assessment(
            {
                "name": "Test Assessment",
                "target": "gpt-4o",
                "planned_attacks": ["tap_attack", "goat_attack"],
                "goal": "test goal",
            }
        )
        assert "result" in result
        assert state_file.exists()

    def test_register_stores_planned_attacks(self, temp_state_file) -> None:
        tracker, state_file = temp_state_file
        tracker.STATE_FILE = state_file
        tracker.register_assessment(
            {
                "name": "Test",
                "target": "groq",
                "planned_attacks": ["tap_attack", "pair_attack", "crescendo_attack"],
            }
        )
        state = json.loads(state_file.read_text())
        assert len(state["planned_attacks"]) == 3
        assert state["status"] == "in_progress"


class TestGetAssessmentStatus:
    def test_no_assessment_returns_error(self, temp_state_file) -> None:
        tracker, _ = temp_state_file
        result = tracker.get_assessment_status({})
        assert "error" in result

    def test_shows_progress(self, temp_state_file) -> None:
        tracker, state_file = temp_state_file
        tracker.STATE_FILE = state_file
        tracker.register_assessment(
            {
                "name": "Test",
                "target": "groq",
                "planned_attacks": ["tap_attack", "goat_attack"],
            }
        )
        tracker.update_assessment_status(
            {
                "attack_name": "tap_attack",
                "status": "completed",
                "asr": 0.45,
            }
        )
        result = tracker.get_assessment_status({})
        assert "1/2" in result["result"]


class TestUpdateAssessmentStatus:
    def test_update_records_completion(self, temp_state_file) -> None:
        tracker, state_file = temp_state_file
        tracker.STATE_FILE = state_file
        tracker.register_assessment(
            {
                "name": "Test",
                "target": "groq",
                "planned_attacks": ["tap_attack"],
            }
        )
        result = tracker.update_assessment_status(
            {
                "attack_name": "tap_attack",
                "status": "completed",
                "asr": 0.8,
                "risk_score": 7.5,
            }
        )
        assert "result" in result

    def test_auto_completes_when_all_done(self, temp_state_file) -> None:
        tracker, state_file = temp_state_file
        tracker.STATE_FILE = state_file
        tracker.register_assessment(
            {
                "name": "Test",
                "target": "groq",
                "planned_attacks": ["tap_attack"],
            }
        )
        tracker.update_assessment_status(
            {
                "attack_name": "tap_attack",
                "status": "completed",
            }
        )
        state = json.loads(state_file.read_text())
        assert state["status"] == "completed"

    def test_replaces_existing_entry(self, temp_state_file) -> None:
        tracker, state_file = temp_state_file
        tracker.STATE_FILE = state_file
        tracker.register_assessment(
            {
                "name": "Test",
                "target": "groq",
                "planned_attacks": ["tap_attack"],
            }
        )
        tracker.update_assessment_status(
            {"attack_name": "tap_attack", "status": "failed"}
        )
        tracker.update_assessment_status(
            {"attack_name": "tap_attack", "status": "completed", "asr": 0.9}
        )
        state = json.loads(state_file.read_text())
        assert len(state["completed_attacks"]) == 1
        assert state["completed_attacks"][0]["status"] == "completed"
