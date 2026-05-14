"""Unit tests for the coordinator worker's pure helpers.

The tests deliberately stay off the event bus and the runtime client — they
exercise the deterministic logic the pipeline depends on (URL validation,
tool-call extraction, prompt assembly). The bus-driven flow is left to
integration testing in a real runtime.
"""

from __future__ import annotations

from pathlib import Path

import coordinator


# ── _is_github_url ───────────────────────────────────────────────────────


class TestIsGithubUrl:
    def test_accepts_canonical_url(self) -> None:
        assert coordinator._is_github_url("https://github.com/owner/repo")

    def test_accepts_git_suffix(self) -> None:
        assert coordinator._is_github_url("https://github.com/owner/repo.git")

    def test_accepts_trailing_slash(self) -> None:
        assert coordinator._is_github_url("https://github.com/owner/repo/")

    def test_rejects_http(self) -> None:
        assert not coordinator._is_github_url("http://github.com/owner/repo")

    def test_rejects_non_github_host(self) -> None:
        assert not coordinator._is_github_url("https://gitlab.com/owner/repo")

    def test_rejects_missing_repo(self) -> None:
        assert not coordinator._is_github_url("https://github.com/owner")

    def test_rejects_empty(self) -> None:
        assert not coordinator._is_github_url("")

    def test_rejects_path_with_spaces(self) -> None:
        assert not coordinator._is_github_url("https://github.com/owner/re po")


# ── _extract_findings ────────────────────────────────────────────────────


def _call(name: str, **args: object) -> dict[str, object]:
    return {"name": name, "arguments": args}


class TestExtractFindings:
    def test_keeps_high_and_critical(self) -> None:
        calls = [
            _call("record_finding", id="HIGH-001", severity="high", title="a"),
            _call("record_finding", id="CRIT-001", severity="critical", title="b"),
            _call("record_finding", id="MED-001", severity="medium", title="c"),
            _call("record_finding", id="LOW-001", severity="low", title="d"),
        ]
        findings = coordinator._extract_findings(calls)
        assert [f["id"] for f in findings] == ["HIGH-001", "CRIT-001"]

    def test_accepts_wire_name(self) -> None:
        wire = "source_code_analysis_worker_template__record_finding"
        calls = [_call(wire, id="W-1", severity="high", title="a")]
        findings = coordinator._extract_findings(calls)
        assert len(findings) == 1
        assert findings[0]["id"] == "W-1"

    def test_normalizes_severity_case_and_whitespace(self) -> None:
        calls = [_call("record_finding", id="X", severity=" CRITICAL ", title="t")]
        findings = coordinator._extract_findings(calls)
        assert findings[0]["severity"] == "critical"

    def test_synthesizes_id_when_missing(self) -> None:
        calls = [
            _call("record_finding", severity="high", title="t1"),
            _call("record_finding", severity="critical", title="t2"),
        ]
        findings = coordinator._extract_findings(calls)
        # Index in tool_calls, not in filtered list, so both keep call-order ids.
        assert [f["id"] for f in findings] == ["FINDING-001", "FINDING-002"]

    def test_skips_unrelated_tool_names(self) -> None:
        calls = [
            _call("report", id="R", severity="critical", title="x"),
            _call("record_finding", id="K", severity="high", title="y"),
        ]
        findings = coordinator._extract_findings(calls)
        assert [f["id"] for f in findings] == ["K"]

    def test_skips_malformed_entries(self) -> None:
        calls = [
            "not-a-dict",
            {"name": 123, "arguments": {"severity": "high"}},
            {"name": "record_finding", "arguments": "not-a-dict"},
            _call("record_finding", id="OK", severity="high", title="t"),
        ]
        findings = coordinator._extract_findings(calls)  # type: ignore[arg-type]
        assert [f["id"] for f in findings] == ["OK"]

    def test_empty_input(self) -> None:
        assert coordinator._extract_findings([]) == []


# ── prompt builders ──────────────────────────────────────────────────────


class TestMapperPrompt:
    def test_includes_url_path_and_budget(self) -> None:
        prompt = coordinator._mapper_prompt(
            "https://github.com/owner/repo", Path("/tmp/x"), 200
        )
        assert "https://github.com/owner/repo" in prompt
        assert "/tmp/x" in prompt
        assert "200" in prompt


class TestSpecialistPrompt:
    def test_carries_attack_surface_into_prompt(self) -> None:
        prompt = coordinator._specialist_prompt(
            "cve-history-researcher",
            "https://github.com/owner/repo",
            Path("/tmp/x"),
            150,
            "ENTRYPOINT: /api/handler",
        )
        assert "cve-history-researcher" in prompt
        assert "ENTRYPOINT: /api/handler" in prompt
        assert "150" in prompt


# ── _build_final_markdown ────────────────────────────────────────────────


class TestBuildFinalMarkdown:
    def test_no_findings_renders_skip_message(self) -> None:
        out = coordinator._build_final_markdown("# review\nbody", [], {})
        assert "Validator Results" in out
        assert "No high or critical findings" in out

    def test_includes_validator_per_finding(self) -> None:
        findings = [
            {"id": "HIGH-001", "title": "first", "severity": "high"},
            {"id": "CRIT-001", "title": "second", "severity": "critical"},
        ]
        validations = {
            "HIGH-001": "validator says ok",
            "CRIT-001": "validator says reproducible",
        }
        out = coordinator._build_final_markdown("# review", findings, validations)
        assert "### HIGH-001: first" in out
        assert "### CRIT-001: second" in out
        assert "validator says ok" in out
        assert "validator says reproducible" in out

    def test_missing_validator_report_is_flagged(self) -> None:
        findings = [{"id": "HIGH-001", "title": "first", "severity": "high"}]
        out = coordinator._build_final_markdown("# review", findings, {})
        assert "Validator report was not produced" in out


# ── capability name constant ─────────────────────────────────────────────


def test_capability_name_matches_directory() -> None:
    assert coordinator.CAPABILITY_NAME == "source-code-analysis-worker-template"
