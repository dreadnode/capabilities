"""Tests for CredenceTool — confidence calibration toolset."""

from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path

import pytest

# Add tools directory to path for import
_REPO_ROOT = Path(__file__).resolve()
while _REPO_ROOT != _REPO_ROOT.parent:
    if (_REPO_ROOT / "capabilities" / "web-security" / "tools").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent
sys.path.insert(0, str(_REPO_ROOT / "capabilities" / "web-security" / "tools"))

from credence import CredenceTool

TRACE_ID_RE = re.compile(r"\[trace_id:([0-9a-f-]{36})\]")


@pytest.fixture
def toolset() -> CredenceTool:
    return CredenceTool()


def extract_trace_id(result: str) -> uuid.UUID:
    match = TRACE_ID_RE.search(result)
    assert match is not None
    return uuid.UUID(match.group(1))


class TestToolDiscovery:
    def test_tool_discovered(self, toolset: CredenceTool) -> None:
        tools = toolset.get_tools()
        assert len(tools) == 1
        assert tools[0].name == "assess_confidence"

    def test_tool_has_description(self, toolset: CredenceTool) -> None:
        tool = toolset.get_tools()[0]
        assert tool.description
        assert "BEFORE" in tool.description

    def test_tool_has_catch(self, toolset: CredenceTool) -> None:
        tool = toolset.get_tools()[0]
        assert tool.catch is True

    def test_schema_has_required_params(self, toolset: CredenceTool) -> None:
        tool = toolset.get_tools()[0]
        props = tool.parameters_schema.get("properties", {})
        assert "claim" in props
        assert "confidence" in props
        assert "evidence_basis" in props

    def test_schema_does_not_accept_trace_id(self, toolset: CredenceTool) -> None:
        tool = toolset.get_tools()[0]
        props = tool.parameters_schema.get("properties", {})
        assert "trace_id" not in props


class TestHighConfidence:
    @pytest.mark.asyncio
    async def test_high_with_poc_confirmed(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="SQLi in /api/users?id=1' OR 1=1--",
            confidence="high",
            evidence_basis="poc_confirmed",
        )
        assert "CONFIRMED" in result
        extract_trace_id(result)

    @pytest.mark.asyncio
    async def test_high_with_response_verified(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="XSS reflected unencoded in search param",
            confidence="high",
            evidence_basis="response_verified",
        )
        assert "CONFIRMED" in result

    @pytest.mark.asyncio
    async def test_high_with_data_flow_traced(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="user input reaches innerHTML in app.js:456",
            confidence="high",
            evidence_basis="data_flow_traced",
        )
        assert "CONFIRMED" in result

    @pytest.mark.asyncio
    async def test_high_with_pattern_only_is_overconfident(
        self, toolset: CredenceTool
    ) -> None:
        result = await toolset.assess_confidence(
            claim="innerHTML usage found in dashboard.js",
            confidence="high",
            evidence_basis="pattern_only",
        )
        assert "OVERCONFIDENT" in result
        assert "lead/gadget" in result.lower()

    @pytest.mark.asyncio
    async def test_high_with_scanner_output_is_overconfident(
        self, toolset: CredenceTool
    ) -> None:
        result = await toolset.assess_confidence(
            claim="nuclei flagged potential SSRF",
            confidence="high",
            evidence_basis="scanner_output",
        )
        assert "OVERCONFIDENT" in result

    @pytest.mark.asyncio
    async def test_high_with_assumed_is_overconfident(
        self, toolset: CredenceTool
    ) -> None:
        result = await toolset.assess_confidence(
            claim="probably using MySQL based on error page",
            confidence="high",
            evidence_basis="assumed",
        )
        assert "OVERCONFIDENT" in result

    @pytest.mark.asyncio
    async def test_high_with_behavior_observed_is_overconfident(
        self, toolset: CredenceTool
    ) -> None:
        result = await toolset.assess_confidence(
            claim="timing difference suggests blind SQLi",
            confidence="high",
            evidence_basis="behavior_observed",
        )
        assert "OVERCONFIDENT" in result

    @pytest.mark.asyncio
    async def test_high_with_code_pattern_is_overconfident(
        self, toolset: CredenceTool
    ) -> None:
        result = await toolset.assess_confidence(
            claim="eval() called with user input nearby",
            confidence="high",
            evidence_basis="code_pattern_with_context",
        )
        assert "OVERCONFIDENT" in result


class TestMediumConfidence:
    @pytest.mark.asyncio
    async def test_medium_with_weak_evidence(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="possible IDOR on /api/orders/{id}",
            confidence="medium",
            evidence_basis="pattern_only",
        )
        assert "UNCONFIRMED LEAD" in result
        assert "report" not in result.lower() or "do not" in result.lower()

    @pytest.mark.asyncio
    async def test_medium_with_behavior_observed(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="different response length for admin vs user",
            confidence="medium",
            evidence_basis="behavior_observed",
        )
        assert "UNCONFIRMED LEAD" in result

    @pytest.mark.asyncio
    async def test_medium_with_strong_evidence_suggests_upgrade(
        self, toolset: CredenceTool
    ) -> None:
        result = await toolset.assess_confidence(
            claim="BOLA confirmed with cross-user data",
            confidence="medium",
            evidence_basis="poc_confirmed",
        )
        assert "UPGRADE" in result

    @pytest.mark.asyncio
    async def test_medium_with_response_verified_suggests_upgrade(
        self, toolset: CredenceTool
    ) -> None:
        result = await toolset.assess_confidence(
            claim="path traversal returns /etc/passwd",
            confidence="medium",
            evidence_basis="response_verified",
        )
        assert "UPGRADE" in result


class TestLowConfidence:
    @pytest.mark.asyncio
    async def test_low_confidence(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="might have command injection somewhere",
            confidence="low",
            evidence_basis="assumed",
        )
        assert "INSUFFICIENT" in result
        assert "gadget" in result.lower()

    @pytest.mark.asyncio
    async def test_uncertain_confidence(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="not sure what this endpoint does",
            confidence="uncertain",
            evidence_basis="assumed",
        )
        assert "INSUFFICIENT" in result

    @pytest.mark.asyncio
    async def test_low_with_strong_evidence_still_insufficient(
        self, toolset: CredenceTool
    ) -> None:
        """Even strong evidence with low confidence = don't assert."""
        result = await toolset.assess_confidence(
            claim="got a 500 but not sure it's exploitable",
            confidence="low",
            evidence_basis="poc_confirmed",
        )
        assert "INSUFFICIENT" in result


class TestAgentString:
    @pytest.mark.asyncio
    async def test_agent_string_in_output(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="XSS confirmed",
            confidence="high",
            evidence_basis="poc_confirmed",
            agent_string="agent-opus",
        )
        assert result.startswith("[agent-opus] ")
        assert "CONFIRMED" in result

    @pytest.mark.asyncio
    async def test_different_agent_strings(self, toolset: CredenceTool) -> None:
        for agent in ("dn-agent-kimi", "agent-codex", "agent-opus"):
            result = await toolset.assess_confidence(
                claim="test claim",
                confidence="low",
                evidence_basis="assumed",
                agent_string=agent,
            )
            assert result.startswith(f"[{agent}] ")

    @pytest.mark.asyncio
    async def test_default_agent_string(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="test claim",
            confidence="high",
            evidence_basis="poc_confirmed",
        )
        assert result.startswith("[unknown] ")

    @pytest.mark.asyncio
    async def test_agent_string_in_schema(self, toolset: CredenceTool) -> None:
        tool = toolset.get_tools()[0]
        props = tool.parameters_schema.get("properties", {})
        assert "agent_string" in props


class TestTraceId:
    @pytest.mark.asyncio
    async def test_trace_id_is_generated_for_each_assessment(
        self, toolset: CredenceTool
    ) -> None:
        first = await toolset.assess_confidence(
            claim="XSS confirmed",
            confidence="high",
            evidence_basis="poc_confirmed",
        )
        second = await toolset.assess_confidence(
            claim="XSS confirmed",
            confidence="high",
            evidence_basis="poc_confirmed",
        )

        assert extract_trace_id(first) != extract_trace_id(second)


class TestCvssScore:
    @pytest.mark.asyncio
    async def test_cvss_tag_in_output(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="IDOR on /api/users/{id}",
            confidence="high",
            evidence_basis="poc_confirmed",
            cvss_score=7.5,
        )
        assert "[cvss:7.5]" in result
        assert "CONFIRMED" in result

    @pytest.mark.asyncio
    async def test_no_cvss_tag_when_omitted(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="test",
            confidence="high",
            evidence_basis="poc_confirmed",
        )
        assert "[cvss:" not in result

    @pytest.mark.asyncio
    async def test_low_confidence_high_cvss_warns(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="maybe RCE",
            confidence="low",
            evidence_basis="assumed",
            cvss_score=9.8,
        )
        assert "CVSS WARNING" in result
        assert "inflated" in result

    @pytest.mark.asyncio
    async def test_high_confidence_critical_cvss_warns(
        self, toolset: CredenceTool
    ) -> None:
        result = await toolset.assess_confidence(
            claim="full RCE",
            confidence="high",
            evidence_basis="poc_confirmed",
            cvss_score=9.8,
        )
        assert "CVSS WARNING" in result
        assert "Critical" in result

    @pytest.mark.asyncio
    async def test_matching_cvss_no_warning(self, toolset: CredenceTool) -> None:
        result = await toolset.assess_confidence(
            claim="info disclosure",
            confidence="high",
            evidence_basis="poc_confirmed",
            cvss_score=4.3,
        )
        assert "CVSS WARNING" not in result


class TestHandleToolCall:
    @pytest.mark.asyncio
    async def test_via_handle_tool_call(self, toolset: CredenceTool) -> None:
        from dreadnode.agents.tools import FunctionCall, ToolCall

        tools = {t.name: t for t in toolset.get_tools()}
        tc = ToolCall(
            id="call_credence",
            function=FunctionCall(
                name="assess_confidence",
                arguments='{"claim": "XSS in search", "confidence": "high", "evidence_basis": "poc_confirmed"}',
            ),
        )
        message, stop = await tools["assess_confidence"].handle_tool_call(tc)
        assert stop is False
        assert "CONFIRMED" in message.content

    @pytest.mark.asyncio
    async def test_overconfident_via_handle_tool_call(
        self, toolset: CredenceTool
    ) -> None:
        from dreadnode.agents.tools import FunctionCall, ToolCall

        tools = {t.name: t for t in toolset.get_tools()}
        tc = ToolCall(
            id="call_credence_2",
            function=FunctionCall(
                name="assess_confidence",
                arguments='{"claim": "probably SQLi", "confidence": "high", "evidence_basis": "assumed"}',
            ),
        )
        message, stop = await tools["assess_confidence"].handle_tool_call(tc)
        assert stop is False
        assert "OVERCONFIDENT" in message.content
