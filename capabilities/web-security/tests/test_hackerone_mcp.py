"""Tests for the HackerOne MCP server."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# Stub fastmcp before importing the MCP module
# ---------------------------------------------------------------------------


def _install_fastmcp_stub() -> None:
    """Install a minimal fastmcp stub so hackerone.py can be imported."""
    fastmcp = types.ModuleType("fastmcp")

    class _FastMCP:
        def __init__(self, name: str) -> None:
            self.name = name
            self._tools: dict[str, object] = {}

        def tool(self, fn):
            self._tools[fn.__name__] = fn
            return fn

        def run(self, **kwargs) -> None:
            pass

    fastmcp.FastMCP = _FastMCP
    sys.modules["fastmcp"] = fastmcp


_install_fastmcp_stub()

# ---------------------------------------------------------------------------
# Import the MCP module
# ---------------------------------------------------------------------------

MODULE_PATH = Path(__file__).resolve().parent.parent / "mcp" / "hackerone.py"
SPEC = importlib.util.spec_from_file_location("hackerone_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

_H1Client = MODULE._H1Client
_attr = MODULE._attr
_rel_data = MODULE._rel_data
_paginate_all = MODULE._paginate_all


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(
    status_code: int = 200,
    json_data: object = None,
    text: str | None = None,
) -> httpx.Response:
    kwargs: dict = {
        "status_code": status_code,
        "request": httpx.Request("GET", "https://api.hackerone.com/v1/test"),
    }
    if json_data is not None:
        kwargs["json"] = json_data
    elif text is not None:
        kwargs["text"] = text
    return httpx.Response(**kwargs)


def _jsonapi_resource(
    resource_id: str,
    resource_type: str,
    attributes: dict,
    relationships: dict | None = None,
) -> dict:
    """Build a JSON:API resource object."""
    r: dict = {
        "id": resource_id,
        "type": resource_type,
        "attributes": attributes,
    }
    if relationships:
        r["relationships"] = relationships
    return r


# ---------------------------------------------------------------------------
# _H1Client tests
# ---------------------------------------------------------------------------


class TestH1Client:
    def test_missing_credentials_raises(self) -> None:
        client = _H1Client()
        with patch.dict("os.environ", {}, clear=True):
            assert client._get_auth_header() is None

    def test_auth_header_with_credentials(self) -> None:
        client = _H1Client()
        with patch.dict("os.environ", {"H1_USERNAME": "user", "H1_API_TOKEN": "tok"}):
            header = client._get_auth_header()
            assert header is not None
            import base64

            decoded = base64.b64decode(header).decode()
            assert decoded == "user:tok"

    @pytest.mark.asyncio
    async def test_get_raises_without_creds(self) -> None:
        client = _H1Client()
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(RuntimeError, match="H1_USERNAME"):
                await client.get()

    @pytest.mark.asyncio
    async def test_safe_get_returns_error_without_creds(self) -> None:
        client = _H1Client()
        with patch.dict("os.environ", {}, clear=True):
            result, err = await client.safe_get()
            assert result is None
            assert "H1_USERNAME" in err


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_attr_extracts_value(self) -> None:
        resource = {"attributes": {"handle": "example", "name": "Example Corp"}}
        assert _attr(resource, "handle") == "example"
        assert _attr(resource, "name") == "Example Corp"

    def test_attr_returns_default(self) -> None:
        resource = {"attributes": {}}
        assert _attr(resource, "missing") == ""
        assert _attr(resource, "missing", "fallback") == "fallback"

    def test_attr_no_attributes_key(self) -> None:
        assert _attr({}, "handle") == ""

    def test_rel_data_extracts(self) -> None:
        resource = {
            "relationships": {
                "weakness": {"data": {"type": "weakness", "id": "42"}},
            },
        }
        data = _rel_data(resource, "weakness")
        assert data == {"type": "weakness", "id": "42"}

    def test_rel_data_missing_rel(self) -> None:
        assert _rel_data({"relationships": {}}, "weakness") is None

    def test_rel_data_no_relationships_key(self) -> None:
        assert _rel_data({}, "weakness") is None


# ---------------------------------------------------------------------------
# Pagination tests
# ---------------------------------------------------------------------------


class TestPagination:
    @pytest.mark.asyncio
    async def test_paginate_single_page(self) -> None:
        mock_client = AsyncMock()
        items = [_jsonapi_resource(str(i), "scope", {"asset_identifier": f"t{i}.com"}) for i in range(5)]
        mock_client.get.return_value = _mock_response(json_data={"data": items})

        result = await _paginate_all(mock_client, "/test", page_size=100)
        assert len(result) == 5
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_paginate_multiple_pages(self) -> None:
        mock_client = AsyncMock()

        page1 = [_jsonapi_resource(str(i), "scope", {"asset_identifier": f"t{i}.com"}) for i in range(100)]
        page2 = [_jsonapi_resource(str(i + 100), "scope", {"asset_identifier": f"t{i + 100}.com"}) for i in range(30)]

        mock_client.get.side_effect = [
            _mock_response(json_data={"data": page1}),
            _mock_response(json_data={"data": page2}),
        ]

        result = await _paginate_all(mock_client, "/test", page_size=100)
        assert len(result) == 130
        assert mock_client.get.call_count == 2

    @pytest.mark.asyncio
    async def test_paginate_stops_on_empty(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(json_data={"data": []})

        result = await _paginate_all(mock_client, "/test")
        assert result == []

    @pytest.mark.asyncio
    async def test_paginate_stops_on_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(status_code=500)

        result = await _paginate_all(mock_client, "/test")
        assert result == []

    @pytest.mark.asyncio
    async def test_paginate_respects_max_pages(self) -> None:
        mock_client = AsyncMock()
        full_page = [_jsonapi_resource(str(i), "scope", {"x": "y"}) for i in range(100)]
        mock_client.get.return_value = _mock_response(json_data={"data": full_page})

        result = await _paginate_all(mock_client, "/test", max_pages=2, page_size=100)
        assert len(result) == 200
        assert mock_client.get.call_count == 2


# ---------------------------------------------------------------------------
# Tool output format tests (using the module-level functions via mcp)
# ---------------------------------------------------------------------------


class TestHealthTool:
    @pytest.mark.asyncio
    async def test_health_success(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "data": {
                    "attributes": {
                        "username": "hacker1",
                        "reputation": 500,
                        "signal": 3.5,
                        "impact": 12.0,
                        "rank": 42,
                    },
                },
            }
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_health()

        assert "Connected to HackerOne API" in result
        assert "hacker1" in result
        assert "500" in result

    @pytest.mark.asyncio
    async def test_health_auth_error(self) -> None:
        with patch.object(MODULE._h1, "safe_get", return_value=(None, "Error: creds missing")):
            result = await MODULE.hackerone_health()
        assert "Error" in result


class TestListProgramsTool:
    @pytest.mark.asyncio
    async def test_list_programs(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "data": [
                    _jsonapi_resource("1", "program", {
                        "handle": "example",
                        "name": "Example Corp",
                        "offers_bounties": True,
                        "submission_state": "open",
                    }),
                    _jsonapi_resource("2", "program", {
                        "handle": "test-vdp",
                        "name": "Test VDP",
                        "offers_bounties": False,
                        "submission_state": "open",
                    }),
                ],
            }
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_list_programs()

        assert "example" in result
        assert "Example Corp" in result
        assert "test-vdp" in result

    @pytest.mark.asyncio
    async def test_list_programs_empty(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(json_data={"data": []})

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_list_programs()

        assert "No programs found" in result


class TestGetProgramScopeTool:
    @pytest.mark.asyncio
    async def test_scope_assets(self) -> None:
        items = [
            _jsonapi_resource("1", "structured_scope", {
                "asset_type": "URL",
                "asset_identifier": "https://api.example.com",
                "eligible_for_bounty": True,
                "max_severity": "critical",
                "instruction": "Focus on API endpoints",
            }),
            _jsonapi_resource("2", "structured_scope", {
                "asset_type": "WILDCARD",
                "asset_identifier": "*.example.com",
                "eligible_for_bounty": True,
                "max_severity": "critical",
                "instruction": "",
            }),
        ]

        with patch.object(MODULE, "_paginate_all", return_value=items):
            with patch.object(MODULE._h1, "safe_get", return_value=(AsyncMock(), None)):
                result = await MODULE.hackerone_get_program_scope(program_handle="example")

        assert "api.example.com" in result
        assert "*.example.com" in result
        assert "URL" in result
        assert "WILDCARD" in result
        assert "bounty" in result
        assert "Focus on API endpoints" in result

    @pytest.mark.asyncio
    async def test_scope_empty(self) -> None:
        with patch.object(MODULE, "_paginate_all", return_value=[]):
            with patch.object(MODULE._h1, "safe_get", return_value=(AsyncMock(), None)):
                result = await MODULE.hackerone_get_program_scope(program_handle="empty")

        assert "No scope assets found" in result


class TestSearchReportsTool:
    @pytest.mark.asyncio
    async def test_search_reports(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "data": [
                    _jsonapi_resource("12345", "report", {
                        "title": "XSS in search",
                        "state": "triaged",
                        "severity_rating": "high",
                        "created_at": "2026-01-15T10:00:00Z",
                        "bounty_awarded_amount": None,
                    }),
                ],
            }
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_search_reports()

        assert "#12345" in result
        assert "XSS in search" in result
        assert "triaged" in result
        assert "high" in result

    @pytest.mark.asyncio
    async def test_search_reports_with_filters(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(json_data={"data": []})

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_search_reports(
                program="example", severity="critical", state="resolved"
            )

        assert "No reports found" in result
        # Verify filters were passed
        call_args = mock_client.get.call_args
        params = call_args.kwargs.get("params", call_args[1].get("params", {}))
        assert params.get("filter[program][]") == "example"
        assert params.get("filter[severity][]") == "critical"
        assert params.get("filter[state][]") == "resolved"


class TestGetReportTool:
    @pytest.mark.asyncio
    async def test_get_report_full(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "data": _jsonapi_resource(
                    "99999",
                    "report",
                    {
                        "title": "SQL Injection in /api/users",
                        "state": "resolved",
                        "substate": "resolved",
                        "severity_rating": "critical",
                        "created_at": "2026-03-01T12:00:00Z",
                        "disclosed_at": None,
                        "bounty_awarded_amount": "5000",
                        "bounty_bonus_amount": "500",
                        "cvss_score": 9.8,
                        "vulnerability_information": "The id parameter is vulnerable to SQL injection...",
                        "impact": "Full database read access via UNION-based injection.",
                    },
                    relationships={
                        "weakness": {"data": {"type": "weakness", "id": "89"}},
                        "structured_scope": {"data": {"type": "structured_scope", "id": "42"}},
                    },
                ),
            }
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_get_report(report_id="99999")

        assert "SQL Injection" in result
        assert "resolved" in result
        assert "critical" in result
        assert "$5000" in result
        assert "$500" in result
        assert "9.8" in result
        assert "Weakness ID: 89" in result
        assert "Scope ID: 42" in result
        assert "SQL injection" in result  # vuln info
        assert "database read access" in result  # impact

    @pytest.mark.asyncio
    async def test_get_report_not_found(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(status_code=404)

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_get_report(report_id="00000")

        assert "not found" in result


class TestSubmitReportTool:
    @pytest.mark.asyncio
    async def test_submit_success(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(
            status_code=201,
            json_data={
                "data": _jsonapi_resource("77777", "report", {
                    "title": "SSRF via URL parameter",
                    "state": "new",
                }),
            },
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_submit_report(
                program_handle="example",
                title="SSRF via URL parameter",
                vulnerability_information="The url param at /fetch fetches arbitrary URLs...",
                impact="Internal service access via SSRF to cloud metadata.",
                severity_rating="high",
                weakness_id="918",
                structured_scope_id="42",
            )

        assert "submitted successfully" in result
        assert "#77777" in result

        # Verify payload structure
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json", call_args[1].get("json", {}))
        assert payload["data"]["type"] == "report"
        assert payload["data"]["attributes"]["title"] == "SSRF via URL parameter"
        assert payload["data"]["relationships"]["program"]["data"]["id"] == "example"
        assert payload["data"]["relationships"]["weakness"]["data"]["id"] == "918"
        assert payload["data"]["relationships"]["structured_scope"]["data"]["id"] == "42"

    @pytest.mark.asyncio
    async def test_submit_validation_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(
            status_code=422,
            json_data={"errors": [{"detail": "Title is too short"}]},
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_submit_report(
                program_handle="example",
                title="X",
                vulnerability_information="...",
                impact="...",
                severity_rating="low",
            )

        assert "Error" in result
        assert "Title is too short" in result


class TestAddCommentTool:
    @pytest.mark.asyncio
    async def test_add_comment_success(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(status_code=200)

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_add_comment(
                report_id="12345",
                message="Additional reproduction steps attached.",
            )

        assert "Comment added" in result
        assert "12345" in result

        # Verify internal=False by default
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json", call_args[1].get("json", {}))
        assert payload["data"]["attributes"]["internal"] is False


class TestSearchHacktivityTool:
    @pytest.mark.asyncio
    async def test_search_hacktivity(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "data": [
                    _jsonapi_resource("1", "hacktivity_item", {
                        "title": "Stored XSS in comments",
                        "severity_rating": "high",
                        "disclosed_at": "2026-02-10T00:00:00Z",
                        "total_awarded_amount": "2500",
                    }),
                ],
            }
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_search_hacktivity(program="example")

        assert "Stored XSS in comments" in result
        assert "high" in result
        assert "$2500" in result

    @pytest.mark.asyncio
    async def test_hacktivity_empty(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(json_data={"data": []})

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_search_hacktivity()

        assert "No disclosed reports found" in result


class TestGetReportActivitiesTool:
    @pytest.mark.asyncio
    async def test_activities(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "data": [
                    _jsonapi_resource("a1", "activity-comment", {
                        "created_at": "2026-03-10T14:00:00Z",
                        "message": "Thanks for the report. We are investigating.",
                        "internal": False,
                        "automated_response": False,
                    }),
                    _jsonapi_resource("a2", "activity-bug-triaged", {
                        "created_at": "2026-03-11T09:00:00Z",
                        "message": "",
                        "internal": False,
                        "automated_response": True,
                    }),
                ],
            }
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_get_report_activities(report_id="12345")

        assert "activity-comment" in result
        assert "investigating" in result
        assert "activity-bug-triaged" in result
        assert "[auto]" in result


class TestGetEarningsTool:
    @pytest.mark.asyncio
    async def test_earnings(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "data": [
                    _jsonapi_resource("e1", "earning", {
                        "amount": "1500.00",
                        "currency": "USD",
                        "awarded_by": "Example Corp",
                        "created_at": "2026-03-01T00:00:00Z",
                    }),
                ],
            }
        )

        with patch.object(MODULE._h1, "safe_get", return_value=(mock_client, None)):
            result = await MODULE.hackerone_get_earnings()

        assert "1500.00" in result
        assert "USD" in result
        assert "Example Corp" in result
