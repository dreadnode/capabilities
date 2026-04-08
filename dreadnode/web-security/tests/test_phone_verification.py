"""Tests for phone verification tools."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


def _install_dreadnode_tools_stub() -> None:
    dreadnode = types.ModuleType("dreadnode")
    agents = types.ModuleType("dreadnode.agents")
    tools = types.ModuleType("dreadnode.agents.tools")

    class _Tool:
        def __init__(self, name: str, description: str, catch: bool) -> None:
            self.name = name
            self.description = description
            self.catch = catch
            self.parameters_schema = {"properties": {}}

    def tool_method(*, name: str, catch: bool = False):
        def decorator(fn):
            fn._tool_metadata = {
                "name": name,
                "catch": catch,
                "description": fn.__doc__ or "",
            }
            return fn

        return decorator

    class Toolset:
        def get_tools(self):
            discovered = []
            for attr_name in dir(self):
                value = getattr(self, attr_name)
                meta = getattr(value, "_tool_metadata", None)
                if meta:
                    discovered.append(
                        _Tool(meta["name"], meta["description"], meta["catch"])
                    )
            return discovered

    class PrivateAttr:
        def __init__(self, **kwargs):
            self.default = kwargs.get("default")
            self.default_factory = kwargs.get("default_factory")

    tools.Toolset = Toolset
    tools.tool_method = tool_method
    agents.tools = tools
    dreadnode.agents = agents

    # Stub pydantic PrivateAttr if not available in this context
    pydantic_mod = sys.modules.get("pydantic")
    if pydantic_mod and not hasattr(pydantic_mod, "PrivateAttr"):
        pydantic_mod.PrivateAttr = PrivateAttr

    sys.modules["dreadnode"] = dreadnode
    sys.modules["dreadnode.agents"] = agents
    sys.modules["dreadnode.agents.tools"] = tools


_install_dreadnode_tools_stub()

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "phone_verification.py"
SPEC = importlib.util.spec_from_file_location("phone_verification", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

PhoneVerification = MODULE.PhoneVerification
_extract_codes = MODULE._extract_codes
_html_to_text = MODULE._html_to_text
_parse_numbers_from_html = MODULE._parse_numbers_from_html
_parse_messages_from_html = MODULE._parse_messages_from_html


# ── Sample HTML fixtures ─────────────────────────────────────────────

# Fixtures match the real receive-smss.com HTML structure (2025)
HOMEPAGE_HTML = """
<a style="text-decoration: none;" href="/sms/13802603245/" aria-label="+13802603245 United States temp number">
  <div class="number-boxes-item d-flex flex-column">
    <img src="/assets/countries3/us.png" class="number-boxes-item-ico" alt="Flag Image">
    <div class="col-12">
      <div class="number-boxes-itemm-number" style="color:black">+13802603245</div>
    </div>
  </div>
</a>
<a style="text-decoration: none;" href="/sms/447538299689/" aria-label="+447538299689 United Kingdom receive sms online">
  <div class="number-boxes-item d-flex flex-column">
    <img src="/assets/countries3/gb.png" class="number-boxes-item-ico" alt="Flag Image">
    <div class="col-12">
      <div class="number-boxes-itemm-number" style="color:black">+447538299689</div>
    </div>
  </div>
</a>
<a style="text-decoration: none;" href="/sms/4915210947617/" aria-label="+4915210947617 Germany sms online">
  <div class="number-boxes-item d-flex flex-column">
    <img src="/assets/countries3/de.png" class="number-boxes-item-ico" alt="Flag Image">
    <div class="col-12">
      <div class="number-boxes-itemm-number" style="color:black">+4915210947617</div>
    </div>
  </div>
</a>
"""

INBOX_HTML = """
<div class="row message_details" style="margin: 20px 0 !important;">
  <div class="col-md-6 msgg"><label>Message</label><br><span>Your Telegram code is <span class="btn22cp1" data-clipboard-text="73652"><b>73652</b></span></span></div>
  <div class="col-md-3 senderr"><label>Sender</label><br><a href="/receive-sms-from-Telegram/">Telegram</a></div>
  <div class="col-md-3 time"><label>Time</label><br>2 minutes ago</div>
</div></div>
<div class="row message_details" style="margin: 20px 0 !important;">
  <div class="col-md-6 msgg"><label>Message</label><br><span>Your verification code is <span class="btn22cp1" data-clipboard-text="984321"><b>984321</b></span></span></div>
  <div class="col-md-3 senderr"><label>Sender</label><br><a href="/receive-sms-from-14155551234/">14155551234</a></div>
  <div class="col-md-3 time"><label>Time</label><br>15 minutes ago</div>
</div></div>
<div class="row message_details" style="margin: 20px 0 !important;">
  <div class="col-md-6 msgg"><label>Message</label><br><span>G-<span class="btn22cp1" data-clipboard-text="482917"><b>482917</b></span> is your verification code.</span></div>
  <div class="col-md-3 senderr"><label>Sender</label><br><a href="/receive-sms-from-Google/">Google</a></div>
  <div class="col-md-3 time"><label>Time</label><br>1 hour ago</div>
</div></div>
"""


@pytest.fixture
def toolset() -> PhoneVerification:
    return PhoneVerification()


# ── Tool discovery ───────────────────────────────────────────────────


class TestToolDiscovery:
    def test_tools_discovered(self, toolset: PhoneVerification) -> None:
        names = {tool.name for tool in toolset.get_tools()}
        assert names == {
            "list_free_phone_numbers",
            "read_phone_inbox",
            "request_private_number",
            "poll_private_number",
        }


# ── Helper functions ─────────────────────────────────────────────────


class TestHelpers:
    def test_extract_codes_basic(self) -> None:
        assert _extract_codes("Code 493812 and backup 9931", r"\b\d{4,8}\b") == [
            "493812",
            "9931",
        ]

    def test_extract_codes_dedup(self) -> None:
        assert _extract_codes("Code 1234 repeat 1234 new 5678", r"\b\d{4}\b") == [
            "1234",
            "5678",
        ]

    def test_html_to_text(self) -> None:
        result = _html_to_text("<p>Telegram code: <b>75363</b></p>")
        assert "75363" in result
        assert "<" not in result

    def test_html_to_text_strips_scripts(self) -> None:
        html = "<script>alert('xss')</script><p>Code: 12345</p>"
        result = _html_to_text(html)
        assert "alert" not in result
        assert "12345" in result


# ── HTML parsers ─────────────────────────────────────────────────────


class TestParseNumbers:
    def test_parses_homepage(self) -> None:
        numbers = _parse_numbers_from_html(HOMEPAGE_HTML)
        assert len(numbers) == 3

        us = numbers[0]
        assert us["digits"] == "13802603245"
        assert us["country"] == "United States"
        assert "receive-smss.com/sms/13802603245" in us["inbox_url"]

        uk = numbers[1]
        assert uk["digits"] == "447538299689"
        assert uk["country"] == "United Kingdom"

    def test_deduplicates(self) -> None:
        doubled = HOMEPAGE_HTML + HOMEPAGE_HTML
        numbers = _parse_numbers_from_html(doubled)
        assert len(numbers) == 3

    def test_empty_html(self) -> None:
        assert _parse_numbers_from_html("<html><body>nothing</body></html>") == []


class TestParseMessages:
    def test_parses_inbox(self) -> None:
        messages = _parse_messages_from_html(INBOX_HTML)
        assert len(messages) == 3
        assert messages[0]["sender"] == "Telegram"
        assert "73652" in messages[0]["body"]
        assert messages[0]["time"] == "2 minutes ago"

    def test_skips_empty_body(self) -> None:
        html = """
        <div class="row message_details">
          <div class="col-md-6 msgg"><label>Message</label><br><span></span></div>
          <div class="col-md-3 senderr"><label>Sender</label><br><a>Empty</a></div>
          <div class="col-md-3 time"><label>Time</label><br>1m ago</div>
        </div></div>
        <div class="row message_details">
          <div class="col-md-6 msgg"><label>Message</label><br><span>Code 1234</span></div>
          <div class="col-md-3 senderr"><label>Sender</label><br><a>Test</a></div>
          <div class="col-md-3 time"><label>Time</label><br>2m ago</div>
        </div></div>
        """
        messages = _parse_messages_from_html(html)
        assert len(messages) == 1
        assert messages[0]["sender"] == "Test"


# ── Free number tools ────────────────────────────────────────────────


class TestListFreeNumbers:
    @pytest.mark.asyncio
    async def test_list_all(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = HOMEPAGE_HTML
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.list_free_phone_numbers("all")
        assert "13802603245" in result
        assert "447538299689" in result
        assert "United States" in result

    @pytest.mark.asyncio
    async def test_filter_by_country(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = HOMEPAGE_HTML
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.list_free_phone_numbers("Germany")
        assert "4915210947617" in result
        assert "13802603245" not in result

    @pytest.mark.asyncio
    async def test_no_match_country(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = HOMEPAGE_HTML
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.list_free_phone_numbers("Japan")
        assert "No numbers found" in result


class TestReadPhoneInbox:
    @pytest.mark.asyncio
    async def test_read_by_number(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = INBOX_HTML
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.read_phone_inbox("13802603245")
        parsed = json.loads(result)
        assert len(parsed["messages"]) == 3
        assert "73652" in parsed["codes"]
        assert "984321" in parsed["codes"]
        assert "482917" in parsed["codes"]

    @pytest.mark.asyncio
    async def test_sender_filter(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = INBOX_HTML
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.read_phone_inbox("13802603245", sender_filter="Telegram")
        parsed = json.loads(result)
        assert len(parsed["messages"]) == 1
        assert "73652" in parsed["codes"]

    @pytest.mark.asyncio
    async def test_accepts_full_url(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = INBOX_HTML
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.read_phone_inbox("https://receive-smss.com/sms/13802603245/")
        mock_client.get.assert_called_with("https://receive-smss.com/sms/13802603245/")
        parsed = json.loads(result)
        assert len(parsed["messages"]) == 3


# ── Paid API tools ───────────────────────────────────────────────────


class TestPrivateNumber:
    @pytest.mark.asyncio
    async def test_request_parses_access_number(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = "ACCESS_NUMBER:12345:15551234567"
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.request_private_number(
            "https://api.example.test/handler_api.php", "key", "tg"
        )
        parsed = json.loads(result)
        assert parsed["request_id"] == "12345"
        assert parsed["phone_number"] == "15551234567"

    @pytest.mark.asyncio
    async def test_request_returns_error_on_bad_response(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = "NO_NUMBERS"
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.request_private_number(
            "https://api.example.test/handler_api.php", "key", "tg"
        )
        assert "NO_NUMBERS" in result

    @pytest.mark.asyncio
    async def test_request_handles_malformed_response(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = "ACCESS_NUMBER:incomplete"
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.request_private_number(
            "https://api.example.test/handler_api.php", "key", "tg"
        )
        assert "Error" in result or "Unexpected" in result


class TestPollPrivateNumber:
    @pytest.mark.asyncio
    async def test_poll_extracts_code(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = "STATUS_OK:Your verification code is 493812"
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.poll_private_number(
            "https://api.example.test/handler_api.php", "key", "12345"
        )
        parsed = json.loads(result)
        assert parsed["codes"] == ["493812"]

    @pytest.mark.asyncio
    async def test_poll_wait_status(self, toolset: PhoneVerification) -> None:
        mock_resp = AsyncMock()
        mock_resp.text = "STATUS_WAIT_CODE"
        mock_resp.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        toolset._http = mock_client

        result = await toolset.poll_private_number(
            "https://api.example.test/handler_api.php", "key", "12345"
        )
        assert "Waiting" in result
