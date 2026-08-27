"""Tests for the wrangler OAST toolset."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# The shared conftest.py stub (dreadnode.agents.tools) is installed before
# this module loads, so the toolset imports cleanly without the real SDK.

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "wrangler.py"
SPEC = importlib.util.spec_from_file_location("wrangler_tool", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

Wrangler = MODULE.Wrangler

AUTH_ENV = {
    "CLOUDFLARE_API_TOKEN": "test-token",
    "CLOUDFLARE_ACCOUNT_ID": "test-account",
}


def _mock_process(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> MagicMock:
    """Create a mock asyncio subprocess."""
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout.encode(), stderr.encode()))
    proc.returncode = returncode
    proc.kill = MagicMock()
    return proc


def _patched_env(env: dict[str, str] | None = None):
    """Patch the environment, keeping PATH so shutil.which still works."""
    return patch.dict(os.environ, env if env is not None else {}, clear=False)


@pytest.fixture
def toolset() -> Wrangler:
    with patch.dict(os.environ, AUTH_ENV, clear=False):
        yield Wrangler()


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------


class TestToolDiscovery:
    def test_tools_discovered(self, toolset: Wrangler) -> None:
        names = {tool.name for tool in toolset.get_tools()}
        assert names == {
            "wrangler_status",
            "wrangler_deploy",
            "wrangler_tail",
            "wrangler_list",
            "wrangler_delete",
        }


# ---------------------------------------------------------------------------
# Env / auth resolution
# ---------------------------------------------------------------------------


class TestAuthResolution:
    def test_auth_error_missing_token(self) -> None:
        with patch.dict(os.environ, {"CLOUDFLARE_ACCOUNT_ID": "acct"}, clear=False):
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)
            os.environ.pop("CF_API_TOKEN", None)
            err = MODULE._auth_error()
        assert err is not None
        assert "CLOUDFLARE_API_TOKEN" in err

    def test_auth_error_missing_account(self) -> None:
        with patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "tok"}, clear=False):
            os.environ.pop("CLOUDFLARE_ACCOUNT_ID", None)
            os.environ.pop("CF_ACCOUNT_ID", None)
            err = MODULE._auth_error()
        assert err is not None
        assert "CLOUDFLARE_ACCOUNT_ID" in err

    def test_auth_ok_with_native_vars(self) -> None:
        with patch.dict(os.environ, AUTH_ENV, clear=False):
            os.environ.pop("CF_API_TOKEN", None)
            os.environ.pop("CF_ACCOUNT_ID", None)
            assert MODULE._auth_error() is None

    def test_cf_aliases_accepted(self) -> None:
        # The flareprox tool in this capability uses CF_* env vars; one
        # credential pair should drive both tools.
        with patch.dict(
            os.environ,
            {"CF_API_TOKEN": "cf-tok", "CF_ACCOUNT_ID": "cf-acct"},
            clear=False,
        ):
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)
            os.environ.pop("CLOUDFLARE_ACCOUNT_ID", None)
            resolved = MODULE._resolve_env()
            auth_err = MODULE._auth_error()
        assert resolved == {
            "CLOUDFLARE_API_TOKEN": "cf-tok",
            "CLOUDFLARE_ACCOUNT_ID": "cf-acct",
        }
        assert auth_err is None

    def test_native_vars_take_precedence(self) -> None:
        with patch.dict(
            os.environ,
            {
                "CLOUDFLARE_API_TOKEN": "native",
                "CLOUDFLARE_ACCOUNT_ID": "native-acct",
                "CF_API_TOKEN": "alias",
                "CF_ACCOUNT_ID": "alias-acct",
            },
            clear=False,
        ):
            resolved = MODULE._resolve_env()
        assert resolved["CLOUDFLARE_API_TOKEN"] == "native"
        assert resolved["CLOUDFLARE_ACCOUNT_ID"] == "native-acct"


# ---------------------------------------------------------------------------
# Name validation / generation
# ---------------------------------------------------------------------------


class TestNames:
    def test_generate_name(self) -> None:
        name = MODULE._generate_name()
        assert name.startswith("dn-oast-")
        assert len(name) == len("dn-oast-") + 8

    def test_generate_name_valid(self) -> None:
        # Auto-generated names must always pass wrangler's own validation.
        assert MODULE._validate_name(MODULE._generate_name()) is None

    def test_validate_name_accepts_valid(self) -> None:
        for name in ("dn-oast-abc123", "worker", "a", "a_b-c1"):
            assert MODULE._validate_name(name) is None

    def test_validate_name_rejects_empty(self) -> None:
        assert MODULE._validate_name("") is not None

    def test_validate_name_rejects_uppercase(self) -> None:
        assert MODULE._validate_name("dn-oast-ABC") is not None

    def test_validate_name_rejects_leading_dash(self) -> None:
        assert MODULE._validate_name("-dn-oast") is not None

    def test_validate_name_rejects_special_chars(self) -> None:
        # Also covers toml injection attempts: quotes, newlines, equals.
        for name in ('dn-oast" main="evil', "dn-oast\nx=1", "dn oast", "dn;oast"):
            assert MODULE._validate_name(name) is not None


# ---------------------------------------------------------------------------
# URL extraction / tail parsing
# ---------------------------------------------------------------------------


class TestOutputParsing:
    def test_ansi_stripped(self) -> None:
        # wrangler colorizes even when piped; the tool must hand the LLM
        # clean text.
        colored = (
            "\x1b[31m\x1b[41;31m[\x1b[41;97mERROR\x1b[41;31m]\x1b[0m request failed"
        )
        assert MODULE._clean(colored) == "[ERROR] request failed"

    def test_extract_worker_url(self) -> None:
        output = (
            "⛅️ wrangler 4.127.0\n"
            "───────────────\n"
            "Uploaded dn-oast-test123 (1.2 sec)\n"
            "Deployed dn-oast-test123 triggers (0.8 sec)\n"
            "  https://dn-oast-test123.myaccount.workers.dev\n"
        )
        assert (
            MODULE._extract_worker_url(output)
            == "https://dn-oast-test123.myaccount.workers.dev"
        )

    def test_extract_worker_url_absent(self) -> None:
        assert MODULE._extract_worker_url("no url here") == ""

    def test_extract_worker_url_ignores_dashboard_links(self) -> None:
        output = (
            "Deployed dn-oast-x triggers\n"
            "  https://dash.cloudflare.com/acct/workers/services/view/dn-oast-x\n"
            "  https://dn-oast-x.sub.workers.dev\n"
        )
        assert MODULE._extract_worker_url(output).endswith("workers.dev")

    def test_format_tail_console_logs(self) -> None:
        event = {
            "outcome": "ok",
            "logs": [
                {
                    "message": ['{"method":"GET","url":"https://w.dev/probe"}'],
                    "level": "log",
                }
            ],
        }
        formatted = MODULE._format_tail_output(json.dumps(event))
        assert "probe" in formatted

    def test_format_tail_request_events(self) -> None:
        # Custom workers that never console.log still surface the request.
        event = {
            "outcome": "ok",
            "logs": [],
            "event": {"request": {"method": "GET", "url": "https://w.dev/collect?x=1"}},
        }
        formatted = MODULE._format_tail_output(json.dumps(event))
        assert "GET https://w.dev/collect?x=1" in formatted

    def test_format_tail_exceptions(self) -> None:
        event = {
            "outcome": "exception",
            "logs": [],
            "exceptions": [{"name": "Error", "message": "boom"}],
        }
        formatted = MODULE._format_tail_output(json.dumps(event))
        assert "Error" in formatted and "boom" in formatted

    def test_format_tail_passthrough_non_json(self) -> None:
        formatted = MODULE._format_tail_output("plain text output\n")
        assert "plain text output" in formatted

    def test_format_tail_multiple_events(self) -> None:
        events = "\n".join(
            json.dumps(
                {
                    "outcome": "ok",
                    "logs": [{"message": [f"event-{i}"], "level": "log"}],
                }
            )
            for i in range(3)
        )
        formatted = MODULE._format_tail_output(events)
        for i in range(3):
            assert f"event-{i}" in formatted


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


class TestTemplates:
    def test_templates_valid(self) -> None:
        for key, code in MODULE._TEMPLATES.items():
            assert code.strip(), f"Template '{key}' is empty"
            assert "export default" in code, f"Template '{key}' missing export"


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class TestStatus:
    @pytest.mark.asyncio
    async def test_missing_binary(self, toolset: Wrangler) -> None:
        with patch("shutil.which", return_value=None):
            result = await toolset.status()
        assert "not found" in result.lower()

    @pytest.mark.asyncio
    async def test_missing_token(self) -> None:
        with patch.dict(os.environ, {"CLOUDFLARE_ACCOUNT_ID": "acct"}, clear=False):
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)
            os.environ.pop("CF_API_TOKEN", None)
            result = await Wrangler().status()
        assert "CLOUDFLARE_API_TOKEN" in result

    @pytest.mark.asyncio
    async def test_missing_account(self) -> None:
        with patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "tok"}, clear=False):
            os.environ.pop("CLOUDFLARE_ACCOUNT_ID", None)
            os.environ.pop("CF_ACCOUNT_ID", None)
            result = await Wrangler().status()
        assert "CLOUDFLARE_ACCOUNT_ID" in result

    @pytest.mark.asyncio
    async def test_whoami_failure(self, toolset: Wrangler) -> None:
        # whoami --json exits non-zero on an invalid token (verified against
        # wrangler 4.x); status must surface that instead of claiming success.
        mock_proc = _mock_process(stderr="Invalid request headers", returncode=1)
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.status()
        assert "token was rejected" in result.lower()

    @pytest.mark.asyncio
    async def test_whoami_not_logged_in(self, toolset: Wrangler) -> None:
        # {"loggedIn": false} with exit 1 — report it as an error.
        mock_proc = _mock_process(stdout='{"loggedIn": false}', returncode=1)
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.status()
        assert "not logged in" in result.lower()

    @pytest.mark.asyncio
    async def test_success(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(
            stdout=json.dumps({"loggedIn": True, "account": {"name": "test"}})
        )
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.status()
        assert "operational" in result.lower()

    @pytest.mark.asyncio
    async def test_uses_json_flag(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout='{"loggedIn": true}')
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            await toolset.status()
        args = mock_exec.call_args[0]
        assert "whoami" in args
        assert "--json" in args


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------


DEPLOY_OUTPUT = (
    "⛅️ wrangler 4.127.0\n"
    "Uploaded dn-oast-test123 (1.2 sec)\n"
    "Deployed dn-oast-test123 triggers (0.8 sec)\n"
    "  https://dn-oast-test123.myaccount.workers.dev\n"
)


class TestDeploy:
    @pytest.mark.asyncio
    async def test_missing_auth(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)
            os.environ.pop("CF_API_TOKEN", None)
            result = await Wrangler().deploy()
        assert "CLOUDFLARE_API_TOKEN" in result

    @pytest.mark.asyncio
    async def test_unknown_template(self, toolset: Wrangler) -> None:
        result = await toolset.deploy(template="nonexistent")
        assert "Unknown template" in result

    @pytest.mark.asyncio
    async def test_custom_without_code(self, toolset: Wrangler) -> None:
        result = await toolset.deploy(template="custom")
        assert "worker_code is required" in result

    @pytest.mark.asyncio
    async def test_invalid_name_rejected(self, toolset: Wrangler) -> None:
        # An invalid name must fail before any subprocess runs.
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            result = await toolset.deploy(template="callback", name="dn-oast-UPPER")
        mock_exec.assert_not_called()
        assert "Invalid worker name" in result

    @pytest.mark.asyncio
    async def test_callback_deploy(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout=DEPLOY_OUTPUT)
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.deploy(template="callback", name="dn-oast-test123")
        assert "deployed successfully" in result.lower()
        assert "https://dn-oast-test123.myaccount.workers.dev" in result

    @pytest.mark.asyncio
    async def test_deploy_failure(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(
            stderr="A request to the Cloudflare API failed", returncode=1
        )
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.deploy(template="callback", name="dn-oast-test123")
        assert result.startswith("Error")

    @pytest.mark.asyncio
    async def test_custom_deploy(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout=DEPLOY_OUTPUT)
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.deploy(
                template="custom",
                name="dn-oast-test123",
                worker_code='export default { fetch() { return new Response("OK"); } };',
            )
        assert "deployed successfully" in result.lower()

    @pytest.mark.asyncio
    async def test_redirect_target_passed_as_var(self, toolset: Wrangler) -> None:
        # The redirect target must travel via --var, never into wrangler.toml
        # where a crafted value could break out of the quoted string.
        mock_proc = _mock_process(stdout=DEPLOY_OUTPUT)
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            await toolset.deploy(
                template="redirect",
                name="dn-oast-redir",
                redirect_target="http://169.254.169.254/latest/meta-data/",
            )
        args = mock_exec.call_args[0]
        assert "--var=REDIRECT_TARGET:http://169.254.169.254/latest/meta-data/" in args

    @pytest.mark.asyncio
    async def test_redirect_target_requires_scheme(self, toolset: Wrangler) -> None:
        result = await toolset.deploy(
            template="redirect",
            name="dn-oast-redir",
            redirect_target="169.254.169.254/",
        )
        assert "full URL including scheme" in result

    @pytest.mark.asyncio
    async def test_deploy_writes_config(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout=DEPLOY_OUTPUT)
        written: dict[str, str] = {}
        original_write = Path.write_text

        def capture_write(self: Path, data: str, **_: object) -> int:
            written[self.name] = data
            return len(data)

        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch.object(Path, "write_text", capture_write),
        ):
            await toolset.deploy(template="callback", name="dn-oast-test123")

        toml = written["wrangler.toml"]
        assert 'name = "dn-oast-test123"' in toml
        assert 'main = "worker.js"' in toml
        assert "compatibility_date" in toml
        # account_id deliberately absent: it comes from the env var contract.
        assert "account_id" not in toml
        assert "export default" in written["worker.js"]

    @pytest.mark.asyncio
    async def test_auto_generated_name(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout=DEPLOY_OUTPUT)
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.deploy(template="callback")
        assert "deployed successfully" in result.lower()
        assert "dn-oast-" in result

    @pytest.mark.asyncio
    async def test_no_url_reported(self, toolset: Wrangler) -> None:
        # workers.dev disabled for the account: deploy succeeds but no URL.
        mock_proc = _mock_process(stdout="Deployed dn-oast-x triggers (0.5 sec)")
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.deploy(template="callback", name="dn-oast-x")
        assert "no workers.dev URL" in result

    @pytest.mark.asyncio
    async def test_temp_dir_cleaned_up(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout=DEPLOY_OUTPUT)
        rmtree_calls: list[str] = []
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch(
                "shutil.rmtree", side_effect=lambda p, **_: rmtree_calls.append(str(p))
            ),
        ):
            await toolset.deploy(template="callback", name="dn-oast-test123")
        assert len(rmtree_calls) == 1
        assert "dn-wrangler-" in rmtree_calls[0]


# ---------------------------------------------------------------------------
# Tail
# ---------------------------------------------------------------------------


class TestTail:
    @pytest.mark.asyncio
    async def test_missing_auth(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)
            os.environ.pop("CF_API_TOKEN", None)
            result = await Wrangler().tail(name="test")
        assert "CLOUDFLARE_API_TOKEN" in result

    @pytest.mark.asyncio
    async def test_empty_name(self, toolset: Wrangler) -> None:
        result = await toolset.tail(name="")
        assert "required" in result.lower()

    @pytest.mark.asyncio
    async def test_invalid_name(self, toolset: Wrangler) -> None:
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            result = await toolset.tail(name="UPPER")
        mock_exec.assert_not_called()
        assert "Invalid worker name" in result

    @pytest.mark.asyncio
    async def test_no_events(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout="")
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.tail(name="dn-oast-test", seconds=1)
        assert "no events" in result.lower()

    @pytest.mark.asyncio
    async def test_events_captured(self, toolset: Wrangler) -> None:
        event = {
            "outcome": "ok",
            "logs": [{"message": ['{"method":"GET","url":"https://w.dev/probe"}']}],
        }
        mock_proc = _mock_process(stdout=json.dumps(event))
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.tail(name="dn-oast-test", seconds=1)
        assert "probe" in result

    @pytest.mark.asyncio
    async def test_tail_error(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(
            stderr="A request to the Cloudflare API failed", returncode=1
        )
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.tail(name="dn-oast-test", seconds=1)
        assert result.startswith("Error")

    @pytest.mark.asyncio
    async def test_seconds_clamped_and_timed_out_is_stop(
        self, toolset: Wrangler
    ) -> None:
        # 999s would stream for minutes; it must be clamped to 60 (+10s
        # overhead). The timeout kill is the designed stop mechanism, not an
        # error: captured events still parse, and a bare timeout with no
        # events is a clean "no events" result.
        event = {
            "outcome": "ok",
            "logs": [{"message": ["clamped-event"], "level": "log"}],
        }
        mock_proc = _mock_process(stdout=json.dumps(event))

        wait_for_calls = {"n": 0}

        async def timeout_once(coro, timeout=None):
            # First wait_for (the stream window) times out; the second
            # (reaping the killed process) succeeds.
            wait_for_calls["n"] += 1
            if wait_for_calls["n"] == 1:
                raise asyncio.TimeoutError
            return await coro

        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("asyncio.wait_for", side_effect=timeout_once),
        ):
            result = await toolset.tail(name="dn-oast-test", seconds=999)
        assert "clamped-event" in result

    @pytest.mark.asyncio
    async def test_timed_out_no_events(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout="")

        wait_for_calls = {"n": 0}

        async def timeout_once(coro, timeout=None):
            wait_for_calls["n"] += 1
            if wait_for_calls["n"] == 1:
                raise asyncio.TimeoutError
            return await coro

        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("asyncio.wait_for", side_effect=timeout_once),
        ):
            result = await toolset.tail(name="dn-oast-test", seconds=5)
        assert "no events" in result.lower()


# ---------------------------------------------------------------------------
# List (Cloudflare REST API)
# ---------------------------------------------------------------------------


class TestList:
    @pytest.mark.asyncio
    async def test_missing_auth(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)
            os.environ.pop("CF_API_TOKEN", None)
            result = await Wrangler().list_workers()
        assert "CLOUDFLARE_API_TOKEN" in result

    @pytest.mark.asyncio
    async def test_list_success(self, toolset: Wrangler) -> None:
        body = {
            "success": True,
            "result": [
                {"id": "dn-oast-abc12345"},
                {"id": "other-worker"},
            ],
            "result_info": {
                "page": 1,
                "per_page": 2,
                "total_count": 2,
                "total_pages": 1,
            },
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = body
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
            result = await toolset.list_workers()
        assert "dn-oast-abc12345" in result
        assert "other-worker" in result
        assert "created by this toolset" in result

    @pytest.mark.asyncio
    async def test_list_paginates(self, toolset: Wrangler) -> None:
        # The scripts endpoint paginates; follow result_info until done.
        page1 = {
            "success": True,
            "result": [{"id": "dn-oast-a1"}],
            "result_info": {"page": 1, "per_page": 1, "total_count": 2},
        }
        page2 = {
            "success": True,
            "result": [{"id": "dn-oast-a2"}],
            "result_info": {"page": 2, "per_page": 1, "total_count": 2},
        }
        mock_response1 = MagicMock()
        mock_response1.status_code = 200
        mock_response1.json.return_value = page1
        mock_response2 = MagicMock()
        mock_response2.status_code = 200
        mock_response2.json.return_value = page2
        with patch(
            "httpx.AsyncClient.get",
            new=AsyncMock(side_effect=[mock_response1, mock_response2]),
        ):
            result = await toolset.list_workers()
        assert "dn-oast-a1" in result
        assert "dn-oast-a2" in result

    @pytest.mark.asyncio
    async def test_list_empty(self, toolset: Wrangler) -> None:
        body = {"success": True, "result": []}
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = body
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
            result = await toolset.list_workers()
        assert "No workers" in result

    @pytest.mark.asyncio
    async def test_list_api_error(self, toolset: Wrangler) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "forbidden"
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
            result = await toolset.list_workers()
        assert "403" in result

    @pytest.mark.asyncio
    async def test_list_network_error(self, toolset: Wrangler) -> None:
        import httpx as _httpx

        with patch(
            "httpx.AsyncClient.get",
            new=AsyncMock(side_effect=_httpx.ConnectError("refused")),
        ):
            result = await toolset.list_workers()
        assert "Error" in result


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


class TestDelete:
    @pytest.mark.asyncio
    async def test_missing_auth(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)
            os.environ.pop("CF_API_TOKEN", None)
            result = await Wrangler().delete(name="test")
        assert "CLOUDFLARE_API_TOKEN" in result

    @pytest.mark.asyncio
    async def test_empty_name(self, toolset: Wrangler) -> None:
        result = await toolset.delete(name="")
        assert "required" in result.lower()

    @pytest.mark.asyncio
    async def test_delete_success(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stdout="Successfully deleted dn-oast-test123")
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            result = await toolset.delete(name="dn-oast-test123")
        args = mock_exec.call_args[0]
        assert "delete" in args
        assert "dn-oast-test123" in args
        assert "--force" in args
        assert "deleted" in result.lower()

    @pytest.mark.asyncio
    async def test_delete_failure(self, toolset: Wrangler) -> None:
        mock_proc = _mock_process(stderr="not found", returncode=1)
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.delete(name="dn-oast-missing")
        assert result.startswith("Error")


# ---------------------------------------------------------------------------
# _run helper
# ---------------------------------------------------------------------------


class TestRunHelper:
    @pytest.mark.asyncio
    async def test_missing_binary_raises(self) -> None:
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError):
                await MODULE._run(["whoami"])

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self) -> None:
        mock_proc = _mock_process(stdout="")
        wait_for_calls = {"n": 0}

        async def timeout_once(coro, timeout=None):
            wait_for_calls["n"] += 1
            if wait_for_calls["n"] == 1:
                raise asyncio.TimeoutError
            return await coro

        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("asyncio.wait_for", side_effect=timeout_once),
        ):
            returncode, stdout, stderr, timed_out = await MODULE._run(
                ["tail", "x"], timeout=1
            )
        mock_proc.kill.assert_called_once()
        assert timed_out is True

    @pytest.mark.asyncio
    async def test_stdout_stderr_separate(self) -> None:
        mock_proc = _mock_process(stdout="events", stderr="banner")
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            returncode, stdout, stderr, timed_out = await MODULE._run(["tail", "x"])
        assert stdout == "events"
        assert stderr == "banner"
        assert timed_out is False

    @pytest.mark.asyncio
    async def test_telemetry_disabled(self) -> None:
        # The runtime sandbox must not emit wrangler telemetry: set the env
        # var on every subprocess invocation.
        mock_proc = _mock_process(stdout="ok")
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            await MODULE._run(["whoami"])
        env = mock_exec.call_args.kwargs["env"]
        assert env["WRANGLER_SEND_METRICS"] == "false"

    @pytest.mark.asyncio
    async def test_cf_alias_mapped_to_native_env(self) -> None:
        # When only CF_* vars are set, wrangler still sees CLOUDFLARE_*.
        mock_proc = _mock_process(stdout="ok")
        with (
            patch.dict(
                os.environ,
                {"CF_API_TOKEN": "cf-tok", "CF_ACCOUNT_ID": "cf-acct"},
                clear=False,
            ),
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)
            os.environ.pop("CLOUDFLARE_ACCOUNT_ID", None)
            try:
                await MODULE._run(["whoami"])
            finally:
                os.environ.pop("CF_API_TOKEN", None)
                os.environ.pop("CF_ACCOUNT_ID", None)
        env = mock_exec.call_args.kwargs["env"]
        assert env["CLOUDFLARE_API_TOKEN"] == "cf-tok"
        assert env["CLOUDFLARE_ACCOUNT_ID"] == "cf-acct"

    @pytest.mark.asyncio
    async def test_output_truncated(self) -> None:
        mock_proc = _mock_process(stdout="x" * 100_000)
        with (
            patch("shutil.which", return_value="/usr/local/bin/wrangler"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            _, stdout, stderr, _ = await MODULE._run(["whoami"])
        assert len(stdout) <= MODULE._MAX_OUTPUT
