#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
# ]
# ///
"""agent-browser MCP server.

Thin Python MCP wrapper around Vercel's agent-browser CLI. This intentionally
does not vendor, install, or reimplement the TypeScript SDK. It delegates to an
existing host command:

  1. AGENT_BROWSER_COMMAND, if set (for example: "npx --yes agent-browser")
  2. agent-browser on PATH
  3. npx --yes agent-browser, if npx is on PATH

If none are available, tools return an actionable error.
"""

from __future__ import annotations

import asyncio
import html
import json
import os
import secrets
import shlex
import shutil
from typing import Annotated

from fastmcp import FastMCP

mcp = FastMCP("agent-browser")

MAX_OUTPUT_CHARS = int(os.environ.get("AGENT_BROWSER_MAX_OUTPUT_CHARS", "50000"))
DEFAULT_TIMEOUT = int(os.environ.get("AGENT_BROWSER_TIMEOUT", "60"))
_XSS_VERIFIER_SESSIONS: dict[str, dict[str, str]] = {}


def _drop_empty(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: cleaned
            for key, item in value.items()
            if (cleaned := _drop_empty(item)) not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [
            cleaned
            for item in value
            if (cleaned := _drop_empty(item)) not in (None, "", [], {})
        ]
    return value


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]..."


def _resolve_command() -> list[str] | None:
    configured = os.environ.get("AGENT_BROWSER_COMMAND")
    if configured:
        parts = shlex.split(configured)
        if parts and shutil.which(parts[0]):
            return parts
        return None

    if shutil.which("agent-browser"):
        return ["agent-browser"]

    if shutil.which("npx"):
        return ["npx", "--yes", "agent-browser"]

    return None


def _missing_dependency_message() -> str:
    return (
        "Error: agent-browser is unavailable. Install it with one of:\n"
        "  npm i -g agent-browser\n"
        "  brew install agent-browser\n"
        "  cargo install agent-browser\n"
        "Then run: agent-browser install\n"
        "Alternatively set AGENT_BROWSER_COMMAND, for example: "
        "AGENT_BROWSER_COMMAND='npx --yes agent-browser'"
    )


def _raise_agent_browser_error(result: str) -> None:
    if result.startswith("Error:") or result.startswith("Error (exit "):
        raise RuntimeError(result)


async def _eval_browser_json(
    js: str,
    *,
    global_args: list[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    result = await _run_agent_browser(
        ["eval", js],
        global_args=global_args,
        timeout=timeout,
    )
    _raise_agent_browser_error(result)
    try:
        parsed = json.loads(result)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"agent-browser eval returned non-JSON output: {result[:500]}"
        ) from exc
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"agent-browser eval returned a JSON string, but it did not contain a JSON object: {parsed[:500]}"
            ) from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("agent-browser eval returned JSON, but not an object")
    return parsed


def _build_xss_canary_script(token: str) -> str:
    token_js = json.dumps(token)
    return f"""
(function() {{
  var token = {token_js};
  var previous = window.__dreadnodeXssVerifier;
  if (previous && previous.token === token && previous.armed) {{
    return JSON.stringify({{status: "already_armed", token: token, url: location.href}});
  }}
  if (previous && typeof previous.restore === "function") {{
    previous.restore();
  }}

  var state = {{
    token: token,
    armed: true,
    armedAt: new Date().toISOString(),
    url: location.href,
    events: [],
    csp: []
  }};

  function toText(value) {{
    try {{
      if (typeof value === "string") return value;
      return JSON.stringify(value);
    }} catch (e) {{
      return String(value);
    }}
  }}

  function record(channel, value, detail) {{
    var text = toText(value);
    state.events.push({{
      channel: channel,
      value: text.slice(0, 500),
      matched: text.indexOf(token) !== -1,
      detail: detail || {{}},
      url: location.href,
      at: new Date().toISOString()
    }});
    if (state.events.length > 50) state.events.shift();
  }}

  window.__dreadnodeXssProof = function(value, detail) {{
    record("proof-function", value, detail || {{}});
    return "recorded";
  }};

  var originalAlert = window.alert;
  var originalConfirm = window.confirm;
  var originalPrompt = window.prompt;
  var originalConsole = {{}};
  window.alert = function(message) {{ record("alert", message); return undefined; }};
  window.confirm = function(message) {{ record("confirm", message); return false; }};
  window.prompt = function(message, defaultValue) {{
    record("prompt", message, {{defaultValue: toText(defaultValue).slice(0, 100)}});
    return null;
  }};

  ["log", "info", "warn", "error"].forEach(function(level) {{
    var original = console[level];
    originalConsole[level] = original;
    console[level] = function() {{
      var args = Array.prototype.slice.call(arguments);
      var text = args.map(toText).join(" ");
      if (text.indexOf(token) !== -1) record("console." + level, text);
      if (typeof original === "function") return original.apply(console, args);
    }};
  }});

  window.addEventListener("message", function(event) {{
    var text = toText(event.data);
    if (text.indexOf(token) !== -1) {{
      record("postMessage", text, {{origin: event.origin || ""}});
    }}
  }});

  window.addEventListener("securitypolicyviolation", function(event) {{
    state.csp.push({{
      violatedDirective: event.violatedDirective || "",
      blockedURI: event.blockedURI || "",
      sample: event.sample || "",
      at: new Date().toISOString()
    }});
    if (state.csp.length > 20) state.csp.shift();
  }});

  try {{
    new MutationObserver(function(mutations) {{
      mutations.forEach(function(mutation) {{
        mutation.addedNodes.forEach(function(node) {{
          if (!node || node.nodeType !== 1) return;
          var tag = String(node.tagName || "").toLowerCase();
          if (tag === "script") {{
            record("script-node", (node.src || "") + " " + (node.textContent || "").slice(0, 500));
          }}
        }});
      }});
    }}).observe(document.documentElement, {{childList: true, subtree: true}});
  }} catch (e) {{
    record("observer-error", String(e));
  }}

  state.restore = function() {{
    window.alert = originalAlert;
    window.confirm = originalConfirm;
    window.prompt = originalPrompt;
    Object.keys(originalConsole).forEach(function(level) {{
      console[level] = originalConsole[level];
    }});
  }};
  window.__dreadnodeXssVerifier = state;
  return JSON.stringify({{status: "armed", token: token, url: location.href, armedAt: state.armedAt}});
}})()
"""


def _read_xss_canary_script() -> str:
    return """
(function() {
  var state = window.__dreadnodeXssVerifier;
  if (!state || !state.armed) return JSON.stringify({armed: false, url: location.href});
  return JSON.stringify({
    armed: true,
    token: state.token,
    armedAt: state.armedAt,
    url: location.href,
    events: state.events || [],
    csp: state.csp || []
  });
})()
"""


def _reset_xss_canary_script() -> str:
    return """
(function() {
  var state = window.__dreadnodeXssVerifier;
  if (state && typeof state.restore === "function") state.restore();
  delete window.__dreadnodeXssVerifier;
  delete window.__dreadnodeXssProof;
  return JSON.stringify({status: "reset", url: location.href});
})()
"""


def _xss_payload_examples(token: str) -> dict[str, str]:
    proof_call = (
        f'window.__dreadnodeXssProof({json.dumps(token)},{{source:"xss-payload"}})'
    )
    attr_proof = html.escape(proof_call, quote=True)
    dialog_value = "__DN_XSS_PROOF__:" + token
    return {
        "script_tag": f"<script>{proof_call}</script>",
        "event_handler": f"<img src=x onerror='{attr_proof}'>",
        "svg_onload": f"<svg onload='{attr_proof}'></svg>",
        "javascript_url": f"javascript:{proof_call}",
        "dialog": f"<script>alert({json.dumps(dialog_value)})</script>",
        "console": f"<script>console.log({json.dumps(dialog_value)})</script>",
        "post_message": f"<script>postMessage({json.dumps(dialog_value)}, '*')</script>",
    }


def _xss_verdict(state: dict, expected_token: str) -> dict:
    if not state.get("armed"):
        return {
            "verified": False,
            "verdict": "CANARY_LOST",
            "confidence": "none",
            "reason": "The verifier canary is not present in the current page. Re-arm it after navigation on the page where the payload renders.",
            "url": state.get("url"),
        }

    observed_token = state.get("token")
    if observed_token != expected_token:
        return {
            "verified": False,
            "verdict": "TOKEN_MISMATCH",
            "confidence": "none",
            "reason": "The page contains a different verifier token than the token being checked.",
            "expected_token": expected_token,
            "observed_token": observed_token,
            "url": state.get("url"),
        }

    events = state.get("events", [])
    matched = [event for event in events if event.get("matched")]
    proof_events = [
        event
        for event in matched
        if event.get("channel")
        in {
            "proof-function",
            "alert",
            "confirm",
            "prompt",
            "console.log",
            "console.info",
            "console.warn",
            "console.error",
            "postMessage",
        }
    ]
    script_events = [
        event for event in matched if event.get("channel") == "script-node"
    ]

    if proof_events:
        return {
            "verified": True,
            "verdict": "CONFIRMED",
            "confidence": "high",
            "reason": "A payload-controlled proof token was observed from JavaScript running in the browser page context.",
            "url": state.get("url"),
            "evidence": proof_events[:10],
            "event_count": len(events),
            "csp": state.get("csp", []),
        }

    if script_events:
        return {
            "verified": False,
            "verdict": "PARTIAL",
            "confidence": "medium",
            "reason": "A script element containing the proof token was added to the DOM, but JavaScript execution did not return the token through an instrumented proof channel.",
            "url": state.get("url"),
            "evidence": script_events[:10],
            "event_count": len(events),
            "csp": state.get("csp", []),
        }

    return {
        "verified": False,
        "verdict": "NOT_DETECTED",
        "confidence": "none",
        "reason": "No payload-controlled proof token was observed. The payload may not have executed, may have been sanitized, may need interaction, or may have rendered after navigation.",
        "url": state.get("url"),
        "event_count": len(events),
        "csp": state.get("csp", []),
    }


async def _run_agent_browser(
    args: list[str],
    *,
    global_args: list[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    command = _resolve_command()
    if not command:
        return _missing_dependency_message()

    argv = command + (global_args or []) + args
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return f"Error: agent-browser command timed out after {timeout}s"

    out = stdout.decode(errors="replace")
    err = stderr.decode(errors="replace")
    text = out if not err else f"{out}\n{err}".strip()
    if proc.returncode != 0:
        return _truncate(f"Error (exit {proc.returncode}): {text}")
    return _truncate(text)


@mcp.tool
async def agent_browser_status() -> dict:
    """Report how the MCP would invoke agent-browser on this host."""
    command = _resolve_command()
    return {
        "available": command is not None,
        "command": command,
        "uses_npx_fallback": bool(command and command[0] == "npx"),
        "timeout_seconds": DEFAULT_TIMEOUT,
        "max_output_chars": MAX_OUTPUT_CHARS,
        "hint": None if command else _missing_dependency_message(),
    }


@mcp.tool
async def agent_browser_run(
    args: Annotated[
        list[str],
        "Raw agent-browser CLI arguments, excluding the binary name",
    ],
    global_args: Annotated[
        list[str] | None,
        "Optional global CLI flags placed before the subcommand, e.g. ['--session-name', 'app']",
    ] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Run any agent-browser command for advanced workflows."""
    if not args:
        return "Error: args must include an agent-browser subcommand."
    return await _run_agent_browser(args, global_args=global_args, timeout=timeout)


@mcp.tool
async def agent_browser_open(
    url: Annotated[str, "URL to navigate to"],
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Open a URL in agent-browser."""
    return await _run_agent_browser(
        ["open", url],
        global_args=global_args,
        timeout=timeout,
    )


@mcp.tool
async def agent_browser_snapshot(
    interactive: Annotated[bool, "Include interactive element refs like @e1"] = True,
    selector: Annotated[str | None, "Optional CSS selector scope"] = None,
    include_cursor: Annotated[bool, "Include cursor-interactive elements"] = False,
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Capture a text snapshot of the current page."""
    args = ["snapshot"]
    if interactive:
        args.append("-i")
    if include_cursor:
        args.append("-C")
    if selector:
        args.extend(["-s", selector])
    return await _run_agent_browser(args, global_args=global_args, timeout=timeout)


@mcp.tool
async def agent_browser_click(
    ref: Annotated[str, "Element ref or selector to click, e.g. @e1"],
    new_tab: Annotated[bool, "Open clicked link in a new tab"] = False,
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Click an element by ref or selector."""
    args = ["click", ref]
    if new_tab:
        args.append("--new-tab")
    return await _run_agent_browser(args, global_args=global_args, timeout=timeout)


@mcp.tool
async def agent_browser_fill(
    ref: Annotated[str, "Input ref or selector, e.g. @e2"],
    text: Annotated[str, "Text to fill"],
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Clear and fill an input."""
    return await _run_agent_browser(
        ["fill", ref, text],
        global_args=global_args,
        timeout=timeout,
    )


@mcp.tool
async def agent_browser_type(
    ref: Annotated[str, "Input ref or selector, e.g. @e2"],
    text: Annotated[str, "Text to type without clearing"],
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Type text into an input without clearing it first."""
    return await _run_agent_browser(
        ["type", ref, text],
        global_args=global_args,
        timeout=timeout,
    )


@mcp.tool
async def agent_browser_press(
    key: Annotated[str, "Key to press, e.g. Enter or Escape"],
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Press a keyboard key."""
    return await _run_agent_browser(
        ["press", key], global_args=global_args, timeout=timeout
    )


@mcp.tool
async def agent_browser_wait(
    target: Annotated[
        str | None,
        "Element ref, selector, milliseconds, or omitted for load wait",
    ] = None,
    load: Annotated[str | None, "Load state, e.g. networkidle"] = None,
    url: Annotated[str | None, "URL glob to wait for"] = None,
    text: Annotated[str | None, "Text substring to wait for"] = None,
    state: Annotated[str | None, "Element state, e.g. hidden"] = None,
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Wait for a page, element, URL, text, or load state."""
    args = ["wait"]
    if target:
        args.append(target)
    if load:
        args.extend(["--load", load])
    if url:
        args.extend(["--url", url])
    if text:
        args.extend(["--text", text])
    if state:
        args.extend(["--state", state])
    return await _run_agent_browser(args, global_args=global_args, timeout=timeout)


@mcp.tool
async def agent_browser_get(
    what: Annotated[str, "Value to get: text, url, title, cdp-url, etc."],
    target: Annotated[str | None, "Optional element ref or selector"] = None,
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Get page or element information."""
    args = ["get", what]
    if target:
        args.append(target)
    return await _run_agent_browser(args, global_args=global_args, timeout=timeout)


@mcp.tool
async def agent_browser_screenshot(
    output: Annotated[str | None, "Optional output path"] = None,
    full: Annotated[bool, "Capture the full page"] = False,
    annotate: Annotated[bool, "Annotate interactive elements"] = False,
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Capture a screenshot."""
    args = ["screenshot"]
    if output:
        args.append(output)
    if full:
        args.append("--full")
    if annotate:
        args.append("--annotate")
    return await _run_agent_browser(args, global_args=global_args, timeout=timeout)


@mcp.tool
async def agent_browser_set_viewport(
    width: Annotated[int, "Viewport width in CSS pixels"],
    height: Annotated[int, "Viewport height in CSS pixels"],
    device_scale_factor: Annotated[int | None, "Optional device scale factor"] = None,
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Set browser viewport size."""
    args = ["set", "viewport", str(width), str(height)]
    if device_scale_factor is not None:
        args.append(str(device_scale_factor))
    return await _run_agent_browser(args, global_args=global_args, timeout=timeout)


@mcp.tool
async def agent_browser_close(
    global_args: Annotated[list[str] | None, "Optional global CLI flags"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Close the browser."""
    return await _run_agent_browser(["close"], global_args=global_args, timeout=timeout)


@mcp.tool
async def agent_browser_xss_verifier_start(
    label: Annotated[
        str,
        "Local verifier label for tracking multiple browser sessions",
    ] = "default",
    global_args: Annotated[
        list[str] | None,
        "Optional agent-browser global CLI flags for the target session",
    ] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> dict:
    """Arm a token-based XSS execution verifier in the current browser page.

    The verifier proves controlled JavaScript execution, not mere reflection.
    It returns an unguessable token and payload templates that send that token
    back through instrumented browser channels.
    """
    token = secrets.token_urlsafe(16)
    state = await _eval_browser_json(
        _build_xss_canary_script(token),
        global_args=global_args,
        timeout=timeout,
    )
    _XSS_VERIFIER_SESSIONS[label] = {
        "token": token,
        "global_args": json.dumps(global_args or []),
    }
    return _drop_empty(
        {
            "status": state.get("status", "armed"),
            "label": label,
            "token": token,
            "url": state.get("url"),
            "payloads": _xss_payload_examples(token),
            "next_step": "Inject or adapt one payload in the suspected XSS sink, trigger rendering in this same browser session, then call agent_browser_xss_verifier_check.",
            "limitations": [
                "Re-arm after page navigation because JavaScript context is page-scoped.",
                "Blind XSS requires an out-of-band callback URL instead of this browser-local verifier.",
                "A CONFIRMED verdict requires the payload to return the proof token through a proof function, dialog, console, or postMessage channel.",
            ],
        }
    )


@mcp.tool
async def agent_browser_xss_verifier_check(
    label: Annotated[
        str,
        "Verifier label from agent_browser_xss_verifier_start",
    ] = "default",
    token: Annotated[
        str | None,
        "Explicit proof token to check; defaults to the token for label",
    ] = None,
    global_args: Annotated[
        list[str] | None,
        "Optional agent-browser global CLI flags for the target session",
    ] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> dict:
    """Check whether an XSS payload returned the verifier proof token."""
    session = _XSS_VERIFIER_SESSIONS.get(label, {})
    expected_token = token or session.get("token")
    if not expected_token:
        raise RuntimeError(
            "No verifier token available. Call agent_browser_xss_verifier_start first or pass token explicitly."
        )

    session_args = json.loads(session.get("global_args", "[]"))
    args = global_args if global_args is not None else session_args
    state = await _eval_browser_json(
        _read_xss_canary_script(),
        global_args=args,
        timeout=timeout,
    )
    verdict = _xss_verdict(state, expected_token)
    verdict["label"] = label
    return _drop_empty(verdict)


@mcp.tool
async def agent_browser_xss_verifier_reset(
    label: Annotated[
        str,
        "Verifier label to clear",
    ] = "default",
    global_args: Annotated[
        list[str] | None,
        "Optional agent-browser global CLI flags for the target session",
    ] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> dict:
    """Remove the XSS verifier canary from the current browser page."""
    session = _XSS_VERIFIER_SESSIONS.pop(label, {})
    session_args = json.loads(session.get("global_args", "[]"))
    args = global_args if global_args is not None else session_args
    state = await _eval_browser_json(
        _reset_xss_canary_script(),
        global_args=args,
        timeout=timeout,
    )
    return _drop_empty(
        {
            "status": state.get("status", "reset"),
            "label": label,
            "url": state.get("url"),
        }
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
