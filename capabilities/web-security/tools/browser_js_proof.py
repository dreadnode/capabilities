"""Browser JavaScript execution proof helpers.

These tools provide a generic browser-side canary for XSS-family validation
without making the evidence hook depend on a specific vulnerability class.
"""

from __future__ import annotations

import asyncio
import html
import json
import os
import secrets
import shlex
import shutil
from typing import Annotated, Any

from dreadnode.agents.tools import Toolset, tool_method

MAX_OUTPUT_CHARS = int(os.environ.get("AGENT_BROWSER_MAX_OUTPUT_CHARS", "50000"))
DEFAULT_TIMEOUT = int(os.environ.get("AGENT_BROWSER_TIMEOUT", "60"))
_JS_PROOF_SESSIONS: dict[str, dict[str, str]] = {}


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
        "agent-browser is unavailable. Install it with one of:\n"
        "  npm i -g agent-browser\n"
        "  brew install agent-browser\n"
        "  cargo install agent-browser\n"
        "Then run: agent-browser install\n"
        "Alternatively set AGENT_BROWSER_COMMAND, for example: "
        "AGENT_BROWSER_COMMAND='npx --yes agent-browser'"
    )


async def _run_agent_browser(
    args: list[str],
    *,
    global_args: list[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    command = _resolve_command()
    if not command:
        raise RuntimeError(_missing_dependency_message())

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
        raise TimeoutError(f"agent-browser command timed out after {timeout}s")

    out = stdout.decode(errors="replace")
    err = stderr.decode(errors="replace")
    text = out if not err else f"{out}\n{err}".strip()
    if proc.returncode != 0:
        raise RuntimeError(_truncate(text))
    return _truncate(text)


async def _eval_browser_json(
    js: str,
    *,
    global_args: list[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    result = await _run_agent_browser(
        ["eval", js],
        global_args=global_args,
        timeout=timeout,
    )
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
                "agent-browser eval returned a JSON string, but it did not contain "
                f"a JSON object: {parsed[:500]}"
            ) from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("agent-browser eval returned JSON, but not an object")
    return parsed


def _build_js_proof_script(token: str) -> str:
    token_js = json.dumps(token)
    return f"""
(function() {{
  var token = {token_js};
  var previous = window.__dreadnodeJsProof;
  if (previous && previous.token === token && previous.armed) {{
    return JSON.stringify({{status: "already_armed", token: token, url: location.href}});
  }}
  if (previous && typeof previous.restore === "function") previous.restore();

  var state = {{
    kind: "browser_js_execution",
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

  window.__dreadnodeProof = function(value, detail) {{
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
    if (text.indexOf(token) !== -1) record("postMessage", text, {{origin: event.origin || ""}});
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

  state.restore = function() {{
    window.alert = originalAlert;
    window.confirm = originalConfirm;
    window.prompt = originalPrompt;
    Object.keys(originalConsole).forEach(function(level) {{
      console[level] = originalConsole[level];
    }});
  }};
  window.__dreadnodeJsProof = state;
  return JSON.stringify({{status: "armed", kind: state.kind, token: token, url: location.href, armedAt: state.armedAt}});
}})()
"""


def _read_js_proof_script() -> str:
    return """
(function() {
  var state = window.__dreadnodeJsProof;
  var storage = {};
  try { storage.localStorage = localStorage.getItem("__dreadnode_js_proof") || ""; } catch (e) {}
  try { storage.sessionStorage = sessionStorage.getItem("__dreadnode_js_proof") || ""; } catch (e) {}
  try { storage.windowName = window.name || ""; } catch (e) {}
  try {
    var marker = document.querySelector("[data-dreadnode-js-proof]");
    storage.domAttribute = marker ? (marker.getAttribute("data-dreadnode-js-proof") || "") : "";
  } catch (e) {}
  if (!state || !state.armed) {
    return JSON.stringify({
      kind: "browser_js_execution",
      armed: false,
      url: location.href,
      storage: storage
    });
  }
  return JSON.stringify({
    kind: state.kind || "browser_js_execution",
    armed: true,
    token: state.token,
    armedAt: state.armedAt,
    url: location.href,
    events: state.events || [],
    csp: state.csp || [],
    storage: storage
  });
})()
"""


def _reset_js_proof_script() -> str:
    return """
(function() {
  var state = window.__dreadnodeJsProof;
  if (state && typeof state.restore === "function") state.restore();
  delete window.__dreadnodeJsProof;
  delete window.__dreadnodeProof;
  try { localStorage.removeItem("__dreadnode_js_proof"); } catch (e) {}
  try { sessionStorage.removeItem("__dreadnode_js_proof"); } catch (e) {}
  try {
    if (window.name && window.name.indexOf("__DN_JS_PROOF__:") !== -1) window.name = "";
  } catch (e) {}
  try {
    document.querySelectorAll("[data-dreadnode-js-proof]").forEach(function(node) {
      node.removeAttribute("data-dreadnode-js-proof");
    });
  } catch (e) {}
  return JSON.stringify({status: "reset", url: location.href});
})()
"""


def _js_execution_payload_examples(token: str) -> dict[str, str]:
    proof_call = (
        "(function(){"
        f"var t={json.dumps(token)};"
        'try{localStorage.setItem("__dreadnode_js_proof",t)}catch(e){};'
        'try{sessionStorage.setItem("__dreadnode_js_proof",t)}catch(e){};'
        'try{window.name="__DN_JS_PROOF__:"+t}catch(e){};'
        'try{document.body&&document.body.setAttribute("data-dreadnode-js-proof",t)}catch(e){};'
        'try{window.__dreadnodeProof&&window.__dreadnodeProof(t,{source:"payload"})}catch(e){};'
        "})()"
    )
    attr_proof = html.escape(proof_call, quote=True)
    dialog_value = "__DN_JS_PROOF__:" + token
    return {
        "script_tag": f"<script>{proof_call}</script>",
        "event_handler": f"<img src=x onerror='{attr_proof}'>",
        "svg_onload": f"<svg onload='{attr_proof}'></svg>",
        "javascript_url": f"javascript:{proof_call}",
        "dialog": f"<script>alert({json.dumps(dialog_value)})</script>",
        "console": f"<script>console.log({json.dumps(dialog_value)})</script>",
        "post_message": f"<script>postMessage({json.dumps(dialog_value)}, '*')</script>",
    }


def _js_execution_verdict(state: dict[str, Any], expected_token: str) -> dict[str, Any]:
    storage = state.get("storage") if isinstance(state.get("storage"), dict) else {}
    storage_matches = [
        {"channel": channel, "value": value}
        for channel, value in storage.items()
        if isinstance(value, str) and expected_token in value
    ]
    if storage_matches:
        return {
            "kind": "browser_js_execution",
            "verified": True,
            "verdict": "CONFIRMED",
            "confidence": "high",
            "reason": "A payload-controlled proof token was observed in browser origin storage after JavaScript execution.",
            "url": state.get("url"),
            "evidence": storage_matches[:10],
            "event_count": len(state.get("events", [])),
            "csp": state.get("csp", []),
        }

    armed = state.get("armed")
    observed_token = state.get("token")
    if armed and observed_token != expected_token:
        return {
            "kind": "browser_js_execution",
            "verified": False,
            "verdict": "TOKEN_MISMATCH",
            "confidence": "none",
            "reason": "The page contains a different proof token than the token being checked.",
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
    if proof_events:
        return {
            "kind": "browser_js_execution",
            "verified": True,
            "verdict": "CONFIRMED",
            "confidence": "high",
            "reason": "A payload-controlled proof token was observed from JavaScript running in the browser page context.",
            "url": state.get("url"),
            "evidence": proof_events[:10],
            "event_count": len(events),
            "csp": state.get("csp", []),
        }

    if not armed:
        return {
            "kind": "browser_js_execution",
            "verified": False,
            "verdict": "CANARY_NOT_OBSERVED",
            "confidence": "none",
            "reason": "No browser JavaScript proof canary or storage marker was observed in the current page. Trigger the payload in agent-browser, then check again.",
            "url": state.get("url"),
        }

    return {
        "kind": "browser_js_execution",
        "verified": False,
        "verdict": "NOT_DETECTED",
        "confidence": "none",
        "reason": "No payload-controlled proof token was observed. The payload may not have executed, may have been sanitized, may need interaction, or may have rendered after navigation.",
        "url": state.get("url"),
        "event_count": len(events),
        "csp": state.get("csp", []),
    }


class BrowserJsProof(Toolset):
    """Generic browser JavaScript execution proof for XSS-family validation."""

    @tool_method(name="agent_browser_start_js_execution_proof", catch=True)
    async def agent_browser_start_js_execution_proof(
        self,
        proof_id: Annotated[
            str,
            "Local proof identifier for tracking multiple browser sessions",
        ] = "default",
        global_args: Annotated[
            list[str] | None,
            "Optional agent-browser global CLI flags for the target session",
        ] = None,
        timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Arm a token-based browser JavaScript execution proof in the current page."""
        token = secrets.token_urlsafe(12)
        state = await _eval_browser_json(
            _build_js_proof_script(token),
            global_args=global_args,
            timeout=timeout,
        )
        _JS_PROOF_SESSIONS[proof_id] = {
            "token": token,
            "global_args": json.dumps(global_args or []),
        }
        return _drop_empty(
            {
                "kind": "browser_js_execution",
                "status": state.get("status", "armed"),
                "proof_id": proof_id,
                "token": token,
                "url": state.get("url"),
                "payloads": _js_execution_payload_examples(token),
                "next_step": "Inject or adapt one payload in the suspected browser execution sink, trigger rendering in this same browser session, then call agent_browser_check_js_execution_proof.",
                "limitations": [
                    "Use browser-local proof for reflected, stored, or DOM XSS that executes in this agent-browser session.",
                    "Blind XSS requires an out-of-band callback URL instead of this browser-local proof.",
                    "A CONFIRMED verdict requires the payload to return or write the proof token through an instrumented browser channel.",
                ],
            }
        )

    @tool_method(name="agent_browser_check_js_execution_proof", catch=True)
    async def agent_browser_check_js_execution_proof(
        self,
        proof_id: Annotated[
            str,
            "Proof identifier from agent_browser_start_js_execution_proof",
        ] = "default",
        token: Annotated[
            str | None,
            "Explicit proof token to check; defaults to the token for proof_id",
        ] = None,
        global_args: Annotated[
            list[str] | None,
            "Optional agent-browser global CLI flags for the target session",
        ] = None,
        timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Check whether a browser JavaScript payload returned the proof token."""
        session = _JS_PROOF_SESSIONS.get(proof_id, {})
        expected_token = token or session.get("token")
        if not expected_token:
            raise RuntimeError(
                "No proof token available. Call agent_browser_start_js_execution_proof first or pass token explicitly."
            )

        session_args = json.loads(session.get("global_args", "[]"))
        args = global_args if global_args is not None else session_args
        state = await _eval_browser_json(
            _read_js_proof_script(),
            global_args=args,
            timeout=timeout,
        )
        verdict = _js_execution_verdict(state, expected_token)
        verdict["proof_id"] = proof_id
        return _drop_empty(verdict)

    @tool_method(name="agent_browser_reset_js_execution_proof", catch=True)
    async def agent_browser_reset_js_execution_proof(
        self,
        proof_id: Annotated[
            str,
            "Proof identifier to clear",
        ] = "default",
        global_args: Annotated[
            list[str] | None,
            "Optional agent-browser global CLI flags for the target session",
        ] = None,
        timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Remove the browser JavaScript execution proof canary from the page."""
        session = _JS_PROOF_SESSIONS.pop(proof_id, {})
        session_args = json.loads(session.get("global_args", "[]"))
        args = global_args if global_args is not None else session_args
        state = await _eval_browser_json(
            _reset_js_proof_script(),
            global_args=args,
            timeout=timeout,
        )
        return _drop_empty(
            {
                "kind": "browser_js_execution",
                "status": state.get("status", "reset"),
                "proof_id": proof_id,
                "url": state.get("url"),
            }
        )
