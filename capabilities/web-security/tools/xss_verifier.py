"""Programmatic XSS verification via agent-browser.

Observes whether arbitrary JavaScript executes in the browser — payload
agnostic, no hardcoded strings or patterns. Works by injecting a canary
script that replaces window.alert/confirm/prompt with logging wrappers
and attaches a MutationObserver to detect <script> tags added to the DOM.
Any dialog call or script injection after arming is recorded and reported.

Covers reflected, DOM, and stored XSS. For stored XSS the canary must be
injected on the page where the payload renders, not where it is submitted
(page navigation destroys the JS context — re-inject after navigating).

Does NOT cover blind XSS (payload fires in a session the agent cannot
access). Use CallbackClient with an OOB URL payload for blind XSS.

Requires agent-browser to be available (see agent_browser MCP server).
"""

import asyncio
import json
import os
import secrets
import shlex
import shutil
from typing import Annotated, Literal

from dreadnode.agents.tools import Toolset, tool_method

_DEFAULT_TIMEOUT = int(os.environ.get("AGENT_BROWSER_TIMEOUT", "60"))


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


async def _eval_js(
    js: str,
    *,
    global_args: list[str] | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
) -> str:
    """Execute JavaScript in the browser page context via agent-browser eval."""
    command = _resolve_command()
    if not command:
        raise RuntimeError(
            "agent-browser is not available. Install with: npm i -g agent-browser"
        )
    argv = command + (global_args or []) + ["eval", js]
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
        raise RuntimeError(f"agent-browser eval timed out after {timeout}s")

    out = stdout.decode(errors="replace")
    err = stderr.decode(errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(
            f"agent-browser eval failed (exit {proc.returncode}): {err or out}"
        )
    return out.strip()


# JavaScript injected into the page to intercept dialog calls and script execution.
# Uses a per-session nonce so multiple inject/verify cycles don't collide.
# __NONCE__ is replaced via str.replace (not .format()) to avoid brace escaping.
_CANARY_SCRIPT = """
(function(nonce) {
  if (window.__xssCanary && window.__xssCanary.nonce === nonce) return 'already_armed';
  window.__xssCanary = {
    nonce: nonce,
    alerts: [],
    confirms: [],
    prompts: [],
    scriptExecutions: [],
    armed: true,
  };
  var c = window.__xssCanary;
  window.alert = function(msg) { c.alerts.push(String(msg)); };
  window.confirm = function(msg) { c.confirms.push(String(msg)); return false; };
  window.prompt = function(msg) { c.prompts.push(String(msg)); return null; };

  // MutationObserver: detect <script> tags injected into the DOM
  new MutationObserver(function(mutations) {
    mutations.forEach(function(m) {
      m.addedNodes.forEach(function(node) {
        if (node.nodeName === 'SCRIPT') {
          c.scriptExecutions.push({
            src: node.src || null,
            inline: (node.textContent || '').slice(0, 200),
          });
        }
      });
    });
  }).observe(document.documentElement, { childList: true, subtree: true });

  return 'armed';
})(__NONCE__)
"""

# Plain JS — not a template. Read-only, no interpolation needed.
_READ_CANARY = """
(function() {
  var c = window.__xssCanary;
  if (!c) return JSON.stringify({armed: false});
  return JSON.stringify({
    armed: c.armed,
    nonce: c.nonce,
    alerts: c.alerts,
    confirms: c.confirms,
    prompts: c.prompts,
    scriptExecutions: c.scriptExecutions,
  });
})()
"""


XssContext = Literal["reflected", "stored", "dom"]


class XssVerifier(Toolset):
    """Payload-agnostic XSS verification via browser-side JavaScript canary.

    Replaces dialog functions and observes DOM mutations to detect whether
    any JavaScript executed — does not inspect or match payload content.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._nonce: str | None = None
        self._global_args: list[str] | None = None

    @tool_method(name="xss_inject_canary", catch=True)
    async def inject_canary(
        self,
        global_args: Annotated[
            list[str] | None,
            "agent-browser global args, e.g. ['--session-name', 'app']. "
            "Must match the session where the target page is loaded.",
        ] = None,
    ) -> str:
        """Inject the XSS detection canary into the current browser page.

        Replaces window.alert, window.confirm, and window.prompt with
        wrappers that log every call. Attaches a MutationObserver on the
        document to record any <script> element added to the DOM.

        Call BEFORE triggering your XSS payload. The canary lives in the
        current page's JS context — page navigation destroys it. For
        stored XSS, inject on the page where the payload renders, not
        where you submit it.
        """
        self._nonce = secrets.token_hex(8)
        self._global_args = global_args
        js = _CANARY_SCRIPT.replace("__NONCE__", json.dumps(self._nonce))
        result = await _eval_js(js, global_args=global_args)
        if "armed" in result:
            return (
                f"Canary armed (nonce: {self._nonce}). "
                "Now trigger your XSS payload, then call xss_verify."
            )
        return f"Unexpected result from canary injection: {result}"

    @tool_method(name="xss_verify", catch=True)
    async def verify(
        self,
        xss_context: Annotated[
            XssContext,
            "The XSS context being tested: "
            "'reflected' (payload in URL/response), "
            "'stored' (payload persisted and rendered), "
            "'dom' (payload processed client-side).",
        ],
        payload_used: Annotated[
            str,
            "The exact XSS payload you injected, e.g. '<script>alert(1)</script>' "
            "or '<img src=x onerror=alert(1)>'.",
        ],
        global_args: Annotated[
            list[str] | None,
            "agent-browser global args. Must match the session used in xss_inject_canary.",
        ] = None,
    ) -> str:
        """Check whether your XSS payload triggered JavaScript execution.

        Reads the canary state from the browser and checks for two
        signals: (1) dialog function calls logged by the overridden
        alert/confirm/prompt, (2) <script> elements caught by the
        MutationObserver. Does not inspect the payload itself.

        Verdicts:
          CONFIRMED    — dialog function was called (strongest proof)
          PARTIAL      — script tag injected into DOM, no dialog fired
          NOT_DETECTED — no JS execution signals observed
          CANARY_LOST  — page navigated, canary no longer present
        """
        if not self._nonce:
            raise RuntimeError(
                "No canary injected. Call xss_inject_canary first, "
                "then trigger your payload, then call xss_verify."
            )

        args = global_args or self._global_args
        raw = await _eval_js(_READ_CANARY, global_args=args)

        try:
            state = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            raise RuntimeError(f"Could not parse canary state: {raw[:500]}")

        if not state.get("armed"):
            return (
                "CANARY_LOST — The canary is no longer present in the page. "
                "This usually means the page navigated away after injection. "
                "Re-inject the canary on the page where the payload renders, "
                "then trigger the payload again."
            )

        if state.get("nonce") != self._nonce:
            return (
                "NONCE_MISMATCH — A different canary session is active. "
                "Call xss_inject_canary again to start a fresh verification."
            )

        alerts = state.get("alerts", [])
        confirms = state.get("confirms", [])
        prompts = state.get("prompts", [])
        scripts = state.get("scriptExecutions", [])

        dialog_count = len(alerts) + len(confirms) + len(prompts)
        script_count = len(scripts)
        total_signals = dialog_count + script_count

        if total_signals == 0:
            return (
                f"NOT_DETECTED — No JavaScript execution caught after payload.\n"
                f"  Payload: {payload_used}\n"
                f"  Context: {xss_context}\n"
                f"  Dialogs triggered: 0\n"
                f"  Scripts injected: 0\n\n"
                "Possible causes:\n"
                "  - Payload was HTML-encoded or sanitized by the application\n"
                "  - CSP blocked inline script execution\n"
                "  - Payload is in a non-executing context (attribute, comment)\n"
                "  - Page navigated away before payload rendered (re-inject canary)\n"
                "  - DOM-based XSS may need user interaction to trigger"
            )

        evidence_lines = []
        if alerts:
            evidence_lines.append(f"  alert() called {len(alerts)}x: {alerts[:5]}")
        if confirms:
            evidence_lines.append(
                f"  confirm() called {len(confirms)}x: {confirms[:5]}"
            )
        if prompts:
            evidence_lines.append(f"  prompt() called {len(prompts)}x: {prompts[:5]}")
        if scripts:
            for s in scripts[:3]:
                src = s.get("src") or "(inline)"
                inline = s.get("inline", "")[:100]
                evidence_lines.append(f"  <script> injected: src={src} body={inline!r}")

        evidence = "\n".join(evidence_lines)

        if dialog_count > 0:
            verdict = "CONFIRMED"
            summary = (
                f"JavaScript executed — dialog function intercepted.\n"
                f"  Payload: {payload_used}\n"
                f"  Context: {xss_context}\n"
                f"  Evidence:\n{evidence}"
            )
        else:
            verdict = "PARTIAL"
            summary = (
                f"Script tag injected into DOM but no dialog function called.\n"
                f"  Payload: {payload_used}\n"
                f"  Context: {xss_context}\n"
                f"  Evidence:\n{evidence}\n\n"
                "The script was added to the DOM, which confirms injection, "
                "but execution was not proven via dialog interception. "
                "Consider using a payload with alert/confirm/prompt to get "
                "a CONFIRMED verdict."
            )

        return f"{verdict} — {summary}"

    @tool_method(name="xss_reset", catch=True)
    async def reset(self) -> str:
        """Reset canary state for a new verification cycle."""
        self._nonce = None
        self._global_args = None
        return "XSS verifier reset. Call xss_inject_canary to start a new cycle."
