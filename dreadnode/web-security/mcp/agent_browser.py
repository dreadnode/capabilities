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
import os
import shlex
import shutil
from typing import Annotated

from fastmcp import FastMCP

mcp = FastMCP("agent-browser")

MAX_OUTPUT_CHARS = int(os.environ.get("AGENT_BROWSER_MAX_OUTPUT_CHARS", "50000"))
DEFAULT_TIMEOUT = int(os.environ.get("AGENT_BROWSER_TIMEOUT", "60"))


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
    return await _run_agent_browser(["press", key], global_args=global_args, timeout=timeout)


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


if __name__ == "__main__":
    mcp.run(transport="stdio")
