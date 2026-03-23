#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "caido-sdk-client",
# ]
# ///
"""Host-side tool server for the web-security capability.

Runs in an isolated venv via `uv run`. All host tool dependencies are declared
above in PEP 723 inline metadata — they never enter the SDK's environment.

To add a new host tool:
  1. Create mcp/tools/<name>.py with a register(mcp: FastMCP) function
  2. Add its dependencies to the script metadata above
  3. Import and call register() below
"""

from __future__ import annotations

from fastmcp import FastMCP

from tools import caido, jxscout

mcp = FastMCP("web-security")

# Register tool modules — each adds its tools to the shared server.
caido.register(mcp)
jxscout.register(mcp)

if __name__ == "__main__":
    mcp.run(transport="stdio")
