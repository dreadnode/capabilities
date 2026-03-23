"""Caido integration is provided via MCP server (mcp/server.py).

Caido tools run in an isolated venv via `uv run` to keep the caido-sdk-client
dependency out of the SDK. See mcp/tools/caido.py for the implementation.
"""

from __future__ import annotations
