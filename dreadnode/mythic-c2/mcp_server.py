#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "mythic>=0.2",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
# ]
# ///
"""Mythic C2 MCP server entry point.

Always registers the read-only observation surface (``lib/observation.py``).
When the ``apollo`` capability flag is on, also registers the Apollo
post-exploitation tasking surface (``lib/apollo.py``) on the same server so
auth and the shared Mythic client live in one process.

Credentials come from the environment so they never appear in conversations.
Authentication happens lazily on the first tool call; the MCP handshake
succeeds even when Mythic is unreachable at startup.

Env vars:
    MYTHIC_SERVER_IP    (default: 127.0.0.1)
    MYTHIC_SERVER_PORT  (default: 7443)
    MYTHIC_USERNAME     (default: mythic_admin)
    MYTHIC_PASSWORD     (required unless MYTHIC_API_TOKEN is set)
    MYTHIC_API_TOKEN    (alternative to username/password)
    MYTHIC_TIMEOUT      (default: -1)
    MYTHIC_DATA_DIR     (default: <capability_root>/data/mythic) — host-side
                        staging dir used by Apollo tools for PowerView.ps1
                        and SharpHound.ps1.

    CAPABILITY_FLAG__MYTHIC_C2__APOLLO
                        "0" (default) → observation tools only.
                        "1"           → Apollo tasking surface is added.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

from lib import observation

APOLLO = os.environ.get("CAPABILITY_FLAG__MYTHIC_C2__APOLLO", "0") == "1"

mcp = FastMCP("mythic-c2")
observation.register(mcp)

if APOLLO:
    from lib import apollo

    apollo.register(mcp)


if __name__ == "__main__":
    mcp.run(transport="stdio")
