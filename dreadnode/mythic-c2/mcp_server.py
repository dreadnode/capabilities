#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "mythic>=0.2",
# ]
# ///
"""Mythic C2 MCP server entry point.

Always registers the read-only observation surface (``lib/observation.py``).
When the ``tasking`` capability flag is on, also registers the generic
payload-type-agnostic tasking surface (``lib/tasking.py``). When the
``apollo`` capability flag is on, adds the Apollo-specific orchestration
surface (``lib/apollo.py``). Both flags are independent — turn ``tasking``
on to task any payload type; turn ``apollo`` on to layer Apollo-specific
workflows on top. All surfaces share one authenticated Mythic client.

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

    CAPABILITY_FLAG__MYTHIC_C2__TASKING
                        "0" (default) → observation-only.
                        "1"           → generic ``issue_task`` +
                                        ``list_callback_commands`` added.
    CAPABILITY_FLAG__MYTHIC_C2__APOLLO
                        "0" (default) → no Apollo-specific orchestration.
                        "1"           → Apollo workflow tools added.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

from lib import observation

TASKING = os.environ.get("CAPABILITY_FLAG__MYTHIC_C2__TASKING", "0") == "1"
APOLLO = os.environ.get("CAPABILITY_FLAG__MYTHIC_C2__APOLLO", "0") == "1"

mcp = FastMCP("mythic-c2")
observation.register(mcp)

if TASKING:
    from lib import tasking

    tasking.register(mcp)

if APOLLO:
    from lib import apollo

    apollo.register(mcp)


if __name__ == "__main__":
    mcp.run(transport="stdio")
