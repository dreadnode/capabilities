"""Compatibility stub for the removed Caido Toolset integration.

Caido is exposed through `mcp/caido.py`; this module exists so older imports do
not fail while making it explicit that no legacy Toolset is exported.
"""

CaidoTools = None
