"""Shared test shims for legacy Toolset-based web-security tools."""

from __future__ import annotations

import inspect
import json
import sys
import types
from dataclasses import dataclass
from typing import Any


def _install_dreadnode_tools_stub() -> None:
    if "dreadnode.agents.tools" in sys.modules:
        return

    dreadnode = types.ModuleType("dreadnode")
    agents = types.ModuleType("dreadnode.agents")
    tools = types.ModuleType("dreadnode.agents.tools")

    @dataclass
    class FunctionCall:
        name: str
        arguments: str

    @dataclass
    class ToolCall:
        id: str
        function: FunctionCall

    @dataclass
    class ToolMessage:
        content: str
        tool_call_id: str | None = None

    class _Tool:
        def __init__(self, instance: object, method: Any, metadata: dict[str, Any]) -> None:
            self._instance = instance
            self._method = method
            self.name = metadata["name"]
            self.description = metadata["description"]
            self.catch = metadata["catch"]
            self.parameters_schema = _schema_for(method)

        async def handle_tool_call(self, tool_call: ToolCall) -> tuple[ToolMessage, bool]:
            arguments = json.loads(tool_call.function.arguments or "{}")
            result = await self._method(**arguments)
            return ToolMessage(content=str(result), tool_call_id=tool_call.id), False

    def _schema_for(method: Any) -> dict[str, Any]:
        signature = inspect.signature(method)
        properties = {
            name: {"type": "string"}
            for name in signature.parameters
            if name != "self"
        }
        return {"type": "object", "properties": properties}

    def tool_method(*, name: str | None = None, catch: bool = False, **_: Any):
        def decorator(fn):
            fn._tool_metadata = {
                "name": name or fn.__name__,
                "catch": catch,
                "description": inspect.getdoc(fn) or "",
            }
            return fn

        return decorator

    class Toolset:
        def get_tools(self):
            discovered = []
            for attr_name in dir(self):
                value = getattr(self, attr_name)
                metadata = getattr(value, "_tool_metadata", None)
                if metadata:
                    discovered.append(_Tool(self, value, metadata))
            return discovered

    tools.FunctionCall = FunctionCall
    tools.ToolCall = ToolCall
    tools.ToolMessage = ToolMessage
    tools.Toolset = Toolset
    tools.tool_method = tool_method
    agents.tools = tools
    dreadnode.agents = agents

    sys.modules["dreadnode"] = dreadnode
    sys.modules["dreadnode.agents"] = agents
    sys.modules["dreadnode.agents.tools"] = tools


_install_dreadnode_tools_stub()
