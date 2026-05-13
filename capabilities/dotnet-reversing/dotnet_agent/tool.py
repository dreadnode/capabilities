#!/usr/bin/env python3
"""
Persistent HTTP server for .NET analysis tools.

Loads pythonnet and ILSpy once at startup, then serves tool requests
via HTTP. Started as a capability client by dreadcode.

On first run, bootstraps dependencies automatically:
- .NET 8.0 runtime (via dotnet-install.sh)
- ILSpy decompiler DLLs (from GitHub releases)
- pythonnet (via pip)

The port is configured via CAPABILITY_PORT environment variable (default: 9797).
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from dotnet_agent.bootstrap import ensure_dependencies

PORT = int(os.environ.get("CAPABILITY_PORT", "9797"))


# ---------------------------------------------------------------------------
# HTTP Server
# ---------------------------------------------------------------------------

# Lazy-loaded after bootstrap
COMMANDS: dict[str, object] = {}


def _load_tools() -> None:
    """Import reversing tools after bootstrap has ensured deps exist."""
    import asyncio

    from dotnet_agent.download import download_nuget_package
    from dotnet_agent.reversing import (
        decompile_methods,
        decompile_module,
        decompile_type,
        get_call_flows_to_method,
        list_methods,
        list_methods_in_type,
        list_namespaces,
        list_types,
        list_types_in_namespace,
        scan_binaries,
        search_by_name,
        search_for_references,
    )

    COMMANDS.update(
        {
            "dotnet_scan_binaries": scan_binaries,
            "dotnet_list_namespaces": list_namespaces,
            "dotnet_list_types_in_namespace": list_types_in_namespace,
            "dotnet_list_types": list_types,
            "dotnet_list_methods_in_type": list_methods_in_type,
            "dotnet_list_methods": list_methods,
            "dotnet_decompile_module": decompile_module,
            "dotnet_decompile_type": decompile_type,
            "dotnet_decompile_methods": decompile_methods,
            "dotnet_search_references": search_for_references,
            "dotnet_search_by_name": search_by_name,
            "dotnet_get_call_flows": get_call_flows_to_method,
            "dotnet_download_nuget": lambda **kwargs: str(
                asyncio.run(
                    download_nuget_package(
                        package=kwargs["package"],
                        version=kwargs.get("version") or None,
                        output_dir=Path(kwargs["output_dir"]) if kwargs.get("output_dir") else None,
                    )
                )
            ),
        }
    )


class ToolHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            payload = json.loads(body)
            tool_name = payload["name"]
            params = payload.get("parameters", {})

            fn = COMMANDS.get(tool_name)
            if fn is None:
                self._respond(400, {"error": f"Unknown tool: {tool_name}"})
                return

            result = fn(**params)  # type: ignore[operator]
            self._respond(200, {"result": result})
        except Exception as e:
            self._respond(500, {"error": str(e)})

    def _respond(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def main() -> None:
    ensure_dependencies()
    _load_tools()
    print(f"dotnet capability ready on port {PORT}", file=sys.stderr, flush=True)
    server = HTTPServer(("127.0.0.1", PORT), ToolHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
