""".NET assembly analysis tools using ILSpy via pythonnet.

Tools are served by a persistent subprocess (dotnet_agent.tool) running
under Python 3.12 (required by pythonnet). The subprocess loads the CLR
once at startup and handles requests via HTTP. This file provides thin
@tool wrappers that proxy calls to that server.

On first tool call the server is spawned automatically. If .NET/ILSpy
aren't installed, the subprocess bootstraps them (~100MB one-time download).
"""

from __future__ import annotations

import asyncio
import atexit
import json
import os
import shutil
import subprocess
import typing as t
from pathlib import Path

import aiohttp
from dreadnode.agents.tools import tool

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

_CAP_ROOT = Path(__file__).parent.parent
_SERVER_MODULE = "dotnet_agent.tool"
_DEFAULT_PORT = 9797
_HEALTH_TIMEOUT = 60  # seconds to wait for server to become ready
_HEALTH_POLL = 0.3  # seconds between health checks

_server_process: subprocess.Popen | None = None  # type: ignore[type-arg]
_server_port: int = _DEFAULT_PORT
_atexit_registered: bool = False


def _find_free_port() -> int:
    """Find a free port to avoid conflicts."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spawn_server() -> int:
    """Spawn the dotnet tool server subprocess. Returns the port."""
    global _server_process, _server_port

    if _server_process and _server_process.poll() is None:
        return _server_port

    _server_port = _find_free_port()
    env = {
        **os.environ,
        "CAPABILITY_PORT": str(_server_port),
        "PYTHONPATH": f"{_CAP_ROOT}{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
    }

    # Use uv to run under Python 3.12 (pythonnet requirement)
    uv_bin = shutil.which("uv")
    if uv_bin:
        cmd = [
            uv_bin,
            "run",
            "--python",
            "3.12",
            "--with",
            "pythonnet>=3.0.5",
            "--with",
            "loguru>=0.7.0",
            "-m",
            _SERVER_MODULE,
        ]
    else:
        # Fallback: assume python3.12 is available with pythonnet installed
        cmd = ["python3.12", "-m", _SERVER_MODULE]

    _server_process = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=None,  # inherit parent stderr so bootstrap progress is visible
        cwd=str(_CAP_ROOT),
    )

    global _atexit_registered
    if not _atexit_registered:
        atexit.register(_shutdown_server)
        _atexit_registered = True
    return _server_port


def _shutdown_server() -> None:
    """Terminate the server subprocess on exit."""
    global _server_process
    if _server_process and _server_process.poll() is None:
        _server_process.terminate()
        try:
            _server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _server_process.kill()
    _server_process = None


async def _ensure_server() -> str:
    """Ensure the server is running and healthy. Returns the base URL."""
    port = _spawn_server()
    base_url = f"http://127.0.0.1:{port}"

    # Wait for health check
    deadline = asyncio.get_event_loop().time() + _HEALTH_TIMEOUT
    last_error = None
    async with aiohttp.ClientSession() as session:
        while asyncio.get_event_loop().time() < deadline:
            # Check if process died
            if _server_process and _server_process.poll() is not None:
                raise RuntimeError(
                    f"Dotnet server exited with code {_server_process.returncode}. "
                    f"Check stderr output above for details."
                )
            try:
                async with session.get(f"{base_url}/health", timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    if resp.status == 200:
                        return base_url
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                last_error = e
            await asyncio.sleep(_HEALTH_POLL)

    # Timed out
    _shutdown_server()
    raise RuntimeError(f"Dotnet server failed to start within {_HEALTH_TIMEOUT}s. " f"Last error: {last_error}")


# ---------------------------------------------------------------------------
# RPC helper
# ---------------------------------------------------------------------------


async def _call_tool(name: str, parameters: dict[str, t.Any]) -> t.Any:
    """Call a tool on the dotnet server."""
    base_url = await _ensure_server()
    payload = json.dumps({"name": name, "parameters": parameters})

    async with aiohttp.ClientSession() as session:
        async with session.post(
            base_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=300),
        ) as resp:
            body = await resp.json()
            if resp.status != 200:
                raise RuntimeError(body.get("error", f"Server returned {resp.status}"))
            return body["result"]


def _format(result: t.Any) -> str:
    """Serialize non-string results for the agent."""
    if isinstance(result, str):
        return result
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@tool
async def dotnet_scan_binaries(
    path: t.Annotated[str, "Directory path to scan"],
    pattern: t.Annotated[str, "Glob pattern for matching files"] = "**/*",
    exclude: t.Annotated[str, "Comma-separated patterns to exclude"] = "",
) -> str:
    """Scan a directory for .NET assemblies (.dll, .exe).

    Returns relative paths of discovered managed binaries.
    """
    exclude_list = [s.strip() for s in exclude.split(",") if s.strip()] or None
    result = await _call_tool(
        "dotnet_scan_binaries",
        {
            "base_path": path,
            "pattern": pattern,
            "exclude": exclude_list,
        },
    )
    return _format(result)


@tool
async def dotnet_list_namespaces(
    path: t.Annotated[str, "Path to .NET assembly"],
) -> str:
    """List all namespaces in a .NET assembly."""
    return _format(await _call_tool("dotnet_list_namespaces", {"path": path}))


@tool
async def dotnet_list_types_in_namespace(
    path: t.Annotated[str, "Path to .NET assembly"],
    namespace: t.Annotated[str, "Namespace to list types from"],
) -> str:
    """List all types (classes, interfaces, etc.) in a namespace."""
    return _format(
        await _call_tool(
            "dotnet_list_types_in_namespace",
            {
                "path": path,
                "namespace": namespace,
            },
        )
    )


@tool
async def dotnet_list_types(
    path: t.Annotated[str, "Path to .NET assembly"],
) -> str:
    """List all types in a .NET assembly."""
    return _format(await _call_tool("dotnet_list_types", {"path": path}))


@tool
async def dotnet_list_methods_in_type(
    path: t.Annotated[str, "Path to .NET assembly"],
    type_name: t.Annotated[str, "Fully qualified type name"],
) -> str:
    """List all methods in a specific type."""
    return _format(
        await _call_tool(
            "dotnet_list_methods_in_type",
            {
                "path": path,
                "type_name": type_name,
            },
        )
    )


@tool
async def dotnet_list_methods(
    path: t.Annotated[str, "Path to .NET assembly"],
) -> str:
    """List all methods in a .NET assembly."""
    return _format(await _call_tool("dotnet_list_methods", {"path": path}))


@tool
async def dotnet_decompile_module(
    path: t.Annotated[str, "Path to .NET assembly"],
) -> str:
    """Decompile an entire .NET module to C# source code.

    Warning: Output can be very large. Prefer dotnet_decompile_type
    for targeted analysis.
    """
    return _format(await _call_tool("dotnet_decompile_module", {"path": path}))


@tool
async def dotnet_decompile_type(
    path: t.Annotated[str, "Path to .NET assembly"],
    type_name: t.Annotated[str, "Fully qualified type name to decompile"],
) -> str:
    """Decompile a specific type to C# source code.

    Preferred over dotnet_decompile_module for targeted reverse engineering.
    """
    return _format(
        await _call_tool(
            "dotnet_decompile_type",
            {
                "path": path,
                "type_name": type_name,
            },
        )
    )


@tool
async def dotnet_decompile_methods(
    path: t.Annotated[str, "Path to .NET assembly"],
    method_names: t.Annotated[list[str], "Method names to decompile"],
) -> str:
    """Decompile specific methods by name.

    Supports flexible name matching. Returns a dict of full method
    name to decompiled C# source.
    """
    return _format(
        await _call_tool(
            "dotnet_decompile_methods",
            {
                "path": path,
                "method_names": method_names,
            },
        )
    )


@tool
async def dotnet_search_references(
    path: t.Annotated[str, "Path to .NET assembly"],
    search: t.Annotated[str, "Search string to find in IL references"],
) -> str:
    """Find methods that reference a search string in their IL code.

    Useful for locating usage of specific APIs, types, or strings.
    Supports flexible matching (dot and :: notation).
    """
    return _format(
        await _call_tool(
            "dotnet_search_references",
            {
                "path": path,
                "search": search,
            },
        )
    )


@tool
async def dotnet_search_by_name(
    path: t.Annotated[str, "Path to .NET assembly"],
    search: t.Annotated[str, "Substring to match against type and method names"],
) -> str:
    """Search for types and methods matching a name substring.

    Returns matching type and method full names.
    """
    return _format(
        await _call_tool(
            "dotnet_search_by_name",
            {
                "path": path,
                "search": search,
            },
        )
    )


@tool
async def dotnet_get_call_flows(
    paths: t.Annotated[list[str], "Assembly paths to analyze"],
    method_name: t.Annotated[str, "Target method name to trace calls to"],
    max_depth: t.Annotated[int, "Maximum call graph depth"] = 10,
) -> str:
    """Trace call paths to a target method across assemblies.

    Builds a call graph showing how execution can reach the target
    method. Returns unique call paths as nested lists.
    """
    return _format(
        await _call_tool(
            "dotnet_get_call_flows",
            {
                "paths": paths,
                "method_name": method_name,
                "max_depth": max_depth,
            },
        )
    )


@tool
async def dotnet_download_nuget(
    package: t.Annotated[str, "NuGet package name (e.g., 'Newtonsoft.Json')"],
    version: t.Annotated[str, "Specific version (empty for latest)"] = "",
    output_dir: t.Annotated[str, "Output directory"] = "",
) -> str:
    """Download and extract a NuGet package for analysis.

    Downloads from nuget.org and extracts for use with dotnet_* tools.
    """
    params: dict[str, t.Any] = {"package": package}
    if version:
        params["version"] = version
    if output_dir:
        params["output_dir"] = output_dir
    return _format(await _call_tool("dotnet_download_nuget", params))
