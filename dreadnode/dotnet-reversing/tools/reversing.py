""".NET assembly analysis tools using ILSpy via pythonnet.

Wraps dotnet_agent.reversing functions as @tool for v1 discovery.
The CLR is loaded lazily on first tool call — if pythonnet or .NET 8.0
aren't installed, tools fail with a clear error instead of crashing
at import time.
"""

from __future__ import annotations

import json
import sys
import typing as t
from pathlib import Path

from dreadnode.agents.tools import tool

# Make dotnet_agent importable from capability root
_cap_root = str(Path(__file__).parent.parent)
if _cap_root not in sys.path:
    sys.path.insert(0, _cap_root)

_rev: t.Any = None


def _get_rev() -> t.Any:
    """Lazy-import dotnet_agent.reversing (triggers CLR load on first call)."""
    global _rev
    if _rev is None:
        try:
            import dotnet_agent.reversing as rev

            _rev = rev
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize .NET CLR: {e}. "
                "Ensure pythonnet>=3.0.5 and .NET 8.0 runtime are installed."
            ) from e
    return _rev


def _format(result: t.Any) -> str:
    """Serialize non-string results for the agent."""
    if isinstance(result, str):
        return result
    return json.dumps(result, indent=2)


@tool
def dotnet_scan_binaries(
    path: t.Annotated[str, "Directory path to scan"],
    pattern: t.Annotated[str, "Glob pattern for matching files"] = "**/*",
    exclude: t.Annotated[str, "Comma-separated patterns to exclude"] = "",
) -> str:
    """Scan a directory for .NET assemblies (.dll, .exe).

    Returns relative paths of discovered managed binaries.
    """
    rev = _get_rev()
    exclude_list = [s.strip() for s in exclude.split(",") if s.strip()] or None
    return _format(rev.scan_binaries(path, pattern, exclude_list))


@tool
def dotnet_list_namespaces(
    path: t.Annotated[str, "Path to .NET assembly"],
) -> str:
    """List all namespaces in a .NET assembly."""
    return _format(_get_rev().list_namespaces(path))


@tool
def dotnet_list_types_in_namespace(
    path: t.Annotated[str, "Path to .NET assembly"],
    namespace: t.Annotated[str, "Namespace to list types from"],
) -> str:
    """List all types (classes, interfaces, etc.) in a namespace."""
    return _format(_get_rev().list_types_in_namespace(path, namespace))


@tool
def dotnet_list_types(
    path: t.Annotated[str, "Path to .NET assembly"],
) -> str:
    """List all types in a .NET assembly."""
    return _format(_get_rev().list_types(path))


@tool
def dotnet_list_methods_in_type(
    path: t.Annotated[str, "Path to .NET assembly"],
    type_name: t.Annotated[str, "Fully qualified type name"],
) -> str:
    """List all methods in a specific type."""
    return _format(_get_rev().list_methods_in_type(path, type_name))


@tool
def dotnet_list_methods(
    path: t.Annotated[str, "Path to .NET assembly"],
) -> str:
    """List all methods in a .NET assembly."""
    return _format(_get_rev().list_methods(path))


@tool
def dotnet_decompile_module(
    path: t.Annotated[str, "Path to .NET assembly"],
) -> str:
    """Decompile an entire .NET module to C# source code.

    Warning: Output can be very large. Prefer dotnet_decompile_type
    for targeted analysis.
    """
    return _get_rev().decompile_module(path)


@tool
def dotnet_decompile_type(
    path: t.Annotated[str, "Path to .NET assembly"],
    type_name: t.Annotated[str, "Fully qualified type name to decompile"],
) -> str:
    """Decompile a specific type to C# source code.

    Preferred over dotnet_decompile_module for targeted reverse engineering.
    """
    return _get_rev().decompile_type(path, type_name)


@tool
def dotnet_decompile_methods(
    path: t.Annotated[str, "Path to .NET assembly"],
    method_names: t.Annotated[list[str], "Method names to decompile"],
) -> str:
    """Decompile specific methods by name.

    Supports flexible name matching. Returns a dict of full method
    name to decompiled C# source.
    """
    return _format(_get_rev().decompile_methods(path, method_names))


@tool
def dotnet_search_references(
    path: t.Annotated[str, "Path to .NET assembly"],
    search: t.Annotated[str, "Search string to find in IL references"],
) -> str:
    """Find methods that reference a search string in their IL code.

    Useful for locating usage of specific APIs, types, or strings.
    Supports flexible matching (dot and :: notation).
    """
    return _format(_get_rev().search_for_references(path, search))


@tool
def dotnet_search_by_name(
    path: t.Annotated[str, "Path to .NET assembly"],
    search: t.Annotated[str, "Substring to match against type and method names"],
) -> str:
    """Search for types and methods matching a name substring.

    Returns matching type and method full names.
    """
    return _format(_get_rev().search_by_name(path, search))


@tool
def dotnet_get_call_flows(
    paths: t.Annotated[list[str], "Assembly paths to analyze"],
    method_name: t.Annotated[str, "Target method name to trace calls to"],
    max_depth: t.Annotated[int, "Maximum call graph depth"] = 10,
) -> str:
    """Trace call paths to a target method across assemblies.

    Builds a call graph showing how execution can reach the target
    method. Returns unique call paths as nested lists.
    """
    return _format(
        _get_rev().get_call_flows_to_method(paths, method_name, max_depth)
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
    from dotnet_agent.download import download_nuget_package

    kwargs: dict[str, t.Any] = {"package": package}
    if version:
        kwargs["version"] = version
    if output_dir:
        kwargs["output_dir"] = Path(output_dir)

    result_path = await download_nuget_package(**kwargs)
    return f"Package extracted to: {result_path}"
