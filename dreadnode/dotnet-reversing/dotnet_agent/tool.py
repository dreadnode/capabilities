#!/usr/bin/env python3
"""
Persistent HTTP server for .NET analysis tools.

Loads pythonnet and ILSpy once at startup, then serves tool requests
via HTTP. Started as a capability client by dreadcode.

On first run, bootstraps dependencies automatically:
- .NET 8.0 runtime (via dotnet-install.sh)
- ILSpy decompiler DLLs (via NuGet restore)

The port is configured via CAPABILITY_PORT environment variable (default: 9797).
"""

import json
import os
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DOTNET_ROOT = Path(os.environ.get("DOTNET_ROOT", Path.home() / ".dotnet"))
LIB_DIR = Path(
    os.environ.get(
        "DOTNET_TOOLS_LIB_DIR",
        str(Path.home() / ".dreadnode" / "dotnet-agent" / "lib"),
    )
)
PORT = int(os.environ.get("CAPABILITY_PORT", "9797"))

# ---------------------------------------------------------------------------
# Bootstrap — install .NET runtime + ILSpy if missing
# ---------------------------------------------------------------------------


def _dotnet_installed() -> bool:
    dotnet_bin = DOTNET_ROOT / "dotnet"
    return dotnet_bin.exists()


def _ilspy_installed() -> bool:
    return (LIB_DIR / "ICSharpCode.Decompiler.dll").exists()


def _install_dotnet() -> None:
    """Install .NET 8.0 runtime via the official install script."""
    print("Installing .NET 8.0 runtime...", file=sys.stderr, flush=True)
    install_script = Path("/tmp/dotnet-install.sh")
    subprocess.run(
        ["curl", "-fsSL", "https://dot.net/v1/dotnet-install.sh", "-o", str(install_script)],
        check=True,
    )
    install_script.chmod(0o755)
    subprocess.run(
        [
            str(install_script),
            "--channel", "8.0",
            "--runtime", "dotnet",
            "--install-dir", str(DOTNET_ROOT),
        ],
        check=True,
    )
    install_script.unlink(missing_ok=True)
    print(f".NET runtime installed to {DOTNET_ROOT}", file=sys.stderr, flush=True)


def _install_ilspy() -> None:
    """Install ILSpy decompiler DLLs via a temporary dotnet project + NuGet restore."""
    print("Installing ILSpy decompiler libraries...", file=sys.stderr, flush=True)

    # Need the SDK temporarily for `dotnet restore`
    install_script = Path("/tmp/dotnet-install.sh")
    subprocess.run(
        ["curl", "-fsSL", "https://dot.net/v1/dotnet-install.sh", "-o", str(install_script)],
        check=True,
    )
    install_script.chmod(0o755)
    subprocess.run(
        [str(install_script), "--channel", "8.0", "--install-dir", str(DOTNET_ROOT)],
        check=True,
    )
    install_script.unlink(missing_ok=True)

    dotnet_bin = str(DOTNET_ROOT / "dotnet")
    env = {**os.environ, "DOTNET_ROOT": str(DOTNET_ROOT), "PATH": f"{DOTNET_ROOT}:{os.environ.get('PATH', '')}"}

    tmp_dir = Path("/tmp/ilspy-restore")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run([dotnet_bin, "new", "console", "--no-restore"], cwd=str(tmp_dir), env=env, check=True)
        subprocess.run(
            [dotnet_bin, "add", "package", "ICSharpCode.Decompiler", "--version", "8.2.0.7535"],
            cwd=str(tmp_dir), env=env, check=True,
        )
        subprocess.run([dotnet_bin, "restore"], cwd=str(tmp_dir), env=env, check=True)

        LIB_DIR.mkdir(parents=True, exist_ok=True)
        nuget_dir = Path.home() / ".nuget" / "packages"

        # Copy ILSpy + Mono.Cecil DLLs
        for pkg, subpath in [
            ("icsharpcode.decompiler", "net8.0"),
            ("system.reflection.metadata", "net8.0"),
            ("mono.cecil", "netstandard2.0"),
        ]:
            pkg_dir = nuget_dir / pkg
            if not pkg_dir.exists():
                continue
            for dll in pkg_dir.rglob(f"*/{subpath}/*.dll"):
                shutil.copy2(dll, LIB_DIR / dll.name)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Clean up SDK (keep runtime only)
    for d in ["sdk", "templates"]:
        p = DOTNET_ROOT / d
        if p.exists():
            shutil.rmtree(p)
    nuget_cache = Path.home() / ".nuget"
    if nuget_cache.exists():
        shutil.rmtree(nuget_cache)

    print(f"ILSpy DLLs installed to {LIB_DIR}", file=sys.stderr, flush=True)


def bootstrap() -> None:
    """Ensure .NET runtime and ILSpy DLLs are present."""
    if not _dotnet_installed():
        _install_dotnet()
    if not _ilspy_installed():
        _install_ilspy()

    # Set env for pythonnet
    os.environ["DOTNET_ROOT"] = str(DOTNET_ROOT)
    os.environ["PATH"] = f"{DOTNET_ROOT}:{os.environ.get('PATH', '')}"
    os.environ["DOTNET_TOOLS_LIB_DIR"] = str(LIB_DIR)


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

    COMMANDS.update({
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
        "dotnet_download_nuget": lambda **kwargs: str(asyncio.run(download_nuget_package(**kwargs))),
    })


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
    bootstrap()
    _load_tools()
    print(f"dotnet capability ready on port {PORT}", file=sys.stderr, flush=True)
    server = HTTPServer(("127.0.0.1", PORT), ToolHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
