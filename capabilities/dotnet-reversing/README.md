# dotnet-reversing

ILSpy-backed decompilation and static analysis for .NET assemblies (`.dll` / `.exe`). One agent (`dotnet-reversing-agent`) over a Python toolset that drives [ILSpy](https://github.com/icsharpcode/ILSpy) through `pythonnet`/CoreCLR: scan a directory for binaries, walk namespaces and types, decompile a type or specific methods to C#, search IL operands for API usage, and trace call flows across assemblies to a target method. Targets don't have to be on disk — it can pull a NuGet package or extract .NET assemblies straight out of a Microsoft Container Registry image (HTTP-only, the container is never run).

**Shape:** one agent, two skills (`dotnet-reversing` for the decompilation workflow, `mcr-analysis` for MCR image extraction), and a Python `@tool` surface — no MCP server. The reversing tools run in a persistent subprocess pinned to **Python 3.12** (a `pythonnet` requirement); the parent process proxies calls to it over a local HTTP port.

## Setup

There is no manifest config to fill in — the toolset **bootstraps its own backend on first use**. The first `dotnet_*` tool call spawns the subprocess (via `uv run --python 3.12 --with pythonnet`), and that subprocess downloads, if not already present:

| Component | Version | Source |
|---|---|---|
| .NET runtime (runtime-only, no SDK) | channel `8.0` | `dot.net/v1/dotnet-install.sh` (~100 MB) |
| ILSpy decompiler DLLs (`ICSharpCode.Decompiler.dll`, `Mono.Cecil.dll`) | `8.2.0.7535` | ILSpy GitHub releases |
| `pythonnet` | `>=3.0.5` | pip / uv |

The download is **one-time and idempotent** — subsequent runs detect the installed DLLs and skip it. Dependencies land in a persistent deps directory so they survive sandbox restarts: `/home/user/workspace/.dreadnode/deps` in the Dreadnode sandbox (when `DREADNODE_SANDBOX` is set or the workspace is an S3 mount), `~/.dreadnode/deps` locally. The bootstrap sets `DOTNET_ROOT` and the ILSpy lib path itself; you don't configure them.

Prerequisites the bootstrap does **not** install for you: `uv` (used to launch the 3.12 subprocess; a `python3.12` with `pythonnet` already present is the fallback), plus `curl` and `unzip` for the downloads. First call needs outbound network to Microsoft and GitHub.

`CAPABILITY_PORT` (default `9797`) overrides the subprocess HTTP port if it collides; a free port is auto-selected otherwise.

## Scope

- **Targets:** managed .NET assemblies — `.dll` and `.exe`. Decompilation is ILSpy's; obfuscated or AOT/native-compiled binaries decompile poorly or not at all.
- **Read-only.** Tools decompile and inspect; nothing patches or writes to the target. Reporting tools persist findings to the Dreadnode platform.
- **NuGet & MCR** are convenience fetchers — `dotnet_download_nuget` pulls from nuget.org, the `mcr_*` tools extract layers from `mcr.microsoft.com` over HTTP without Docker and without executing the image.

`secure-software` hands off to this capability for .NET assemblies found inside packages (its tools surface under the `dotnet_*` namespace); agent-facing usage — the decompilation and vuln-hunting workflow, tool-by-tool — lives in `skills/`, not here.
