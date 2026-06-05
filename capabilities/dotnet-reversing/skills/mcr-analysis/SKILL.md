---
name: mcr-analysis
description: Use when analyzing .NET applications from Microsoft Container Registry (MCR) images without running containers.
---

# MCR Container Image Analysis

Extract and analyze .NET assemblies from Microsoft Container Registry images
without executing any container code. Uses pure HTTP—no Docker required.

Load the `vuln-assessment-methodology` skill alongside this one for severity
calibration, disprove-first discipline, and the quality checklist.

## When to Use MCR Tools

Use MCR tools when:
- Target is an MCR image reference (e.g., `dotnet/aspnet:8.0`, `azure-functions/dotnet:4`)
- You need to analyze a specific .NET runtime version
- Investigating Azure/Microsoft container-based services

Use standard `dotnet_*` tools directly when you already have DLL/EXE files on disk.

## Quick Start

```
mcr_search_repositories(query="dotnet")                    # find repos
mcr_list_tags(repository="dotnet/aspnet", filter_pattern="8.0")  # list versions
mcr_pull_and_extract(image="dotnet/aspnet:8.0")            # extract DLLs
dotnet_scan_binaries(path="~/workspace/mcr/dotnet_aspnet_8.0")  # analyze
```

## Tools

| Tool | Purpose |
|------|---------|
| `mcr_search_repositories(query)` | Search ~3,200 MCR repos by name |
| `mcr_list_tags(repository, filter_pattern?, include_windows?)` | List image tags, sorted by version |
| `mcr_pull_and_extract(image, platform?, dll_only?)` | Extract .NET binaries from image. Platform default: `linux/amd64`, also `linux/arm64`. |

## MCR Repository Structure

| Repository | Contents |
|------------|----------|
| `dotnet/runtime` | .NET runtime only (~168 DLLs) |
| `dotnet/aspnet` | ASP.NET Core + runtime (~307 DLLs) |
| `dotnet/sdk` | Full SDK + runtime + tools |
| `dotnet/nightly/*` | Preview/nightly builds |
| `azure-functions/*` | Azure Functions runtime |
| `appsvc/*` | Azure App Service images |

Use `mcr_search_repositories` to discover repos beyond these — the catalog has
~3,200 entries across Azure services, infrastructure, and tooling.

## Not All MCR Images Are .NET

Many MCR images use Go, Python, TypeScript, or Rust. Extraction will return
"No .NET assemblies found" for these. This is common for infrastructure and
networking components (CNI plugins, proxies, tunnels, AI/ML runtimes).

If extraction fails:
1. Try `dll_only=false` — some images use AOT compilation or non-standard layouts
2. Try a different platform (`linux/arm64` vs `linux/amd64`)
3. Accept that the image may not contain .NET code and move on

## Workflow

### 1. Find the Target Image

```
mcr_search_repositories(query="azure-functions")
```

### 2. List Available Tags

```
mcr_list_tags(repository="azure-functions/dotnet", filter_pattern="8")
```

Tags are sorted newest-first. Prefer specific version tags (e.g., `8.0.25`) over `latest`.

### 3. Extract Assemblies

```
mcr_pull_and_extract(image="azure-functions/dotnet:4-dotnet8")
```

Output goes to `~/workspace/mcr/{repo}_{tag}/`. Extractions are cached — repeated calls skip the download.

### 4. Analyze Extracted Assemblies

```
dotnet_scan_binaries(path="~/workspace/mcr/azure-functions_dotnet_4-dotnet8")
dotnet_list_namespaces(path="~/workspace/mcr/.../TargetAssembly.dll")
dotnet_search_references(path="~/workspace/mcr/.../TargetAssembly.dll", search="SqlCommand")
```

For app images (`appsvc/*`, `azure-functions/*`), prioritize assemblies under `/app/` over runtime DLLs. For runtime images (`dotnet/runtime`, `dotnet/aspnet`), target `System.Private.CoreLib.dll` or `Microsoft.AspNetCore.dll` directly.

## MCR-Specific Attack Surface

When analyzing assemblies extracted from MCR images, look for these in addition
to standard .NET vulnerability patterns:

1. **ONNX/ML model loading** — Path traversal in model file paths
2. **ANSI/terminal parsers** — Escape sequence injection breaking HTML context
3. **Protobuf/gRPC handling** — Oversized message DoS, recursive depth bombs
4. **URL parsers** — Scheme bypass, authority confusion, attribute breakout

## Prioritizing MCR Repos for Security Analysis

Not all MCR repos are equally interesting. Prioritize:

**Highest value:**
- New products/services (few tags, v0.x/v1.x — less mature, less audited)
- API gateways and reverse proxies (parse untrusted HTTP — smuggling, injection)
- Auth/identity services (JWT, certificate, token handling)
- Database access layers (SQL injection, query injection)
- AI/ML services (model loading, prompt handling, inference pipelines)

**Medium value:**
- Emulators (often have weaker auth than production counterparts)
- Internal/SRE tools (may rely on network isolation instead of auth)
- Monitoring/observability dashboards (render untrusted telemetry data)

**Lower value:**
- Mature Microsoft runtime images (dotnet/runtime, dotnet/aspnet — heavily audited)
- Helm charts and Bicep modules (infrastructure-as-code, not runtime code)
- Build tools and SDKs (not typically internet-facing)

## Delegating Analysis to Subagents

When dispatching subagents to analyze extracted assemblies:

1. **Load the analysis guidance** — ensure subagents have both the
   `dotnet-reversing` and `vuln-assessment-methodology` skills loaded
2. **Tell them what NOT to report** — share known false-positive patterns
   from previous analysis of similar codebases
3. **Specify the application assemblies** — list the non-framework DLLs
   explicitly so they don't waste time on Microsoft.AspNetCore.* etc.
4. **Set threat model context** — tell them if the target is public-facing,
   internal, or a dev tool so they assign severity appropriately
5. **Require disproof attempts** — instruct subagents to try to disprove
   each finding before reporting it

## Critical Rules

**DO:**
- Always use `mcr_list_tags` before `mcr_pull_and_extract` to pick the right version
- Use specific version tags (e.g., `8.0.25`) not floating tags (`8.0`, `latest`)
- After extraction, immediately run `dotnet_scan_binaries` on the output directory
- Prioritize `/app/` or `/emulator/` assemblies over runtime assemblies
- Try `dll_only=false` if default extraction finds nothing
- Check tag counts and version numbers to gauge maturity (few tags = newer = less audited)

**DO NOT:**
- Skip the extraction step and try to analyze MCR URLs directly
- Use `latest` tag for security analysis — it changes over time
- Assume extraction failure means the image is empty — it may not be .NET
- Dispatch subagents without the analysis guidance loaded

## Tips

- **Version pinning**: Use specific tags like `8.0.25` instead of `8.0` or `latest` for reproducibility
- **Cache reuse**: Repeated extractions of the same image skip the download
- **Large images**: SDK images are huge (~800MB); prefer runtime/aspnet images when possible
- **Parallel extraction**: Extract multiple images simultaneously while waiting for results
- **Cross-reference tags**: Repos with very few tags or only `latest` are brand new — potentially less audited
