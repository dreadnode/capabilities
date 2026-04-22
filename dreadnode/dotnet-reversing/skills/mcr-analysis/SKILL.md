---
name: mcr-analysis
description: Use when analyzing .NET applications from Microsoft Container Registry (MCR) images without running containers.
---

# MCR Container Image Analysis

Extract and analyze .NET assemblies from Microsoft Container Registry images without executing any container code. Uses pure HTTP—no Docker required.

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

## Critical Rules

**DO:**
- Always use `mcr_list_tags` before `mcr_pull_and_extract` to pick the right version
- Use specific version tags (e.g., `8.0.25`) not floating tags (`8.0`, `latest`)
- After extraction, immediately run `dotnet_scan_binaries` on the output directory
- Prioritize `/app/` assemblies over runtime assemblies when analyzing app images

**DO NOT:**
- Skip the extraction step and try to analyze MCR URLs directly — you must extract first
- Use `latest` tag for security analysis — it changes over time
- Forget to note the output directory path from `mcr_pull_and_extract`

## Tips

- **Version pinning**: Use specific tags like `8.0.25` instead of `8.0` or `latest` for reproducibility
- **Cache reuse**: Repeated extractions of the same image skip the download
- **Large images**: SDK images are huge (~800MB); prefer runtime/aspnet images when possible
