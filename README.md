<p align="center">
    <img
    src="https://d1lppblt9t2x15.cloudfront.net/logos/5714928f3cdc09503751580cffbe8d02.png"
    alt="Logo"
    align="center"
    width="144px"
    height="144px"
    />
</p>

<h3 align="center">
Dreadnode Capabilities
</h3>

<h4 align="center">
    <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/dreadnode/capabilities/ci.yml?label=ci">
    <img alt="Security Scan" src="https://img.shields.io/github/actions/workflow/status/dreadnode/capabilities/security-scan.yml?label=security-scan">
    <img alt="Sync" src="https://img.shields.io/github/actions/workflow/status/dreadnode/capabilities/sync.yml?label=sync">
</h4>

</br>

A capability is a portable bundle that extends a Dreadnode runtime with everything an agent needs to do a job — agent prompts, Python tools, skills, MCP servers, background workers, and sandbox setup — driven by a single `capability.yaml`. This repository is the public source of the capabilities Dreadnode authors and ships to the platform.

```yaml
# capability.yaml
schema: 1
name: web-recon
version: "0.1.0"
description: Basic host reconnaissance.
```

```python
# tools/lookup.py
import typing as t
from dreadnode import tool

@tool
def lookup_host(host: t.Annotated[str, "Hostname or IP to look up"]) -> dict[str, str]:
    """Resolve a host and return basic metadata."""
    return {"host": host, "status": "reachable"}
```

That's a working capability. The loader auto-discovers `agents/`, `tools/`, `skills/`, and `mcp/` from the directory, so the manifest stays small.

## Where capabilities run

- **Platform catalog** — browse and install everything published to your workspace at [app.dreadnode.io/capabilities](https://app.dreadnode.io/capabilities).
- **TUI capability manager** — open `dn`, press `Ctrl+P` to install, enable, and inspect capabilities on a running runtime.
- **Local checkout** — drop a capability directory in `~/.dreadnode/capabilities/` (or anywhere on `DREADNODE_CAPABILITY_DIRS`) and the runtime picks it up.

Every capability in this repo syncs to the platform on push to `main` via the [sync workflow](.github/workflows/sync.yml).

## Documentation

Full reference for the manifest, components, discovery rules, installation, and publishing lives in the docs:

**[docs.dreadnode.io/capabilities/overview](https://docs.dreadnode.io/capabilities/overview/)**

For an end-to-end walkthrough — scaffold, write a tool and an agent, install locally, drive it from the TUI — start with the [Quickstart](https://docs.dreadnode.io/capabilities/quickstart/).

## Local development

Validate every manifest in the repo:

```bash
just validate
```

Mirror the repo into your local capability store so a `dn` runtime sees the changes:

```bash
just sync-dreadnode-files   # rsyncs capabilities/* into ~/.dreadnode/capabilities/
```

Pre-commit hooks run `ruff`, `ruff-format`, `check-yaml`, and `gitleaks`. Don't bypass them — fix the underlying issue.

## Security scanning

Every skill in this repo is scanned with [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) for prompt injection, data exfiltration, tool-chaining abuse, and supply chain risk. CI fails on HIGH+ findings and uploads SARIF reports to GitHub Code Scanning. The repo policy in [`scan-policy.yaml`](scan-policy.yaml) tunes the scanner for security-focused content.

```bash
just security-scan                    # scan all capabilities
just security-scan web-security       # scan one capability
just security-scan behavioral="true"  # deep dataflow analysis
```

## Contributing

This repo is published for reference, not as a contribution target — we don't generally accept external PRs that add new capabilities. See [CONTRIBUTING.md](CONTRIBUTING.md) for what's useful to send and how to build your own capabilities instead.

## License

Each capability declares its own license in its `capability.yaml`. Most are MIT — check the manifest of the capability you're using.
