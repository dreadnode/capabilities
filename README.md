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

This repo maintains the source for all our capabilities published to [app.dreadnode.io](https://app.dreadnode.io).

Full reference for the manifest, components, discovery rules, installation, and publishing lives in the docs:

**[docs.dreadnode.io/capabilities/overview](https://docs.dreadnode.io/capabilities/overview/)**

For an end-to-end walkthrough — scaffold, write a tool and an agent, install locally, drive it from the TUI — start with the [Quickstart](https://docs.dreadnode.io/capabilities/quickstart/).

## How to use

- **Install in the TUIr** — start `dn`, press `Ctrl+P` and find one of the `dreadnode/` capabilities.
- **Browse the catalog** — interactively browse everything published at [app.dreadnode.io](https://app.dreadnode.io).
- **Local checkout** — drop a capability directory in `~/.dreadnode/capabilities/` (or anywhere on `DREADNODE_CAPABILITY_DIRS`) and the runtime picks it up.

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
