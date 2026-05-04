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

This is the source repo for the capabilities Dreadnode publishes to [app.dreadnode.io](https://app.dreadnode.io). A capability is a directory — a manifest plus any combination of agents, tools, skills, and MCP servers — that a Dreadnode runtime picks up and loads:

```text
ai-red-teaming/
  capability.yaml     # manifest
  agents/             # markdown prompts
  tools/              # python @tool functions
  skills/             # SKILL.md packs
```

## Install one

- **Published** — `dn capability install dreadnode/ai-red-teaming` (swap in any name from `capabilities/`)
- **From source** — `dn capability install ./capabilities/ai-red-teaming` symlinks the directory into your runtime, so edits go live on reload
- **From the TUI** — start `dn`, press `Ctrl+P`, filter for `dreadnode/`

`dn` is the Dreadnode CLI — see [getting-started](https://docs.dreadnode.io/getting-started/quickstart/) to install and authenticate. Full install reference for capabilities lives at [docs.dreadnode.io/capabilities/installing](https://docs.dreadnode.io/capabilities/installing/).

## Build your own

Every directory under `capabilities/` is a shipped, working example. Read one alongside the docs:

- [Concepts and load model](https://docs.dreadnode.io/capabilities/overview/)
- [Manifest reference](https://docs.dreadnode.io/capabilities/manifest/)
- [Quickstart](https://docs.dreadnode.io/capabilities/quickstart/) — scaffold to running in the TUI in about ten minutes

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

Each capability declares its license in its `capability.yaml`.
