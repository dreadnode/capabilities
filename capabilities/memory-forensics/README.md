# memory-forensics

A curated Volatility3 surface for memory forensics and DFIR triage over captured memory images. The `volatility` MCP wraps the Volatility3 CLI with action-named tools for the artifacts an analyst actually pivots through — process enumeration and tree, pool-tag scanning for hidden processes, network endpoints, code-injection (malfind), DLLs and handles, registry hives/keys, credential extraction (hashdump), services, YARA scanning, process dumping, and a cross-plugin timeline — plus an escape hatch (`volatility_run_plugin`) for the long tail. Windows / Linux / macOS images are all in scope; most tools take an `os_kind` you resolve once with `volatility_info`.

**Shape:** one agent (`forensics-analyst`, read-only DFIR posture), five skills (memory-triage, process-injection-hunt, credential-theft-hunt, persistence-hunt, yara-memory-hunting), one MCP server (`volatility`). Sibling `ios-forensics` is the same shape for iOS device images — this one is host memory.

## Setup

The MCP self-bootstraps via `uv run` (PEP 723 deps: `fastmcp`, `volatility3>=2.7`, `yara-python`), so `uv` is the only hard prerequisite (`checks:` enforces it). Volatility3 itself is pulled in by that bootstrap, but you can point at a system install instead — the server resolves the command in this order:

1. `VOLATILITY_COMMAND` if set (e.g. `vol`, or a full command string)
2. `vol` on `PATH`
3. the `volatility3.cli` entry point under the bootstrapped interpreter

So no separate install is required for a default run; set `VOLATILITY_COMMAND` only when you want a specific `vol` (e.g. a build with extra community plugins).

**Symbol tables are the classic friction.** Vol3 fetches PDBs from the Microsoft symbol server on the first plugin run against a Windows image, and Linux/Mac images need a matching ISF symbol table. First-run plugins on a fresh host will hang or fail until symbols resolve. For air-gapped or offline work, prime a symbol cache and pass it through the escape hatch (`volatility_run_plugin` with Vol3's `-s <dir>` / `--offline`) — the curated tools don't expose a symbol-dir flag of their own. See [Volatility3 Symbol Tables](https://volatility3.readthedocs.io/en/stable/symbol-tables.html).

**Image formats:** raw/padded images and the formats Vol3 reads natively — `.mem`, `.raw`, `.vmem`, `.dmp`, `.lime`, `.bin`, `.aff4`. Pass an absolute path; the server checks the file exists before invoking Vol3.

| Var | Default | Notes |
|---|---|---|
| `VOLATILITY_COMMAND` | unset | Force a specific `vol` command; otherwise resolved as above. |
| `VOLATILITY_TIMEOUT` | `600` | Per-plugin timeout (seconds). Long plugins (`memmap`, `timeliner`, whole-image `yarascan`) blow this on multi-GB images — scope by `--pid` first, then raise. |
| `VOLATILITY_MAX_OUTPUT_CHARS` | `200000` | Tool output is truncated past this; raise for verbose plugins. |

Configure these through the deployer environment (secrets/settings screen or web app — no `.env` autoload).

## Before you trust it

- **Symbols gate everything.** A plugin that "returns nothing" on first run is often an unresolved symbol table, not a clean image — confirm `volatility_info` succeeds before reading absence as signal.
- **JSON schemas drift across Vol3 versions.** `-r json` field names are stable within a minor version but not across; `volatility_list_plugins` shows what the local Vol3 actually ships before you rely on a plugin name.
- **Read-only by design** — the agent acquires nothing and modifies no evidence; the one writing tool (`volatility_dump_process`) only emits carved artifacts into an `output_dir` you name.
- **`volatility_dump_process` `pe` mode** routes through `pslist` rather than a dedicated dumper; `vad` (the default) is the right mode for hunting injected regions.

Tests: `mcp/test_server.py` covers helpers and tool registration. The analysis playbooks (which plugin to run when, MITRE mapping, hunt sequencing) live in `skills/`, not here.
