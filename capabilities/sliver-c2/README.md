# sliver-c2

Wires a [Sliver](https://github.com/BishopFox/sliver) C2 server into chat and agents over the `sliver-py` SDK. Covers operator-side server management (list sessions/beacons, start mTLS/HTTPS/HTTP/DNS listeners, kill jobs, regenerate implants) and full implant post-exploitation against the active session/beacon — file ops, process control, `execute-assembly`, shellcode injection, sideloading, token manipulation, registry r/w, and LSASS-style process dumps. This is **active offense, not telemetry**: unlike the `mythic-c2`/`mythic-c2-readonly` split there is no read-only mode here — every implant tool runs commands on and mutates the target.

## Setup

The MCP connects with a Sliver **operator config** (`.cfg`) — the file `new-operator` mints, carrying the embedded mTLS client cert/key and the server address. Resolution order:

1. `SLIVER_CONFIG_FILE` — explicit path to a `.cfg`.
2. Auto-discovery — newest `*.cfg` in `~/.sliver-client/configs/` (where the Sliver client drops imported operator configs).

For a remote server, enable **Multiplayer Mode** on the server, generate an operator config, and point `SLIVER_CONFIG_FILE` at it. For Claude Code, set it in `.claude/settings.json`:

```json
{ "env": { "SLIVER_CONFIG_FILE": "/path/to/operator.cfg" } }
```

`SLIVER_TIMEOUT` (default `60` s) bounds per-call gRPC waits; raise it for slow beacons or large transfers. The `connect` tool re-points at a config at runtime; `interact(implant_id, implant_type=)` selects the active implant before any post-ex tool.

## Before you trust it

- **Active-only, no guardrail.** The server has no read-only flag — `rm`, `execute_shellcode`, `get_system`, `process_dump`, `registry_write` all mutate the target the moment they're called. Only run against engagements you're **explicitly authorized** to operate, and treat agent autonomy here as live tradecraft.
- **One implant at a time.** `interact()` sets a single global active session/beacon; post-ex tools act on whatever was last selected.
- **Beacons are async.** Calls against a beacon block until its next check-in (interval + jitter), so they can hang for a while — size `SLIVER_TIMEOUT` accordingly.
- **Wraps `sliver-py`, not the upstream MCP.** Sliver ships its own experimental `sliver-client mcp` (stdio/HTTP-SSE); we deliberately build on the stable `sliver-py` SDK instead for a curated, typed tool surface.

`docs/sliver/` is a vendored snapshot of the official Sliver wiki (GPLv3, see `docs/sliver/LICENSE`) for reference. Agent-facing tradecraft — sessions-vs-beacons posture, post-ex workflow, OPSEC — lives in `skills/sliver-c2/`, not here.
