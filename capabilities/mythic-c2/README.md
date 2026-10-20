# mythic-c2

Integration with [Mythic](https://github.com/its-a-feature/Mythic) C2. **Observation-only by default** — read callbacks, tasks, credentials, files, artifacts, keylogs, screenshots, processes, tokens, BloodHound discovery, and operation summaries from a running Mythic server. Optional flags add active tasking, Apollo post-exploitation, and a background worker that writes AI findings back onto Mythic's own surfaces.

For a strictly read-only deployment with no active surface at all, use the sibling `mythic-c2-readonly`. This capability is the superset: the same observation surface, plus the opt-in active and triage features below.

## Setup

Point it at your Mythic server via the secrets screen (`/secrets`, F7) — these vars are shared by the MCP server and the worker:

| Var | Notes |
|---|---|
| `MYTHIC_SERVER_IP` | Mythic host (default `127.0.0.1`). |
| `MYTHIC_SERVER_PORT` | Mythic port. |
| `MYTHIC_USERNAME` / `MYTHIC_PASSWORD` | Operator login (username defaults to `mythic_admin`). |
| `MYTHIC_API_TOKEN` | Use instead of username/password if you have one. |

### Flags — all off by default

Off means observation-only; the capability does nothing active until you opt in (`/capabilities` → reload after changing).

| Flag | Registers | Risk |
|---|---|---|
| `tasking` | Generic `issue_task` + `list_callback_commands` — works for any payload type (Apollo, Poseidon, Merlin, …) | Issues live commands to implants |
| `apollo` | Apollo-specific multi-step helpers (`sharphound_and_download`, `powershell_script`, …) | Active post-exploitation |
| `triage` | The `task-annotator` worker — reviews completed tasks, keylogs, and downloads in the background and writes findings onto Mythic (task comments, severity/category tags, event log, cross-object `ai:trail` tags) | Mutates your Mythic operation's surfaces |

## Before you trust it

- **With `tasking` or `apollo` on, this executes post-exploitation** against live implants — not a reporting tool. Authorization and scope are yours.
- **The `triage` worker writes to your Mythic operation** — comments, tags, and event-log entries appear under the operator identity. It runs continuously while the flag is set (and exits cleanly on boot when unset).
- Three agents (`operator`, `correlator`, `task-analyzer`) drive these surfaces; their methodology lives in the agent prompts (`agents/`) and `docs/`, not here.
