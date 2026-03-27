# Mythic C2 Read-Only

Read-only Mythic C2 integration. Query callbacks, task history, credentials, downloaded files, artifacts, and more — without executing any commands or modifying Mythic state.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- Network access to a Mythic C2 instance

## Configuration

Set environment variables for your Mythic instance:

```bash
export MYTHIC_SERVER_IP="10.1.10.99"
export MYTHIC_SERVER_PORT="7443"

# Choose one:
export MYTHIC_PASSWORD="your-password"
# OR
export MYTHIC_API_TOKEN="your-api-token"

# Optional:
export MYTHIC_USERNAME="mythic_admin"  # default: mythic_admin
```

For Claude Code, add to `.claude/settings.json`:

```json
{
  "env": {
    "MYTHIC_SERVER_IP": "10.1.10.99",
    "MYTHIC_SERVER_PORT": "7443",
    "MYTHIC_PASSWORD": "your-password"
  }
}
```

## Quick Start

```bash
uv run skills/mythic-c2-readonly/scripts/mythic_read.py status
uv run skills/mythic-c2-readonly/scripts/mythic_read.py callbacks
uv run skills/mythic-c2-readonly/scripts/mythic_read.py tasks --callback 1
uv run skills/mythic-c2-readonly/scripts/mythic_read.py credentials
uv run skills/mythic-c2-readonly/scripts/mythic_read.py search administrator
```

## Multi-User Setup

Each user sets their own env vars. No shared configuration needed.

## Available Commands

Run `uv run scripts/mythic_read.py --help` for full usage.

| Command | Purpose |
|---------|---------|
| `status` | Connection info |
| `callbacks` | List agent connections |
| `callback <id>` | Full callback details |
| `tasks` | Command history |
| `task-output <id>` | Decoded command output |
| `credentials` | Discovered credentials |
| `files` | Downloaded/uploaded files |
| `file-contents <uuid>` | Read file contents |
| `artifacts` | IOCs generated |
| `keylogs` | Keylog data |
| `screenshots` | Screenshot metadata |
| `processes` | Process listings |
| `file-browser` | File system data |
| `tokens` | Token data |
| `search <term>` | Cross-type search |

Add `--detail` or `--json` to any command for full raw output.
