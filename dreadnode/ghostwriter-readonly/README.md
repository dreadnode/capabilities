# GhostWriter Read-Only

Read-only GhostWriter integration. Query clients, projects, findings, objectives, targets, scope, deconflictions, evidence, observations, reports, infrastructure, activity logs, and notes — without modifying any GhostWriter state.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- Network access to a GhostWriter instance

## Configuration

Set environment variables for your GhostWriter instance:

```bash
export GHOSTWRITER_URL="https://10.2.10.100"

# Choose one:
export GHOSTWRITER_API_TOKEN="your-api-token"
# OR
export GHOSTWRITER_USERNAME="your-username"
export GHOSTWRITER_PASSWORD="your-password"
```

For Claude Code, add to `.claude/settings.json`:

```json
{
  "env": {
    "GHOSTWRITER_URL": "https://10.2.10.100",
    "GHOSTWRITER_API_TOKEN": "your-api-token"
  }
}
```

## Quick Start

```bash
uv run skills/ghostwriter-readonly/scripts/ghostwriter_read.py status
uv run skills/ghostwriter-readonly/scripts/ghostwriter_read.py clients
uv run skills/ghostwriter-readonly/scripts/ghostwriter_read.py projects
uv run skills/ghostwriter-readonly/scripts/ghostwriter_read.py findings --project 1
uv run skills/ghostwriter-readonly/scripts/ghostwriter_read.py search "SQL injection"
```

## Multi-User Setup

Each user sets their own env vars. No shared configuration needed.

## Available Commands

Run `uv run scripts/ghostwriter_read.py --help` for full usage.

| Command | Purpose |
|---------|---------|
| `status` | Connection info |
| `clients` | List client organizations |
| `client <id>` | Client details |
| `projects` | List projects/engagements |
| `project <id>` | Project details with findings |
| `findings` | List reported findings |
| `finding <id>` | Finding details |
| `finding-templates` | Finding template library |
| `objectives` | Project objectives |
| `targets` | Target hosts/systems |
| `scope` | Scope definitions |
| `deconflictions` | Deconfliction entries |
| `evidence` | Evidence files |
| `whitecards` | White cards / exceptions |
| `observations` | List observations |
| `reports` | List reports |
| `infrastructure` | Servers and domains summary |
| `servers` | List servers |
| `domains` | List domains |
| `activity-logs` | Operation logs |
| `notes <type>` | Notes (client/project/domain/server) |
| `search <term>` | Cross-type search |

Add `--detail` or `--json` to any command for full raw output.
