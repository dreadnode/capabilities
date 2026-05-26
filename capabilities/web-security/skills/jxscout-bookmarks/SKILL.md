---
name: jxscout-bookmarks
description: Create jxscout bookmarks and bookmark groups via the CLI to document interesting code during security research. Use when analyzing JS/HTML files, reviewing findings, documenting client-side flows, or when the user asks to bookmark security-relevant code patterns, gadgets, or sinks.
license: proprietary
metadata:
  source: jxscout-pro-v2
  author: francisconeves97
  origin: ported from jxscout-pro-v2 agent skills
---

# jxscout Bookmarks

Bookmark interesting code during security research -- client-side flows, sinks, gadgets, postMessage handlers, authentication logic, request construction patterns, etc. Bookmarks appear in the VS Code extension sidebar with highlight decorations and markdown notes.

jxscout works with JS, HTML, and HTTP-related files. Bookmarks should point to code in these web assets.

## Prerequisites

The `JXSCOUT_PROJECT_NAME` environment variable must be set. It is available in the project's `.env` file at the root of the working directory. All commands use `jxscout-pro-v2 -c` (client mode).

## Commands

### Groups

#### List existing groups

```bash
jxscout-pro-v2 -c bookmark list-groups
```

Returns JSON array of `{ id, name, highlight_color, created_at }`.

#### Create a group

```bash
jxscout-pro-v2 -c bookmark create-group --name "postMessage handlers" --highlight-color "rgba(255,165,0,0.15)"
```

- `--name` -- descriptive category name
- `--highlight-color` -- optional CSS color string for code highlighting in VS Code (e.g. `rgba(255,0,0,0.1)`)

Returns JSON with the created group.

#### Update a group

```bash
jxscout-pro-v2 -c bookmark update-group --name "Old Name" --new-name "New Name" --highlight-color "rgba(0,255,0,0.1)"
```

Pass empty string to `--highlight-color` to clear it.

#### Delete a group

```bash
jxscout-pro-v2 -c bookmark delete-group --name "Group Name"
```

Deletes the group and all bookmarks in it.

### Bookmarks

#### Create a bookmark

```bash
jxscout-pro-v2 -c bookmark create \
  --group "postMessage handlers" \
  --file-path /absolute/path/to/file.js \
  --start-line 10 --start-column 0 \
  --end-line 15 --end-column 42 \
  --note "Accepts messages from any origin, passes event.data.url to location.href"
```

- `--group` -- group name (must already exist)
- `--file-path` -- absolute path to the file
- `--start-line`, `--end-line` -- 1-indexed line numbers
- `--start-column`, `--end-column` -- 0-indexed column numbers
- `--note` -- optional, supports markdown

#### List bookmarks

```bash
jxscout-pro-v2 -c bookmark list [--group "Group Name"] [--file-path /path/to/file.js]
```

Returns JSON array of all bookmarks, optionally filtered by group or file path.

#### Update a bookmark

```bash
jxscout-pro-v2 -c bookmark update --id <bookmark_id> [--group "New Group"] [--note "Updated note"] [--file-path /new/path] [--start-line N --start-column N --end-line N --end-column N]
```

Pass empty string to `--note` to clear it.

#### Delete a bookmark

```bash
jxscout-pro-v2 -c bookmark delete --id <bookmark_id>
```

## Workflow

1. Check existing groups: `jxscout-pro-v2 -c bookmark list-groups`
2. Create a group if none fits: `jxscout-pro-v2 -c bookmark create-group --name "XSS sinks"`
3. Create bookmarks with notes as you find interesting code

**Checkpoint:** After creating a group, run `bookmark list-groups` to verify. After creating bookmarks, run `bookmark list --group "Name"` to confirm.

## What to bookmark

Sinks, message handlers without origin checks, auth logic, request construction with user-controlled params, JSONP callbacks, DOM clobbering targets, multi-step flows (bookmark each step in same group with progression notes).

Bookmarks can also point to raw `.req`/`.res` files in `http_requests/` for marking interesting API calls or auth flows.

## Note guidelines

Notes should explain **why** the code is interesting. Notes support markdown.

- Good: "postMessage handler -- no origin check, passes `event.data.redirect` to `window.location`"
- Bad: "Event listener"
