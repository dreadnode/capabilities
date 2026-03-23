---
name: jxscout-bookmarks
description: Create jxscout bookmarks and bookmark groups via the CLI to document interesting code during security research. Use when analyzing JS/HTML files, reviewing findings, documenting client-side flows, or when the user asks to bookmark security-relevant code patterns, gadgets, or sinks.
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

## When to bookmark

Bookmark things the user would want to review or come back to:

- **Sinks**: `innerHTML` assignments, `document.write`, `eval`, `location.href` assignments with user-controlled input
- **Message handlers**: `window.addEventListener("message", ...)` -- especially without origin checks
- **Auth logic**: token validation, session handling, role checks in client-side code
- **Request construction**: places where API calls are built, especially with user-controlled parameters
- **Interesting gadgets**: JSONP callbacks, script injection points, DOM clobbering targets
- **Data flows**: where sensitive data moves from one component to another
- **Multi-step flows**: authentication sequences, payment flows, cross-origin communication chains, OAuth handshakes. Bookmark each step in the same group with notes describing the progression (e.g. "Step 1: redirect_uri parsed from query", "Step 2: passed to OAuth authorize endpoint without validation"). This makes complex flows reviewable as a sequence rather than scattered across files.
- **Interesting functionality**: admin panels, feature flags, internal tools, debug endpoints -- anything that reveals capabilities or attack surface worth revisiting

## Note quality

Notes should explain **why** the code is interesting, not just describe what it does.

Good notes:
- "postMessage handler -- no origin check, passes `event.data.redirect` to `window.location`"
- "Constructs API URL with user-controlled `req.query.callback` -- potential JSONP abuse"
- "JWT decoded client-side without signature verification, role extracted from payload"

Bad notes:
- "This is a function"
- "Event listener"
- "API call"

## Bookmarking HTTP request/response files

If `http_requests/` exists in the project working directory, bookmarks can also point to raw `.req`/`.res` files captured by jxscout -- not just JS/HTML code. This is useful for marking interesting API calls, auth flows, or responses that contain relevant security data (tokens, error messages, internal paths).

## Tips

- Notes support markdown -- use code blocks, links, and formatting freely.
- Reuse existing groups when the category fits; create new ones for distinct themes.
- When bookmarking a function or block, include the full range (first to last line).
- Use highlight colors to visually distinguish different risk levels or categories in VS Code.
