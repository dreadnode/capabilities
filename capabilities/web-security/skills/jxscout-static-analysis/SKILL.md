---
name: jxscout-static-analysis
description: Query and manage jxscout static analysis matches -- list match kinds, get matches with filters, mark matches as seen/unseen. Use when investigating code patterns, exploring the attack surface, or tracking review progress across match results.
license: proprietary
metadata:
  source: jxscout-pro-v2
  author: francisconeves97
  origin: ported from jxscout-pro-v2 agent skills
---

# jxscout Static Analysis (Matches)

jxscout runs static analyzers on every ingested JS and HTML file. Results are **matches** -- structured data pointing to patterns (paths, URLs, secrets, sinks). Query them during investigation alongside direct code search for patterns analyzers don't cover.

## Prerequisites

The `JXSCOUT_PROJECT_NAME` environment variable must be set. It is available in the project's `.env` file at the root of the working directory. All commands use `jxscout-pro-v2 -c` (client mode).

## Commands

### List available match kinds

```bash
jxscout-pro-v2 -c list-match-kinds --json
```

Returns a JSON array of all enabled match kind strings for the project. Run this to know what's available -- the list depends on the project's analyzer configuration and may include custom match kinds.

Common built-in match kinds: `path`, `api_path`, `hostname`, `url`, `secret`, `onmessage`, `html_manipulation`, `npm_package`, `url_search_params`, `location_assignment`.

### Get matches

```bash
jxscout-pro-v2 -c get-matches --match-kind <kind> [options]
```

**Required:**
- `--match-kind <kind>` -- the match kind to query (from `list-match-kinds`)

**Options:**
- `--json` -- output as JSON array with file paths, positions, values, and seen status (strongly recommended)
- `--limit <n>` -- max number of matches to return (JSON mode only)
- `--offset <n>` -- skip first n matches (JSON mode only)
- `--file-path-include <pattern>` -- only include matches from files matching this pattern (repeatable)
- `--file-type <type>` -- filter by file type: `js`, `html` (repeatable)
- `--value-include <substring>` -- only include matches whose value contains this substring (repeatable)
- `--show-only-unseen` -- only return matches that have not been marked as seen
- `--show-only-seen` -- only return matches that have been marked as seen

Without `--json`, the command outputs deduplicated match values (one per line). With `--json`, each match includes:

```json
{
  "id": 42,
  "match_kind": "path",
  "match_value": "/api/v2/users",
  "position": { "start": { "line": 42, "column": 10 }, "end": { "line": 42, "column": 26 } },
  "file_type": "js",
  "file_path": "/path/to/file.js",
  "seen": false
}
```

### Mark matches as seen

```bash
jxscout-pro-v2 -c mark-matches-seen --match-ids 1,2,3
```

Mark specific matches by ID. Use this after reviewing matches to track progress.

**Bulk mode** -- mark all matches of a kind (with optional filters):

```bash
jxscout-pro-v2 -c mark-matches-seen --match-kind path
jxscout-pro-v2 -c mark-matches-seen --match-kind path --value-include "admin"
jxscout-pro-v2 -c mark-matches-seen --match-kind path --file-path-include "auth"
```

Bulk mode supports the same filters as `get-matches`: `--file-path-include`, `--file-type`, `--value-include`.

Returns JSON: `{"updated_count": N}`

### Mark matches as unseen

```bash
jxscout-pro-v2 -c mark-matches-unseen --match-ids 4,5,6
```

Same interface as `mark-matches-seen`. Use this to re-mark matches for review.

**Bulk mode:**

```bash
jxscout-pro-v2 -c mark-matches-unseen --match-kind path
```

Returns JSON: `{"updated_count": N}`

## Workflow

1. **Discover match kinds**: `jxscout-pro-v2 -c list-match-kinds --json`
2. **Query high-value kinds first**: `secret`, `onmessage`, `html_manipulation`, then `path`, `api_path`
3. **Use filters** to focus:
   - `--value-include "admin"` for admin-related paths
   - `--value-include "internal"` for internal endpoints
   - `--file-path-include "auth"` to scope to auth files
   - `--show-only-unseen` for unreviewed matches only
4. **Read the code** at match positions to understand context
5. **Mark as seen** after reviewing: `mark-matches-seen --match-ids <ids>`
6. **Grep for more**: matches only cover configured analyzers -- search directly for uncovered patterns

**Checkpoint:** After each triage session, verify all reviewed matches are marked seen. Use `get-matches --match-kind <kind> --show-only-unseen` to confirm only new/unreviewed items remain.

## HTTP request context

If `http_requests/` exists in the project working directory, jxscout has captured raw HTTP traffic from the target. The files are organized as `http_requests/{host}/{path}/{METHOD}/{timestamp}_{status}.req|.res` and contain raw HTTP request/response pairs.

Use these alongside static analysis to:
- **Cross-reference API calls**: match `path` or `api_path` results against actual captured requests to see real parameters, headers, and auth tokens in use
- **Discover endpoints not in JS**: some endpoints are only visible in server responses or redirects, not in client-side code
- **Understand real request patterns**: see actual `Content-Type`, auth headers, cookies, and request bodies that the application sends
- **Validate findings**: check if a pattern found via static analysis is actually exercised in real traffic

Browse `http_requests/` with `ls` / `find` and read individual `.req`/`.res` files to enrich your analysis.

## Limitations

Matches are only as good as the configured analyzers. Things that matches will NOT catch include:
- Dynamically constructed URLs or paths (e.g. `base + "/api/" + endpoint`)
- Patterns not covered by any enabled analyzer
- Logic bugs, race conditions, or business logic flaws

When investigating a specific area, always combine match queries with direct code search (grep/ripgrep) to get the full picture. If you find a pattern worth tracking systematically, consider creating a custom analyzer for it.
