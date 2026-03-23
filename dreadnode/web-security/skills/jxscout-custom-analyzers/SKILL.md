---
name: jxscout-custom-analyzers
description: Create custom jxscout analyzers (regex, derived, or script-based) and retrigger analysis. Use when the user wants to find specific code patterns across all project files, add new match kinds, or extend jxscout's static analysis capabilities.
---

# jxscout Custom Analyzers

jxscout supports custom analyzers that you can add to a project's configuration. These run alongside the built-in analyzers and generate new match kinds that appear in the VS Code extension and are queryable via `get-matches`.

There are three types: **regex**, **derived**, and **script**. All are configured in the project's `settings.jsonc` under `analyzer > custom_analyzers`.

## Prerequisites

The `JXSCOUT_PROJECT_NAME` environment variable must be set. The project settings file is at `<working_directory>/settings.jsonc`. All commands use `jxscout-pro-v2 -c` (client mode).

## Choosing the right analyzer type

For JS/TS code pattern matching (function calls, assignments, data flow, control structures), **prefer AST-based analysis via script analyzers** (e.g. semgrep) over regex. Regex works for simple literal patterns -- hardcoded URLs, API keys, specific strings -- but is fragile for code constructs because it misses variations in whitespace, formatting, nesting, and comments.

Rule of thumb:
- **Regex**: simple string patterns that don't depend on code structure
- **Derived**: narrowing down an existing match kind by value
- **Script (semgrep)**: anything involving code semantics -- function calls, assignments, data flow, missing checks

## Analyzer types

### Regex analyzer

Pattern-matches source code with one or more regexes. Good for simple literal patterns (URLs, API keys, specific strings) but fragile for code constructs.

```json
{
  "analyzer": {
    "custom_analyzers": {
      "sensitive_fetch": {
        "enabled": true,
        "type": "regex",
        "file_types": ["js", "reversed_source"],
        "match_kind": "sensitive_fetch",
        "regex_list": ["fetch\\s*\\([^)]*\\/api\\/admin", "fetch\\s*\\([^)]*\\/internal"]
      }
    }
  }
}
```

- `file_types`: which files to scan -- `js`, `html`, `reversed_source`
- `match_kind`: the kind string for generated matches
- `regex_list`: array of regex patterns

### Derived analyzer

Filters an existing match kind to create a new, more specific one. Useful for flagging specific values within a broader match kind.

```json
{
  "analyzer": {
    "custom_analyzers": {
      "admin_paths": {
        "enabled": true,
        "type": "derived",
        "file_types": ["js", "html", "reversed_source"],
        "original_match_kind": "path",
        "new_match_kind": "admin_path",
        "regex_list": [".*admin.*", ".*internal.*", ".*debug.*"]
      }
    }
  }
}
```

- `original_match_kind`: the source match kind to derive from
- `new_match_kind`: the new match kind to create
- `regex_list`: if any regex matches the original value, a derived match is created
- `preprocess_script`: optional script that receives the match value on stdin and outputs the transformed value (or nothing to skip)

### Script analyzer

Runs an arbitrary script that receives file paths on stdin and outputs matches as JSON. Most flexible -- use for complex analysis like AST-based pattern matching.

```json
{
  "analyzer": {
    "custom_analyzers": {
      "semgrep_postmessage": {
        "enabled": true,
        "type": "script",
        "file_types": ["js", "reversed_source"],
        "script": "$JXSCOUT_PROJECT_DIR/scripts/semgrep_to_jxscout.sh --rule $JXSCOUT_PROJECT_DIR/semgrep/postmessage.yaml --kind postmessage_handler"
      }
    }
  }
}
```

The script receives file paths on stdin (one per line) and must output a JSON array:

```json
[
  {
    "kind": "postmessage_handler",
    "value": "window.addEventListener('message', function(e) { ... })",
    "start": { "line": 10, "column": 0 },
    "end": { "line": 15, "column": 1 }
  }
]
```

`$JXSCOUT_PROJECT_DIR` and `$JXSCOUT_PROJECT_NAME` are available as environment variables in all scripts.

## Using semgrep for JS analysis

When semgrep is available and you need to find JS/TS code patterns, prefer it over regex. Semgrep uses AST-based matching which is far more accurate for code patterns (function calls, assignments, data flow) than regular expressions.

### 1. Create a semgrep rule

Create a YAML rule file in your project (e.g. `semgrep/postmessage_no_origin.yaml`):

```yaml
rules:
  - id: postmessage-no-origin-check
    message: postMessage handler without origin check
    pattern: |
      window.addEventListener("message", function($EVENT) {
        ...
      })
    languages: [javascript, typescript]
    severity: WARNING
```

### 2. Create the wrapper script

Create `scripts/semgrep_to_jxscout.sh` in your project directory. This script converts semgrep JSON output to the jxscout match format:

```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_PATH=""
KIND=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -r|--rule) RULE_PATH="$2"; shift 2 ;;
    -k|--kind) KIND="$2"; shift 2 ;;
    *) echo "Usage: $0 -r|--rule <rule_path> -k|--kind <kind> (file paths on stdin)" >&2; exit 1 ;;
  esac
done

[[ -n "$RULE_PATH" ]] || { echo "Missing -r|--rule <path>" >&2; exit 1; }
[[ -n "$KIND" ]] || { echo "Missing -k|--kind <kind>" >&2; exit 1; }

FILES=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" ]] && FILES+=("$line")
done

[[ ${#FILES[@]} -gt 0 ]] || { echo "No file paths on stdin" >&2; exit 1; }

SEMGREP_JSON=$(semgrep scan --config "$RULE_PATH" "${FILES[@]}" --json --quiet)

output=""
while IFS= read -r result; do
  path=$(echo "$result" | jq -r '.path')
  start_offset=$(echo "$result" | jq -r '.start.offset')
  end_offset=$(echo "$result" | jq -r '.end.offset')
  start_line=$(echo "$result" | jq -r '.start.line')
  start_col=$(echo "$result" | jq -r '.start.col')
  end_line=$(echo "$result" | jq -r '.end.line')
  end_col=$(echo "$result" | jq -r '.end.col')

  value=$(tail -c +$((start_offset + 1)) "$path" | head -c $((end_offset - start_offset)))

  one=$(jq -cn \
    --arg kind "$KIND" \
    --arg value "$value" \
    --argjson start_line "$start_line" \
    --argjson start_col "$start_col" \
    --argjson end_line "$end_line" \
    --argjson end_col "$end_col" \
    '{kind: $kind, value: $value, start: {line: $start_line, column: $start_col}, end: {line: $end_line, column: $end_col}}')
  output="${output}${one}"$'\n'
done < <(echo "$SEMGREP_JSON" | jq -c '.results[]? // empty')

if [[ -z "$output" ]]; then
  echo "[]"
else
  echo "$output" | jq -cs 'if . == null then [] else . end'
fi
```

Make it executable: `chmod +x scripts/semgrep_to_jxscout.sh`

### 3. Add to project settings

```json
{
  "analyzer": {
    "custom_analyzers": {
      "postmessage_no_origin": {
        "enabled": true,
        "type": "script",
        "file_types": ["js", "reversed_source"],
        "script": "$JXSCOUT_PROJECT_DIR/scripts/semgrep_to_jxscout.sh --rule $JXSCOUT_PROJECT_DIR/semgrep/postmessage_no_origin.yaml --kind postmessage_no_origin"
      }
    }
  }
}
```

## Testing analyzers

**Always test every new or modified analyzer before retriggering project-wide.** Use the `analyze` command on a single file:

```bash
jxscout-pro-v2 -c analyze --file-type <js|html|reversed_source> <file_path>
```

This outputs the matches that would be generated but does **not** store them in the database.

If no file in the project contains the pattern you're targeting, create a small temporary test file with known patterns that should match, run `analyze` against it, verify the output is correct, and delete the temp file. This ensures the analyzer actually works before committing to a potentially long retrigger across the full project.

## Retriggering analysis

After adding or modifying analyzers, retrigger analysis to regenerate matches across the project:

```bash
jxscout-pro-v2 -c retrigger-events --subscriber analyzer [options]
```

Options:
- `--glob <pattern>` -- only retrigger for files matching a glob (e.g. `*.js`, `/path/to/*.html`)
- `--event-name <name>` -- filter by event name (repeatable)
- `--status <status>` -- filter by status: `done`, `failed`, `killed` (repeatable)
- `--json` -- output result as JSON

**Always retrigger after adding or modifying an analyzer** -- without this, the new matches won't exist in the database. Only skip retriggering if the user explicitly says they don't want to. On large projects you can mention it may take a while, but proceed unless told otherwise. Use `--glob` to scope the retrigger to specific files or directories if the user wants a faster, targeted run.

To see what subscribers and events are available:

```bash
jxscout-pro-v2 -c list-subscribers --json
```

## Updating the VS Code matches view

**You must always add new match kinds to the VS Code matches view.** Without this step, the analyzer's results won't be visible in the sidebar and the analyzer is effectively useless to the user.

**CRITICAL: Before adding a match kind, you MUST check whether `vscode_extension` already exists in `settings.jsonc`.** If it does NOT exist, you MUST first copy the entire `vscode_extension` block from the full project settings into `settings.jsonc`. If you skip this and only add the new match kind entry, **all built-in match kinds will disappear from the VS Code sidebar** because the override replaces the defaults entirely.

### Step 1: Ensure `vscode_extension` is in `settings.jsonc`

Check `settings.jsonc` for a `vscode_extension` key. If it is **not** present:

1. Run `jxscout-pro-v2 -c print-full-project-settings`
2. Copy the **entire** `vscode_extension` block from the output into `settings.jsonc`
3. Only then proceed to add your new match kind

This preserves all existing built-in match kinds (paths, URLs, secrets, sinks, etc.) in the sidebar. **Never skip this step** -- adding only the new entry without the existing structure will remove every other match kind from the view.

If `vscode_extension > matches_view > structure` already exists in `settings.jsonc`, skip to step 2.

### Step 2: Add your match kind to the view

Append an entry like this to the `vscode_extension > matches_view > structure` array:

```json
{
  "type": "navigation",
  "label": "Sensitive Fetches",
  "icon": "vscode:shield",
  "children": [
    {
      "type": "match",
      "match_kind": "sensitive_fetch",
      "icon": "vscode:shield",
      "dont_collapse_individual_matches": true
    }
  ]
}
```

- `type`: `"navigation"` for tree nodes, `"match"` for leaves that show actual matches
- `match_kind`: must match the kind string from your analyzer config
- `icon`: use `jxscout:<name>` for built-in icons, `vscode:<name>` for VS Code icons, or `file:/path/to/icon.svg` for custom SVGs
- `dont_collapse_individual_matches`: controls whether matches with the same value are collapsed into one tree node or shown individually (see below)

### Collapsing vs. showing individual matches

By default, matches with the same value are collapsed into a single tree node (e.g. if `/api/users` appears in 5 files, you see one `/api/users` node). This is useful for value-oriented match kinds where the value itself is what matters -- paths, URLs, hostnames, query params, secrets.

For source/sink analyzers, collapsing is **wrong**. Two matches like `document.innerHTML = e` can have the same textual value but represent completely different code locations with different variables, contexts, and security implications. Set `"dont_collapse_individual_matches": true` so every match gets its own node.

Rule of thumb:
- **Collapse** (default, or `false`): the match value alone tells you everything -- paths, URLs, hostnames, secrets, query params
- **Don't collapse** (`true`): the match value is a code snippet where the surrounding context matters -- sinks (`innerHTML`, `eval`), event handlers (`onmessage`), assignments, function calls

jxscout auto-reloads when `settings.jsonc` changes, so the view updates immediately after saving.

## Workflow for adding a custom analyzer

1. Decide the analyzer type: regex for simple literal patterns, derived for filtering existing match kinds, script for code-semantic analysis (prefer semgrep for JS/TS when available)
2. Add the configuration to `settings.jsonc` under `analyzer > custom_analyzers`
3. Test with `analyze` on a file that should match (create a temp test file if needed, then delete it)
4. **Always** add the new match kind to the VS Code matches view -- **first ensure the full `vscode_extension` block is in `settings.jsonc`** (get it from `print-full-project-settings` if missing), then append your entry
5. **Always** retrigger analysis with `retrigger-events --subscriber analyzer` (skip only if the user explicitly says not to)
6. Query results with `get-matches --match-kind <your_kind> --json`
