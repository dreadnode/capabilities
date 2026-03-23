---
name: jxscout-security-research
description: Holistic guide for using jxscout to perform real vulnerability assessment on web applications. Use when doing security research, vulnerability hunting, attack surface mapping, or when you need to understand how jxscout's capabilities fit together for effective security analysis.
---

# Security Research with jxscout

jxscout is a JavaScript security analysis and recon tool that acts as an MITM HTTP/S proxy. It intercepts web traffic, ingests JS/HTML files, runs static analyzers, reverses source maps, and gives you a full picture of the client-side attack surface. This guide explains how to use its capabilities together for real vulnerability assessment -- not just pattern matching.

## Mindset

You are doing security research, not running a scanner. jxscout gives you tools to explore, analyze, and test. The goal is to find real vulnerabilities -- exploitable bugs that have actual security impact. That means:

- **Follow the data**: trace how user input flows through the application, from URL parameters and postMessage events to DOM sinks and API calls.
- **Think like an attacker**: what can be controlled, what can be reached, what can be chained?
- **Go beyond matches**: static analysis results are a starting point, not the end. Read the surrounding code, understand the context, check for sanitization, find alternative paths.
- **Verify with real requests**: use captured HTTP traffic and the repeater to confirm that what you see in code actually works in practice.
- **Document as you go**: bookmark interesting code, create findings for confirmed issues, mark reviewed matches as seen so you don't revisit them.

## Prerequisites

The `JXSCOUT_PROJECT_NAME` environment variable must be set. It is available in the project's `.env` file at the root of the working directory. All CLI commands use `jxscout-pro-v2 -c` (client mode).

## Capabilities overview

### HTTP request/response context

If `http_requests/` exists in the project working directory, jxscout has captured raw HTTP traffic from the target. The files are organized as `http_requests/{host}/{path}/{METHOD}/{timestamp}_{status}.req|.res`.

Use captured traffic to:

- **Understand real API patterns**: see actual request bodies, auth headers, cookies, and content types the application sends
- **Discover endpoints not visible in JS**: some endpoints only appear in server responses, redirects, or error messages
- **Cross-reference with static analysis**: match `path` or `api_path` results against real requests to see how endpoints are actually called
- **Find auth tokens and session handling**: look at `Authorization`, `Cookie`, and `Set-Cookie` headers across requests
- **Identify interesting responses**: error messages, stack traces, internal paths, version numbers, debug output

### Static analysis (matches)

jxscout runs static analyzers on every JS and HTML file it ingests. Results are called **matches** -- structured data pointing to specific patterns (paths, URLs, secrets, sinks, etc.).

Use matches when they're useful for your investigation -- don't wait to be asked. They're a tool for pinpointing specific things efficiently:

```bash
jxscout-pro-v2 -c list-match-kinds --json
jxscout-pro-v2 -c get-matches --match-kind path --json --show-only-unseen
jxscout-pro-v2 -c get-matches --match-kind secret --json
jxscout-pro-v2 -c get-matches --match-kind onmessage --json --value-include "origin"
```

But also grep the codebase directly, read code manually, and explore beyond what analyzers find. Matches only cover what analyzers are configured to detect.

### Tracking progress with seen/unseen

Matches have a seen/unseen status. Use this to track what you've reviewed:

```bash
# Mark specific matches as seen after reviewing them
jxscout-pro-v2 -c mark-matches-seen --match-ids 1,2,3

# Mark all matches of a kind as seen (bulk)
jxscout-pro-v2 -c mark-matches-seen --match-kind path

# Focus on unreviewed matches
jxscout-pro-v2 -c get-matches --match-kind path --json --show-only-unseen

# Re-mark as unseen if you want to revisit
jxscout-pro-v2 -c mark-matches-unseen --match-ids 4,5,6
```

This is especially valuable for large projects where there are thousands of matches. Review systematically, mark as seen, and use `--show-only-unseen` to always see what's new or unreviewed.

### Custom analyzers

When you find a pattern worth tracking across the entire project, create a custom analyzer rather than manually grepping for it repeatedly. There are three types:

- **Regex**: simple literal patterns (hardcoded URLs, API keys, specific strings)
- **Derived**: narrow down an existing match kind by value
- **Script (semgrep)**: code-semantic analysis (function calls, assignments, data flow, missing checks)

Add them to `settings.jsonc` under `analyzer > custom_analyzers`, test with `analyze`, then `retrigger-events --subscriber analyzer` to generate matches project-wide. See the custom-analyzers skill for full details.

### Bookmarks

Bookmark code you want to come back to -- sinks, gadgets, interesting flows, authentication logic, request construction patterns. Group related bookmarks together and write notes explaining **why** the code is interesting, not just what it does.

Bookmarks are especially useful for documenting multi-step flows: bookmark each step in the same group with notes that describe the progression (e.g., "Step 1: user input received here", "Step 2: passed to API construction without validation", "Step 3: sent in fetch request").

```bash
jxscout-pro-v2 -c bookmark create-group --name "OAuth flow"
jxscout-pro-v2 -c bookmark create \
  --group "OAuth flow" \
  --file-path /path/to/auth.js \
  --start-line 45 --start-column 0 \
  --end-line 52 --end-column 1 \
  --note "Step 1: OAuth redirect constructed with user-controlled redirect_uri parameter"
```

### Repeater

Use the repeater to test endpoints hands-on. Start from captured requests in `http_requests/`, copy to `repeater/<endpoint>/<test>/original.req`, then iterate:

```bash
jxscout-pro-v2 -c repeater repeater/api_v2_users/idor_test/original.req
```

Edit `original.req` between runs -- each send creates timestamped copies so your full history is preserved. See the repeater skill for full details.

### Findings

Document confirmed vulnerabilities and useful primitives as findings:

```bash
jxscout-pro-v2 -c create-finding \
  --kind xss \
  --severity high \
  --description "Reflected XSS in /search endpoint via q parameter -- innerHTML assignment without sanitization" \
  --dedup-key "/search:q:xss"
```

Create findings for things with real security value: confirmed vulns, interesting gadgets, exploitable primitives. Not for theoretical risks without evidence. See the findings skill for full details.

### Asset relationships

Map the attack surface by understanding how assets relate:

```bash
# What JS runs on a specific page?
jxscout-pro-v2 -c get-loaded-js-files https://target.com/app --json

# Which pages load a vulnerable script?
jxscout-pro-v2 -c get-js-file-loader-page /path/to/vulnerable.js --json

# What iframes does a page embed?
jxscout-pro-v2 -c get-loaded-iframes https://target.com/app --json

# Full relationship graph
jxscout-pro-v2 -c get-related-assets /path/to/file --json
```

This is critical for impact assessment: finding a sink in a JS file is more valuable when you know which pages load it.

### Project settings

The project's behavior is controlled by `settings.jsonc` in the working directory. You can view the full resolved settings (defaults merged with overrides) with:

```bash
jxscout-pro-v2 -c print-full-project-settings
```

Update `settings.jsonc` when it helps your assessment:

- **Scope**: adjust `ingestion > scope` to include or exclude specific hostnames/patterns
- **HTTP ingestion**: configure `http_request_ingestion` rules to capture or skip specific request patterns
- **Analyzer config**: add custom analyzers, adjust file type targets, enable/disable specific analysis
- **VS Code extension view**: add new match kinds to `vscode_extension > matches_view > structure` so they appear in the sidebar

jxscout auto-reloads when `settings.jsonc` changes.

### Path discovery and bruteforcing

Use discovered paths from static analysis as input for endpoint discovery:

```bash
# Get all discovered paths
jxscout-pro-v2 -c get-matches --match-kind path

# Get API-specific paths
jxscout-pro-v2 -c get-matches --match-kind api_path

# Generate wordlists from extracted words
jxscout-pro-v2 -c wordlist --json
```

Combine these with scripting to probe for hidden endpoints, test path variations, or bruteforce parameter values. Create scripts in the project directory as needed.

## Research workflow

There's no single correct order. Adapt based on what you're investigating and what you find. Here's a typical flow:

1. **Orient**: browse `http_requests/` to understand what the application does, what APIs it calls, how authentication works. Check asset relationships to understand the page/script structure.

2. **Map the surface**: query matches for paths, URLs, hostnames to get an overview of the exposed attack surface. Use relationships to scope your analysis to specific pages.

3. **Hunt for vulnerabilities**: focus on high-value match kinds (secrets, sinks, onmessage, html_manipulation). Read the surrounding code. Trace data flows. Check for sanitization and validation.

4. **Test**: use the repeater to send real requests. Modify parameters, headers, auth tokens. Verify that what you found in code is actually exploitable.

5. **Document**: create findings for confirmed issues. Bookmark interesting code for future reference. Mark reviewed matches as seen.

6. **Automate**: if you spot a pattern worth tracking, create a custom analyzer. If you need to test many endpoints, write a script.

7. **Iterate**: new files get ingested as jxscout captures more traffic. Check `--show-only-unseen` to see new matches. Re-examine areas as your understanding deepens.
