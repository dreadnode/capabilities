---
name: jxscout-relationships
description: Query jxscout for asset relationships -- which JS files and iframes a page loads, lazy-loaded chunks, reversed source maps, and how assets relate to each other. Use when mapping the attack surface of a specific page or understanding how assets are connected.
license: proprietary
metadata:
  source: jxscout-pro-v2
  author: francisconeves97
  origin: ported from jxscout-pro-v2 agent skills
---

# jxscout Asset Relationships

jxscout tracks how web assets relate to each other: which JS files an HTML page loads, which iframes it embeds, which chunks were discovered from a script, and which source maps were reversed. Use these commands to map the attack surface of a specific page or trace how assets are connected.

## Prerequisites

The `JXSCOUT_PROJECT_NAME` environment variable must be set. All commands use `jxscout-pro-v2 -c` (client mode).

## Commands

### Get JS files loaded by a page

```bash
jxscout-pro-v2 -c get-loaded-js-files <url_or_path> [--include-reversed-sources] [--json]
```

Lists all JS files loaded by an HTML page. Pass either the URL or the local file path.

- `--include-reversed-sources` -- also include file paths of reversed source map files
- `--json` -- structured output with `js_files` and optionally `reversed_sources` arrays

This is useful for scoping your analysis to the JS that actually runs on a specific page, rather than searching the entire project.

### Get loader page for a JS file

```bash
jxscout-pro-v2 -c get-js-file-loader-page <url_or_path> [--json]
```

Returns the HTML page(s) that load a given JS file. This is the reverse of `get-loaded-js-files`. Pass either the URL or the local file path of the JS file.

Also works with reversed source files -- it follows the chain (reversed source -> source map -> JS file) to find the pages that load the original JS file the reversed source was extracted from.

- `--json` -- structured output with a `loader_pages` array

This is useful for impact assessment: given a JS file with a vulnerability or interesting code, find which pages are affected.

### Get iframes loaded by a page

```bash
jxscout-pro-v2 -c get-loaded-iframes <url_or_path> [--json]
```

Lists all iframes embedded by an HTML page. Relevant for:
- **postMessage analysis**: iframes are common postMessage targets and sources
- **Cross-origin interactions**: understanding which origins are framed
- **Clickjacking assessment**: identifying framed content

## Workflow

1. **Scope to a page**: `get-loaded-js-files` to see what JS runs on it — focus review on these files rather than the entire project
2. **Check iframes**: `get-loaded-iframes` to identify cross-origin messaging patterns (postMessage targets, clickjacking candidates)
3. **Follow the chain**: reversed sources often have more readable code — check for admin panels, feature flags, debug endpoints in lazy-loaded chunks
4. **Assess impact**: given a vulnerable JS file, `get-js-file-loader-page` reveals which pages are affected

**Checkpoint:** After mapping a page's assets, verify the relationships match what you see in the browser's Network tab. If scripts are missing, check for lazy-loaded chunks by searching for dynamic `import()` calls in the loaded JS: `rg "import\(" <js_file_path>`. If chunks are found, trace their loader page to complete the map.
