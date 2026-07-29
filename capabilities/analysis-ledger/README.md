# Analysis Ledger

Analysis Ledger supports recursive, single-agent static analysis that can
outlive a model context window. The runtime owns the normal
think/tool/observe loop; typed Agent Output records hold the durable worklist,
evidence, and progress that feed later iterations.

The design builds on [Andrej Karpathy's LLM Wiki
pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f),
then adds the control state needed for code analysis. Maintained summaries
still compound like wiki pages, while explicit targets and claims make
traversal resumable and bounded.

## What it demonstrates

| Need | Implementation |
| --- | --- |
| Bounded autonomous iteration | Native `/auto <steps>` policy |
| Durable run definition | `analysis_run` Item |
| Ranked recursive frontier | `analysis_target` Items + `analysis_next_targets` |
| Evidence and uncertainty | `analysis_claim` Items |
| Compact lookup | Built-in `list_items` / `search_items` + `analysis_progress` |
| Focused rehydration | Built-in `read_item` with links |
| Persistent state transitions | Built-in `update_item` and `link_items` |
| Confirmed security output | Built-in `finding` Item |

No worker or server modification is involved. Browsing, reading, and full-text
search come from the platform's built-in `list_items`, `read_item`, and
`search_items` tools; writes use the runtime's capability-aware Agent Output
tools. This capability adds only the typed schema and two frontier-control reads
(`analysis_next_targets`, `analysis_progress`) the generic surface cannot
express.

## Try it

This requires:

- Dreadnode SDK 2.0.38 or newer,
- a configured model/provider,
- a platform-connected profile with an active project and effective
  `items:read` plus `items:write` grants.

> **Select a project first.** The ledger's runs, targets, and claims live in
> your profile's active project, and reads/writes require item-read/item-write
> grants. The tools raise `requires ... an active project` mid-run if none is
> selected. Pick one in the TUI project picker (it's shown in the status bar)
> before starting a run.

```bash
dn capability install dreadnode/analysis-ledger
dn --capability analysis-ledger --agent recursive-sast
```

Then enter `/auto 100` and try:

```text
Analyze authentication bypass risk in /path/to/repo.

Create a run at the current commit. Seed targets from entrypoints,
authorization checks, and sensitive sinks. Process one target per iteration,
record evidence-bearing claims, and enqueue newly discovered paths. Stop after
30 targets, an empty frontier, or three non-expanding iterations.
```

For architecture-oriented exploration:

```text
Map the request path from HTTP entrypoints to persistence in /path/to/repo.
Maintain module and function targets, record trust-boundary claims with
file:line evidence, and leave a resumable frontier for uncertain paths.
```

## How the loop actually runs

The everyday path is a **single autonomous run**, not manual restarts. You start
one `/auto` session and the runtime keeps the loop going:

```text
Analyze authentication bypass risk in /path/to/repo.
```
then `/auto 100`.

As context fills, the runtime **auto-compacts** (summarizes older messages) and
the agent keeps iterating — it does not stop or wait for you. Each iteration
re-reads the ledger (`analysis_progress` → `analysis_next_targets`) rather than
trusting the conversation. The frontier, claims, and persisted run counters are
durable records in the **active platform project**. That is what lets one run
cover a codebase far larger than a single context window, provided each
completed iteration checkpoints before compaction or interruption.

Records produced during the run appear under the session's Output tab and on
the project's Agent Output page in the platform web app (the TUI prints a
clickable link beneath each write). They are private to the session owner by
default; promote session visibility to workspace before expecting teammates to
read them.

**Resuming later is the same mechanism, across a harder boundary.** If a session
dies, or you come back the next day, start a new session and ask it to resume —
**pin the same objective and commit**, because `run_key` is derived from the
canonical repository, immutable revision, and normalized objective as the first
24 lowercase hex characters of their newline-delimited SHA-256 digest:

```text
Resume the authentication-bypass analysis run for /path/to/repo at <commit-sha>.
```

The agent calls `search_items` with the exact `run_key` and
`item_type="analysis_run"`, reads the frontier, and resumes an `in-progress`
target before selecting queued work. Completed checkpoints are not repeated.
Keep one live session per run: target claiming remains a read-then-update, not
an atomic lease.

## Compose with other analysis capabilities

Analysis Ledger supplies the durable worklist; it does not ship analysis
engines. The composition mechanism is general: the runtime makes every installed
capability's tools globally visible, and the `recursive-sast` agent enables all
of them (`tools: "*"`), so any analysis capability you install alongside becomes
usable inspection tooling while Analysis Ledger stays the owner of the typed
Item schema. Point a target's rationale at those tools and record their output
as claim evidence.

`sast` is the worked example. Install it alongside Analysis Ledger to add
`filemap`, CodeQL, Semgrep, dangerous-function scanners, and git tooling:

```bash
dn capability install dreadnode/sast
dn capability install dreadnode/analysis-ledger
dn --capability analysis-ledger --capability sast --agent recursive-sast
```

The agent explicitly disables `codesearch` and delegation because `codesearch`
spawns a sub-agent. This capability deliberately exercises the simpler
single-agent path.

## Operating model

```text
survey → seed frontier → select target → inspect bounded code neighborhood
   ↑                                               ↓
progress ← complete/refute ← record claims ← discover child targets
```

The local codebase and optional static-analysis engines remain the analysis
plane. Items store only selected work and durable conclusions; they are not a
replacement for an AST, code index, or callgraph database.

## Current limitations

- Reads and updates require platform connectivity plus item-read/item-write
  grants. Trace-backed writes become queryable only after platform
  materialization.
- Item refs are project-unique, so every target and claim ref is run-prefixed.
- Browsing and full-text search are handled server-side by the built-in tools.
  Frontier tools narrow candidates with server search on `run_ref`, exact-filter
  locally, and scan up to 1,000 records per type to rank custom
  `target_state`/`priority` and claim `disposition`. They refuse to select or
  stop on a truncated candidate scan.
- Target claiming is a read-then-update operation, not an atomic lease. Use one
  session per run.
- Source invalidation is procedural: the run pins a revision and optional
  target fingerprints, but no background process marks changed targets stale.
- Compaction is a context pressure valve, not persistence. Items and the
  per-iteration run checkpoint remain the source of truth.
- Platform trace-backed materialization runs at session freeze where supported,
  but is eventual and cannot satisfy same-iteration reads, updates, or links.
