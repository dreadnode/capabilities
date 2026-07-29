# LLM Wiki

LLM Wiki adapts [Andrej Karpathy's LLM Wiki
pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f)
to Dreadnode Agent Output. Instead of maintaining a directory of Markdown
pages, the agent compiles sources into typed, linked `wiki_page` items that can
be read and revised across turns and sessions.

## What it demonstrates

| LLM Wiki operation | Capability implementation |
| --- | --- |
| Index pages | Built-in `list_items` (`item_type="wiki_page"`) |
| Find a page | Built-in `search_items` full-text query |
| Read a page | Built-in `read_item` by ref or UUID |
| Create a page | Typed `report_item` call |
| Revise a page | `update_item` |
| Wikilinks | `link_items` relationships |
| Bounded coverage | `wiki_progress` counts and complete-scan stop signal |
| Ingest, query, lint | `llm-wiki` skill and agent |

The platform now provides the read surface directly: browsing, reading, and
full-text search are built-in tools (`list_items`, `read_item`, `search_items`)
that every agent in a platform-connected session receives. This capability
supplies the typed `wiki_page` schema, the operating skill/agent, and one
wiki-specific loop signal (`wiki_progress`) the generic tools cannot express.

## Try it

This capability requires:

- Dreadnode SDK 2.0.38 or newer,
- a configured model/provider,
- a platform-connected profile with an active project and effective
  `items:read` plus `items:write` grants.

> **Select a project first.** The built-in reads query, and writes land in, your
> profile's active project, and require item-read and item-write grants. If none
> is selected the tools raise `requires ... an active project` mid-run, not at
> launch. Pick one in the TUI project picker (it's shown in the status bar)
> before starting.

```bash
dn capability install dreadnode/llm-wiki
dn --capability llm-wiki --agent llm-wiki
```

Example prompts:

```text
Ingest https://example.com/article into the wiki. Use wiki_id example-article
and preserve claims and source evidence.

Build a structured wiki describing the architecture and trust boundaries in /path/to/repo.

What does the wiki say about authentication? Cite the evidence stored on relevant pages.

Lint the wiki for contradictions, unsupported claims, duplicate pages, and open questions.
```

Use `/auto 100` for a bounded autonomous ingest or maintenance pass. The agent
polls `wiki_progress(wiki_id=...)` between sweeps and stops only after a complete
scan shows open questions cleared and a sweep makes no repairs. Pages
are found with the built-in `search_items` (full-text) and `list_items`, so
large wikis stay navigable without loading the whole corpus.

## Where the wiki lives

The pages are `wiki_page` records in the **active platform project**, not files
on disk — that is what makes them outlive a context window and a session:

- **In the app.** Pages produced during a session appear under that session's
  Output tab and on the project's Agent Output page; the TUI prints a clickable
  link beneath each write. This is where the session owner reviews the result
  and chooses whether to share it.
- **Across sessions.** A later session owned by the same user reads the same
  pages by `ref` and keeps compiling onto them. Another teammate can read them
  only after the originating session is promoted from private to workspace
  visibility.

Every page carries a `wiki_id`; refs remain project-unique and should also use a
wiki-specific prefix.

## Current limitations

- Reads and direct writes require platform connectivity and item-read/item-write
  grants. A trace-backed write is not readable until materialization completes.
- Item refs are project-unique; independent wikis need distinct `wiki_id` values
  and ref prefixes.
- `wiki_progress` scans up to 1,000 `wiki_page` records to aggregate kinds and
  open questions; very large wikis report the scan as truncated.
- Direct item writes must succeed to be immediately readable. Platform
  trace-backed materialization runs at session freeze where supported, but is
  eventual and must not be used for same-loop read/link dependencies.
- This is a single-agent knowledge-maintenance pattern, not a concurrent work
  queue or deterministic workflow controller.
