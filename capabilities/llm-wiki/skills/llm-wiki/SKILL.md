---
name: llm-wiki
description: Use when building, querying, revising, or linting a persistent LLM-maintained wiki from source material in Dreadnode Agent Output.
---

# LLM Wiki

Compile source material into `wiki_page` records that compound across turns.
Operate on the maintained pages instead of repeatedly reconstructing knowledge
from raw sources.

This instantiates Andrej Karpathy's
[LLM Wiki](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f)
pattern with typed Agent Output records rather than Markdown files.

Choose one stable lowercase kebab-case `wiki_id` before reading or writing. Put
that value on every page and pass it to `wiki_progress`; it is the isolation
boundary when a project contains more than one wiki.

## Choose the operation

- **Ingest** when the user supplies new source material.
- **Query** when the user asks a question about accumulated knowledge.
- **Lint** when the user asks to check or improve wiki health.

## Ingest

1. Call `list_items` with `item_type="wiki_page"` (or `search_items` with a
   topic query and `item_type="wiki_page"`) to find existing pages related to
   the source.
2. Read only those pages with `read_item`. Reject candidates whose `wiki_id`
   differs from the active wiki.
3. Read the raw source and extract claims with concrete evidence references.
4. Update an existing page when it covers the same subject. Create a new page
   only for a durable entity, concept, comparison, overview, source summary, or
   synthesis that deserves independent maintenance.
5. Use `report_item` with `item_type="wiki_page"`, the active `wiki_id`, and a
   stable lowercase kebab-case `ref`. Use `update_item` for revisions.
6. Connect related pages with `link_items`. Prefer specific relationships such
   as `supports`, `contradicts`, `summarizes`, `depends_on`, or `related_to`.
7. Re-read changed pages and report what was added, revised, or contradicted.

Never issue dependent page creates in the same model turn. When one new page
must link to another, create and re-read the target first, create the source
without an inline link, then call `link_items` after both refs are readable.
Trace-backed reconciliation is eventual and cannot satisfy a same-turn link
dependency.

When updating `claims`, `tags`, `source_refs`, or `open_questions`, send the
complete replacement list for that field because item updates shallow-merge.

## Query

1. Find candidate pages with `search_items` (full-text over titles, summaries,
   and claims) or browse `list_items`, always with `item_type="wiki_page"`.
2. Read the smallest relevant set of pages with `read_item`, discard pages from
   another `wiki_id`, and follow useful links.
3. Answer from their claims and evidence. Distinguish direct evidence from your
   synthesis and state unresolved uncertainty.
4. If the answer creates durable new synthesis, offer to file it as a page. Do
   not mutate the wiki merely because it was queried.

## Lint

Call `wiki_progress(wiki_id=...)` for a bounded coverage snapshot, then page
through `list_items` (`item_type="wiki_page"`) and selectively read suspected
problems with `read_item`. Check for:

- duplicate pages covering the same subject,
- claims that conflict without a `contradicts` link,
- claims lacking evidence,
- stale summaries after claim updates,
- orphan pages with no useful relationships,
- open questions now answered elsewhere,
- important recurring concepts without their own page.

Apply unambiguous repairs. Present uncertain merges, deletions, or substantive
reinterpretations to the user before changing them.

In an autonomous `/auto` maintenance pass, re-check `wiki_progress` between
sweeps and stop only when `complete_scan` and `open_questions_cleared` both hold
and a sweep applies no new repairs. Do not loop on a clean wiki merely because
steps remain in the budget.

## Boundaries

- Platform connectivity, an active project, and item-read plus item-write grants
  are required;
  browsing, reading, and search come from the built-in `list_items`,
  `read_item`, and `search_items` tools.
- Treat raw sources as immutable; only maintain the compiled `wiki_page` items.
- Keep `list_items`/`search_items` calls compact and paginated; open full pages
  with `read_item` only when needed. Never use full payloads as an index.
- Keep `wiki_id` and ref prefixes stable when maintaining multiple independent
  wikis in one project.
- This capability has no atomic work claiming; do not present it as a
  concurrent queue.
