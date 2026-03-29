#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any

from loguru import logger

import critical_lab_sync as base

try:
    import rigging as rg
except ImportError:  # pragma: no cover
    rg = None


if rg is not None:
    class CriticalLabAgent:
        def __init__(
            self,
            *,
            state_file: Path,
            artifacts_root: Path,
            skills_root: Path,
            sections: list[str],
            explicit_urls: list[str],
            max_articles: int,
            generated_prefix: str,
            ignore_state: bool,
        ) -> None:
            self.state_file = state_file
            self.artifacts_root = artifacts_root
            self.skills_root = skills_root
            self.sections = sections
            self.explicit_urls = [url.rstrip("/") for url in explicit_urls]
            self.max_articles = max_articles
            self.generated_prefix = generated_prefix
            self.ignore_state = ignore_state or bool(explicit_urls)
            self.state: dict[str, Any] = base.load_json(self.state_file, {"articles": {}})
            self.state_articles: dict[str, dict[str, Any]] = self.state.setdefault("articles", {})
            self._article_cache: dict[str, base.Article] = {}
            self._saved_decisions: set[str] = set()

        def _get_article(self, url: str) -> base.Article:
            normalized = url.rstrip("/")
            if normalized in self._article_cache:
                return self._article_cache[normalized]
            article = base.extract_article(normalized, base.fetch_text(normalized))
            self._article_cache[normalized] = article
            return article

        def _resolve_article_for_decision(self, article_url: str) -> base.Article:
            candidate = article_url.strip().rstrip("/")
            if candidate.startswith("http://") or candidate.startswith("https://"):
                return self._get_article(candidate)

            pending = self.pending_articles()
            if len(pending) == 1:
                logger.warning(f"Malformed article_url={article_url!r}; defaulting to sole pending article {pending[0].url}")
                return pending[0]

            raise ValueError(f"Malformed or ambiguous article_url: {article_url!r}")

        def pending_articles(self) -> list[base.Article]:
            urls = base.discover_article_urls(self.sections, self.explicit_urls)
            pending: list[base.Article] = []
            for url in urls:
                try:
                    article = self._get_article(url)
                except Exception as exc:
                    logger.warning(f"Failed to process {url}: {exc}")
                    continue
                existing = self.state_articles.get(article.url)
                if (
                    not self.ignore_state
                    and existing
                    and existing.get("content_hash") == article.content_hash
                ):
                    continue
                pending.append(article)
                if len(pending) >= self.max_articles:
                    break
            return pending

        @rg.tool_method
        def list_pending_articles(self) -> str:
            """Discover pending Critical Lab articles that are new or changed versus the saved state."""
            payload = [
                {
                    "url": article.url,
                    "slug": article.slug,
                    "section": article.section,
                    "title": article.title,
                    "published_at": article.published_at,
                    "summary": article.summary,
                    "content_hash": article.content_hash,
                }
                for article in self.pending_articles()
            ]
            return json.dumps(payload, indent=2)

        @rg.tool_method
        def fetch_article(
            self,
            url: Annotated[str, "Article URL from list_pending_articles"],
        ) -> str:
            """Fetch one article as JSON, including a trimmed body for analysis."""
            article = self._get_article(url)
            payload = base.asdict(article)
            payload["body_markdown"] = base.trim_article_body(article.body_markdown)
            return json.dumps(payload, indent=2)

        @rg.tool_method
        def list_existing_skills(self) -> str:
            """List existing web-security skills with short descriptions."""
            return base.build_skill_catalog(self.skills_root)

        @rg.tool_method
        def read_skill(
            self,
            skill_slug: Annotated[str, "Skill directory name under dreadnode/web-security/skills"],
        ) -> str:
            """Read one existing skill file by slug to compare overlap."""
            skill_path = self.skills_root / skill_slug / "SKILL.md"
            if not skill_path.exists():
                return f"Skill not found: {skill_slug}"
            return skill_path.read_text()

        @rg.tool_method
        def save_decision(
            self,
            article_url: Annotated[str, "Article URL being decided"],
            should_create_skill: Annotated[bool, "Whether a new skill should be created"],
            skill_slug: Annotated[str, "Proposed skill slug in kebab-case"],
            source_summary: Annotated[str, "Short summary of the source article"],
            overlap_notes: Annotated[str, "Notes about overlap with existing skills"],
            rationale: Annotated[str, "Why this should or should not become a skill"],
            skill_markdown: Annotated[str, "Complete SKILL.md content if creating a skill"] = "",
        ) -> str:
            """Persist the decision as a draft JSON artifact, optionally write a new skill file, and update state."""
            article = self._resolve_article_for_decision(article_url)
            if article.url in self._saved_decisions:
                logger.warning(f"Duplicate save_decision ignored for {article.url}")
                return json.dumps(
                    {
                        "article_url": article.url,
                        "duplicate": True,
                        "message": "Decision already saved for this article in the current run.",
                    },
                    indent=2,
                )
            draft_payload = {
                "article": base.asdict(article),
                "draft": {
                    "should_create_skill": should_create_skill,
                    "skill_slug": skill_slug,
                    "source_summary": source_summary,
                    "overlap_notes": overlap_notes,
                    "rationale": rationale,
                    "skill_markdown": skill_markdown,
                },
            }
            article_path = self.artifacts_root / "articles" / f"{article.slug}.json"
            draft_path = self.artifacts_root / "drafts" / f"{article.slug}.json"
            base.write_json(article_path, base.asdict(article))
            base.write_json(draft_path, draft_payload)

            wrote_skill = False
            if should_create_skill and skill_markdown.strip():
                normalized_slug = base.normalize_slug(skill_slug or f"{self.generated_prefix}-{article.slug}")
                if not normalized_slug.startswith(f"{self.generated_prefix}-"):
                    normalized_slug = f"{self.generated_prefix}-{normalized_slug}"
                skill_dir = self.skills_root / normalized_slug
                skill_dir.mkdir(parents=True, exist_ok=True)
                skill_path = skill_dir / "SKILL.md"
                skill_path.write_text(base.ensure_frontmatter_name(skill_markdown.strip() + "\n", normalized_slug))
                wrote_skill = True

            self.state_articles[article.url] = {
                "slug": article.slug,
                "section": article.section,
                "title": article.title,
                "published_at": article.published_at,
                "content_hash": article.content_hash,
                "last_processed_at": article.published_at or "",
            }
            base.write_json(self.state_file, self.state)
            self._saved_decisions.add(article.url)
            logger.info(f"Saved decision for {article.url} wrote_skill={wrote_skill}")
            return json.dumps(
                {
                    "article_url": article.url,
                    "draft_path": str(draft_path),
                    "wrote_skill": wrote_skill,
                },
                indent=2,
            )

        @rg.tool_method
        def finish(
            self,
            summary: Annotated[str, "Final summary of the work completed"],
        ) -> str:
            """Finish the run after every pending article has a saved decision."""
            return rg.Stop(summary)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sections", default="research")
    parser.add_argument("--article-url", action="append", default=[])
    parser.add_argument("--max-articles", type=int, default=10)
    parser.add_argument("--state-file", type=Path, default=base.DEFAULT_ROOT / "state.json")
    parser.add_argument("--artifacts-root", type=Path, default=base.DEFAULT_ROOT)
    parser.add_argument("--skills-root", type=Path, default=base.DEFAULT_SKILLS_ROOT)
    parser.add_argument("--generated-prefix", default="critical-lab")
    parser.add_argument("--generator-id", default=os.environ.get("GENERATOR", ""))
    parser.add_argument("--ignore-state", action="store_true")
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["trace", "debug", "info", "success", "warning", "error", "critical"],
    )
    return parser.parse_args()


async def main() -> int:
    if rg is None:
        raise SystemExit("rigging is required")

    args = parse_args()
    from rigging import logging as rg_logging

    rg_logging.configure_logging(args.log_level)

    sections = [part.strip() for part in args.sections.split(",") if part.strip()]
    agent = CriticalLabAgent(
        state_file=args.state_file,
        artifacts_root=args.artifacts_root,
        skills_root=args.skills_root,
        sections=sections,
        explicit_urls=args.article_url,
        max_articles=args.max_articles,
        generated_prefix=args.generated_prefix,
        ignore_state=args.ignore_state,
    )

    pending = agent.pending_articles()
    if not pending:
        print("No changed or new articles found.")
        return 0

    print(json.dumps({"pending_articles": len(pending), "ignore_state": agent.ignore_state}, indent=2))
    for article in pending:
        logger.info(f"Pending article {article.url} [{article.content_hash[:12]}]")

    if not args.generator_id:
        raise SystemExit("GENERATOR or --generator-id is required")

    system_prompt = """You are an autonomous security research distillation agent working inside a checked-out capabilities repository.

Use the tools to inspect pending articles and compare them against the existing web-security skills.

Required workflow:
1. Call `list_pending_articles` once.
2. For each pending article, call `fetch_article`.
3. Call `list_existing_skills`.
4. Call `read_skill` for the most likely overlapping skills before deciding.
5. Always call `save_decision` for every article.
6. Only create a new skill when the technique is genuinely new and reusable.
7. After all pending articles are handled, call `finish`.

Rules:
- Be conservative about overlap.
- Do not skip saving a decision.
- When creating a skill, `skill_markdown` must be a full SKILL.md file with frontmatter.
- Prefer concise, operator-focused writing.
""".strip()

    chat_log = args.artifacts_root / "agent-chats.jsonl"
    pipeline = (
        rg.get_generator(args.generator_id)
        .chat(
            [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": "Process all pending Critical Lab articles and save a decision for each one.",
                },
            ]
        )
        .using(agent, mode="auto", max_depth=40)
        .watch(
            rg.watchers.make_stream_to_logs(level="info", max_chars=800, max_lines=80),
            rg.watchers.write_chats_to_jsonl(chat_log, replace=True),
        )
    )
    await pipeline.run()

    created_skills = 0
    drafts_dir = args.artifacts_root / "drafts"
    if drafts_dir.exists():
        for draft_file in drafts_dir.glob("*.json"):
            payload = json.loads(draft_file.read_text())
            if payload.get("draft", {}).get("should_create_skill") is True:
                created_skills += 1

    print(
        json.dumps(
            {
                "pending_articles": len(pending),
                "created_skills": created_skills,
                "drafts_dir": str(drafts_dir),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
