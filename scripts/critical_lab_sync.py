#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from html import unescape
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from bs4 import BeautifulSoup
from loguru import logger

try:
    import rigging as rg
except ImportError:  # pragma: no cover - exercised in CI/runtime
    rg = None


USER_AGENT = "dreadnode-capabilities-critical-lab-sync/0.1"
DEFAULT_ROOT = Path(".automation/critical-lab")
DEFAULT_SKILLS_ROOT = Path("dreadnode/web-security/skills")
MAX_ARTICLE_BODY_CHARS = 6000
MAX_SKILL_CATALOG_CHARS = 12000
DEFAULT_SECTION_URLS = {
    "research": [
        "https://lab.ctbb.show/",
        "https://lab.ctbb.show/research/all/",
    ],
    "writeups": [
        "https://lab.ctbb.show/",
        "https://lab.ctbb.show/writeups/all/",
    ],
}


@dataclass
class Article:
    url: str
    slug: str
    section: str
    title: str
    author: str | None
    published_at: str | None
    tags: list[str]
    summary: str
    body_markdown: str
    content_hash: str


if rg is not None:
    class SkillDraft(rg.Model):
        should_create_skill: bool = rg.element()
        skill_slug: str = rg.element()
        source_summary: str = rg.element()
        overlap_notes: str = rg.element()
        rationale: str = rg.element()
        skill_markdown: str = rg.element()

        @classmethod
        def xml_example(cls) -> str:
            return cls(
                should_create_skill=True,
                skill_slug="example-skill",
                source_summary="Short summary of the research article.",
                overlap_notes="Any overlap with existing skills.",
                rationale="Why this should or should not become a skill.",
                skill_markdown="---\nname: example-skill\ndescription: Example.\n---\n\n# Example skill\n",
            ).to_pretty_xml()
else:
    class SkillDraft(object):
        pass


def fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=30) as response:  # noqa: S310
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return re.sub(r"-{2,}", "-", slug)


def extract_links(html: str, base_url: str, sections: set[str]) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links: set[str] = set()

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        path = parsed.path.rstrip("/")
        if any(path.startswith(f"/{section}/") for section in sections):
            if path in {"/research/all", "/writeups/all"}:
                continue
            links.add(f"{parsed.scheme}://{parsed.netloc}{path}")

    if links:
        return sorted(links)

    for match in re.findall(
        r'https://lab\.ctbb\.show/(?:research|writeups)/[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+',
        html,
    ):
        links.add(match)

    return sorted(links)


def first_text(soup: BeautifulSoup, selectors: list[str]) -> str | None:
    for selector in selectors:
        node = soup.select_one(selector)
        if node:
            text = node.get_text(" ", strip=True)
            if text:
                return text
    return None


def collect_tags(soup: BeautifulSoup) -> list[str]:
    tag_candidates = []
    for selector in [
        'meta[property="article:tag"]',
        'meta[name="keywords"]',
        'a[href*="/tag/"]',
    ]:
        for node in soup.select(selector):
            if node.name == "meta":
                content = node.get("content", "")
                tag_candidates.extend(part.strip() for part in content.split(","))
            else:
                tag_candidates.append(node.get_text(" ", strip=True))

    seen: set[str] = set()
    tags: list[str] = []
    for raw in tag_candidates:
        tag = raw.strip().lower()
        if tag and tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags


def _clean_text_block(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def html_to_markdown(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    lines: list[str] = []
    seen_blocks: set[str] = set()

    for node in soup.find_all(["h1", "h2", "h3", "h4", "p", "li", "pre", "blockquote"]):
        if node.name == "pre":
            text = _clean_text_block(node.get_text("", strip=False))
            if not text:
                continue
            block = f"```\n{text}\n```"
        elif node.name == "blockquote":
            text = _clean_text_block(node.get_text(" ", strip=True))
            if not text:
                continue
            block = "\n".join(f"> {line}" for line in text.splitlines())
        elif node.name == "li":
            text = _clean_text_block(node.get_text(" ", strip=True))
            if not text:
                continue
            block = f"- {text}"
        elif node.name.startswith("h"):
            text = _clean_text_block(node.get_text(" ", strip=True))
            if not text:
                continue
            level = int(node.name[1])
            block = f'{"#" * level} {text}'
        else:
            text = _clean_text_block(node.get_text(" ", strip=True))
            if not text:
                continue
            block = text

        if block in seen_blocks:
            continue
        seen_blocks.add(block)
        lines.append(block)

    return "\n\n".join(lines).strip()


def extract_article(url: str, html: str) -> Article:
    soup = BeautifulSoup(html, "html.parser")
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2 or parts[0] not in {"research", "writeups"}:
        raise ValueError(f"Unsupported article path: {url}")

    section = parts[0]
    article_slug = normalize_slug(parts[-1])

    page_title = soup.title.get_text(" ", strip=True) if soup.title else None
    title = first_text(soup, ["h1"]) or page_title or article_slug.replace("-", " ").title()
    author = first_text(
        soup,
        [
            '[rel="author"]',
            '[class*="author"]',
            '[data-testid*="author"]',
        ],
    )
    published_at = None
    for selector, attr in [
        ('meta[property="article:published_time"]', "content"),
        ('meta[name="date"]', "content"),
        ("time[datetime]", "datetime"),
    ]:
        node = soup.select_one(selector)
        if node and node.get(attr):
            published_at = node[attr].strip()
            break

    summary = ""
    for selector, attr in [
        ('meta[name="description"]', "content"),
        ('meta[property="og:description"]', "content"),
        ('meta[name="twitter:description"]', "content"),
    ]:
        node = soup.select_one(selector)
        if node and node.get(attr):
            summary = unescape(node[attr].strip())
            break

    article_node = soup.select_one("article") or soup.select_one("main") or soup.body
    if article_node is None:
        raise ValueError(f"Could not locate article content for {url}")

    body_markdown = html_to_markdown(str(article_node))
    content_hash = hashlib.sha256(body_markdown.encode("utf-8")).hexdigest()

    return Article(
        url=url,
        slug=article_slug,
        section=section,
        title=title if isinstance(title, str) else article_slug.replace("-", " ").title(),
        author=author,
        published_at=published_at,
        tags=collect_tags(soup),
        summary=summary,
        body_markdown=body_markdown,
        content_hash=content_hash,
    )


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def build_skill_catalog(skills_root: Path) -> str:
    entries: list[str] = []
    for skill_md in sorted(skills_root.glob("*/SKILL.md")):
        text = skill_md.read_text()
        description_match = re.search(r"^description:\s*(.+)$", text, re.MULTILINE)
        description = description_match.group(1).strip() if description_match else ""
        entries.append(f"- {skill_md.parent.name}: {description}")
    catalog = "\n".join(entries)
    if len(catalog) <= MAX_SKILL_CATALOG_CHARS:
        return catalog
    return catalog[: MAX_SKILL_CATALOG_CHARS - 64].rstrip() + "\n... [truncated]"


def trim_article_body(body_markdown: str) -> str:
    if len(body_markdown) <= MAX_ARTICLE_BODY_CHARS:
        return body_markdown
    return body_markdown[: MAX_ARTICLE_BODY_CHARS - 64].rstrip() + "\n\n... [truncated]"


async def distill_article(article: Article, generator_id: str, skills_root: Path) -> SkillDraft:
    if rg is None:
        raise RuntimeError("rigging is not installed; cannot run distillation")

    async def log_chat(chats: list[rg.Chat]) -> None:
        for chat in chats:
            logger.info(f"Rigging completed chat {chat.uuid} for {article.url}")
            logger.debug(f"Conversation:\n{chat.conversation}")

    @rg.prompt(generator_id=generator_id)
    async def draft_skill(
        article_title: str,
        article_url: str,
        article_section: str,
        article_published_at: str,
        article_tags: str,
        article_summary: str,
        article_body_markdown: str,
        existing_skills: str,
    ) -> SkillDraft:
        """
        You turn security research into Dreadnode web-security skill files.

        Constraints:
        - Only produce a skill when the article contains a reusable offensive web security technique, workflow, exploit primitive, or testing pattern.
        - Prefer practical attack guidance over general commentary.
        - If the repo already has a materially overlapping skill, set `should_create_skill` to false unless the article clearly introduces a distinct technique.
        - Keep `skill_slug` in kebab-case.
        - `skill_markdown` must be a complete `SKILL.md` file with YAML frontmatter containing `name` and `description`.
        - Write in the terse, operator-focused style already used in this repo.
        - Reference the source article URL in the generated skill.

        Existing skills:
        {{ existing_skills }}

        Article title: {{ article_title }}
        Source URL: {{ article_url }}
        Section: {{ article_section }}
        Published: {{ article_published_at }}
        Tags: {{ article_tags }}
        Summary: {{ article_summary }}

        Article body:
        {{ article_body_markdown }}
        """

    draft_skill.watch(rg.watchers.make_stream_to_logs(level="info", max_chars=800, max_lines=80), log_chat)

    published_at = article.published_at or ""
    tags = ", ".join(article.tags)
    catalog = build_skill_catalog(skills_root)
    body = trim_article_body(article.body_markdown)
    logger.info(f"Invoking Rigging for {article.url} with {generator_id}")
    return await draft_skill(
        article.title,
        article.url,
        article.section,
        published_at,
        tags,
        article.summary,
        body,
        catalog,
    )


def ensure_frontmatter_name(skill_markdown: str, skill_slug: str) -> str:
    if not skill_markdown.startswith("---"):
        return (
            f"---\nname: {skill_slug}\ndescription: Generated skill draft.\n---\n\n"
            f"{skill_markdown.strip()}\n"
        )
    if re.search(r"^name:\s*", skill_markdown, re.MULTILINE):
        return skill_markdown
    return skill_markdown.replace("---\n", f"---\nname: {skill_slug}\n", 1)


def discover_article_urls(sections: list[str], extra_urls: list[str]) -> list[str]:
    explicit = [url.rstrip("/") for url in extra_urls]
    if explicit:
        deduped: list[str] = []
        seen: set[str] = set()
        for url in explicit:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped

    found: set[str] = set()
    wanted_sections = set(sections)
    for section in sections:
        for url in DEFAULT_SECTION_URLS.get(section, []):
            try:
                html = fetch_text(url)
            except (HTTPError, URLError, TimeoutError) as exc:
                print(f"WARN: failed to fetch index {url}: {exc}", file=sys.stderr)
                continue
            found.update(extract_links(html, url, wanted_sections))
    return sorted(found)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sections",
        default="research",
        help="Comma-separated sections to scan (research,writeups). Default: research",
    )
    parser.add_argument(
        "--article-url",
        action="append",
        default=[],
        help="Explicit article URL to process. Can be supplied multiple times.",
    )
    parser.add_argument(
        "--max-articles",
        type=int,
        default=10,
        help="Maximum number of changed/new articles to process in one run.",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=DEFAULT_ROOT / "state.json",
        help="Path to persisted discovery state.",
    )
    parser.add_argument(
        "--artifacts-root",
        type=Path,
        default=DEFAULT_ROOT,
        help="Directory for article snapshots and generated metadata.",
    )
    parser.add_argument(
        "--skills-root",
        type=Path,
        default=DEFAULT_SKILLS_ROOT,
        help="Root directory containing web-security skills.",
    )
    parser.add_argument(
        "--generated-prefix",
        default="critical-lab",
        help="Prefix for generated skill directories.",
    )
    parser.add_argument(
        "--generator-id",
        default=os.environ.get("CRITICAL_LAB_GENERATOR_ID", ""),
        help="Rigging generator id. Defaults to CRITICAL_LAB_GENERATOR_ID.",
    )
    parser.add_argument(
        "--record-skips",
        action="store_true",
        help="Persist state even when an article does not produce a skill draft.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover and snapshot articles without running Rigging or writing skills.",
    )
    parser.add_argument(
        "--ignore-state",
        action="store_true",
        help="Process discovered articles even if the content hash already exists in state.",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["trace", "debug", "info", "success", "warning", "error", "critical"],
        help="Log level for the sync script and Rigging logger.",
    )
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    if rg is not None:
        from rigging import logging as rg_logging

        rg_logging.configure_logging(args.log_level)
    else:
        logger.remove()
        logger.add(sys.stderr, level=args.log_level.upper())

    sections = [part.strip() for part in args.sections.split(",") if part.strip()]
    state: dict[str, Any] = load_json(args.state_file, {"articles": {}})
    state_articles: dict[str, dict[str, Any]] = state.setdefault("articles", {})
    ignore_state = args.ignore_state or bool(args.article_url)

    urls = discover_article_urls(sections, args.article_url)
    if not urls:
        print("No article URLs discovered.")
        return 0

    print(
        json.dumps(
            {
                "discovered_urls": len(urls),
                "ignore_state": ignore_state,
                "dry_run": args.dry_run,
            },
            indent=2,
        )
    )

    changed_articles: list[Article] = []
    for url in urls:
        try:
            article = extract_article(url, fetch_text(url))
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            print(f"WARN: failed to process {url}: {exc}", file=sys.stderr)
            continue

        logger.info(f"Fetched {article.url} [{article.content_hash[:12]}]")

        existing = state_articles.get(article.url)
        if (
            not ignore_state
            and existing
            and existing.get("content_hash") == article.content_hash
        ):
            print(f"UNCHANGED: {article.url}")
            continue

        changed_articles.append(article)
        print(f"QUEUE: {article.url}")
        if len(changed_articles) >= args.max_articles:
            break

    if not changed_articles:
        print("No changed or new articles found.")
        return 0

    snapshots_dir = args.artifacts_root / "articles"
    draft_dir = args.artifacts_root / "drafts"
    created_skills = 0
    processed_urls: set[str] = set()

    for article in changed_articles:
        processed_urls.add(article.url)
        snapshot_path = snapshots_dir / f"{article.slug}.json"
        write_json(snapshot_path, asdict(article))

        if args.dry_run:
            print(f"DRY RUN: captured {article.url}")
            continue

        if not args.generator_id:
            raise SystemExit("CRITICAL_LAB_GENERATOR_ID or --generator-id is required unless --dry-run is used")

        draft = await distill_article(article, args.generator_id, args.skills_root)
        draft_payload = {
            "article": asdict(article),
            "draft": draft.model_dump(mode="json"),
        }
        write_json(draft_dir / f"{article.slug}.json", draft_payload)
        logger.info(
            "Draft result for {}: should_create_skill={} skill_slug={}",
            article.url,
            draft.should_create_skill,
            draft.skill_slug,
        )

        if not draft.should_create_skill or not draft.skill_markdown.strip():
            print(f"SKIP: {article.url} -> {draft.rationale}")
            continue

        skill_slug = normalize_slug(draft.skill_slug or f"{args.generated_prefix}-{article.slug}")
        if not skill_slug.startswith(f"{args.generated_prefix}-"):
            skill_slug = f"{args.generated_prefix}-{skill_slug}"
        skill_dir = args.skills_root / skill_slug
        skill_dir.mkdir(parents=True, exist_ok=True)
        skill_path = skill_dir / "SKILL.md"
        skill_path.write_text(ensure_frontmatter_name(draft.skill_markdown.strip() + "\n", skill_slug))
        created_skills += 1
        print(f"WROTE: {skill_path}")

    if created_skills or args.record_skips:
        for article in changed_articles:
            if created_skills or args.record_skips or article.url in processed_urls:
                state_articles[article.url] = {
                    "slug": article.slug,
                    "section": article.section,
                    "title": article.title,
                    "published_at": article.published_at,
                    "content_hash": article.content_hash,
                    "last_processed_at": article.published_at or "",
                }
        write_json(args.state_file, state)

    print(
        json.dumps(
            {
                "discovered_urls": len(urls),
                "changed_articles": len(changed_articles),
                "created_skills": created_skills,
                "dry_run": args.dry_run,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
