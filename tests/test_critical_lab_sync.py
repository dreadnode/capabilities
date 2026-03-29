from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "critical_lab_sync.py"
    spec = importlib.util.spec_from_file_location("critical_lab_sync", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = load_module()


ARTICLE_HTML = """
<html>
  <head>
    <title>Abusing libmagic: Inconsistencies That Lead to Type Confusion</title>
    <meta name="description" content="Research summary" />
    <meta property="article:published_time" content="2025-10-06T00:00:00+00:00" />
  </head>
  <body>
    <article>
      <h1>Abusing libmagic: Inconsistencies That Lead to Type Confusion</h1>
      <p>Intro paragraph.</p>
      <pre><code>#!/usr/bin/env python3
import json, argparse

def generate_nested_json(depth, width=1):
    if depth &lt;= 0:
        return "terminal_value"
    return {}
</code></pre>
      <p>Closing paragraph.</p>
    </article>
  </body>
</html>
"""


class CriticalLabSyncTests(unittest.TestCase):
    def test_html_to_markdown_preserves_preformatted_code(self) -> None:
        article = MODULE.extract_article(
            "https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion",
            ARTICLE_HTML,
        )

        self.assertIn("```", article.body_markdown)
        self.assertIn("import json, argparse", article.body_markdown)
        self.assertNotIn("\nimport\njson\n,\nargparse", article.body_markdown)
        self.assertEqual(article.body_markdown.count("#!/usr/bin/env python3"), 1)

    def test_discover_article_urls_prefers_explicit_urls(self) -> None:
        with mock.patch.object(MODULE, "fetch_text", side_effect=AssertionError("should not fetch indexes")):
            urls = MODULE.discover_article_urls(
                ["research"],
                [
                    "https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion",
                    "https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion/",
                ],
            )

        self.assertEqual(
            urls,
            ["https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion"],
        )


class CriticalLabSyncMainTests(unittest.IsolatedAsyncioTestCase):
    async def test_explicit_article_dry_run_ignores_state_and_does_not_rewrite_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_file = root / "state.json"
            state_payload = {
                "articles": {
                    "https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion": {
                        "content_hash": MODULE.extract_article(
                            "https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion",
                            ARTICLE_HTML,
                        ).content_hash
                    }
                }
            }
            state_file.write_text(json.dumps(state_payload))

            args = argparse.Namespace(
                sections="research",
                article_url=[
                    "https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion"
                ],
                max_articles=1,
                state_file=state_file,
                artifacts_root=root / "artifacts",
                skills_root=root / "skills",
                generated_prefix="critical-lab",
                generator_id="",
                record_skips=False,
                dry_run=True,
                ignore_state=False,
                log_level="info",
            )

            with (
                mock.patch.object(MODULE, "parse_args", return_value=args),
                mock.patch.object(MODULE, "fetch_text", return_value=ARTICLE_HTML),
            ):
                rc = await MODULE.main()

            self.assertEqual(rc, 0)
            snapshot = root / "artifacts" / "articles" / "libmagic-inconsistencies-that-lead-to-type-confusion.json"
            self.assertTrue(snapshot.exists())
            self.assertEqual(json.loads(state_file.read_text()), state_payload)


if __name__ == "__main__":
    unittest.main()
