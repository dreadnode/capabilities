from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SYNC = load_module("critical_lab_sync", SCRIPTS / "critical_lab_sync.py")
AGENT = load_module("critical_lab_agent", SCRIPTS / "critical_lab_agent.py")

ARTICLE_HTML = """
<html>
  <head>
    <title>Example Research</title>
    <meta name="description" content="Research summary" />
    <meta property="article:published_time" content="2025-10-06T00:00:00+00:00" />
  </head>
  <body>
    <article>
      <h1>Example Research</h1>
      <p>Technique details.</p>
    </article>
  </body>
</html>
"""


@unittest.skipIf(getattr(AGENT, "rg", None) is None, "rigging not installed")
class CriticalLabAgentTests(unittest.TestCase):
    def make_agent(self, root: Path) -> object:
        skills_root = root / "skills"
        (skills_root / "existing-skill").mkdir(parents=True)
        (skills_root / "existing-skill" / "SKILL.md").write_text(
            "---\nname: existing-skill\ndescription: Existing skill.\n---\n"
        )
        return AGENT.CriticalLabAgent(
            state_file=root / "state.json",
            artifacts_root=root / "artifacts",
            skills_root=skills_root,
            sections=["research"],
            explicit_urls=["https://lab.ctbb.show/research/example-research"],
            max_articles=5,
            generated_prefix="critical-lab",
            ignore_state=False,
        )

    def test_pending_articles_uses_explicit_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            agent = self.make_agent(root)
            with mock.patch.object(SYNC, "fetch_text", return_value=ARTICLE_HTML):
                pending = agent.pending_articles()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].url, "https://lab.ctbb.show/research/example-research")

    def test_save_decision_writes_draft_and_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            agent = self.make_agent(root)
            with mock.patch.object(SYNC, "fetch_text", return_value=ARTICLE_HTML):
                result = json.loads(
                    agent.save_decision(
                        article_url="https://lab.ctbb.show/research/example-research",
                        should_create_skill=True,
                        skill_slug="example-technique",
                        source_summary="summary",
                        overlap_notes="none",
                        rationale="new technique",
                        skill_markdown="---\nname: example-technique\ndescription: Example.\n---\n\n# Example\n",
                    )
                )

            self.assertTrue(result["wrote_skill"])
            draft_path = root / "artifacts" / "drafts" / "example-research.json"
            skill_path = root / "skills" / "critical-lab-example-technique" / "SKILL.md"
            state_path = root / "state.json"
            self.assertTrue(draft_path.exists())
            self.assertTrue(skill_path.exists())
            self.assertTrue(state_path.exists())

    def test_save_decision_recovers_from_malformed_article_url_when_single_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            agent = self.make_agent(root)
            with mock.patch.object(SYNC, "fetch_text", return_value=ARTICLE_HTML):
                result = json.loads(
                    agent.save_decision(
                        article_url=":",
                        should_create_skill=False,
                        skill_slug="example-technique",
                        source_summary="summary",
                        overlap_notes="overlap",
                        rationale="skip",
                        skill_markdown="",
                    )
                )

            self.assertEqual(
                result["article_url"],
                "https://lab.ctbb.show/research/example-research",
            )
            draft_path = root / "artifacts" / "drafts" / "example-research.json"
            self.assertTrue(draft_path.exists())

    def test_duplicate_save_decision_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            agent = self.make_agent(root)
            with mock.patch.object(SYNC, "fetch_text", return_value=ARTICLE_HTML):
                first = json.loads(
                    agent.save_decision(
                        article_url="https://lab.ctbb.show/research/example-research",
                        should_create_skill=False,
                        skill_slug="example-technique",
                        source_summary="summary",
                        overlap_notes="overlap",
                        rationale="skip",
                        skill_markdown="",
                    )
                )
                second = json.loads(
                    agent.save_decision(
                        article_url="https://lab.ctbb.show/research/example-research",
                        should_create_skill=False,
                        skill_slug="example-technique",
                        source_summary="summary",
                        overlap_notes="overlap",
                        rationale="skip",
                        skill_markdown="",
                    )
                )

            self.assertEqual(first["article_url"], "https://lab.ctbb.show/research/example-research")
            self.assertTrue(second["duplicate"])


if __name__ == "__main__":
    unittest.main()
