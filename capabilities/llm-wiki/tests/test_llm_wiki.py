import asyncio
import importlib.util
import sys
import typing as t
from pathlib import Path

import pytest

CAPABILITY_ROOT = Path(__file__).parents[1]


def _load_module(name: str, relative_path: str) -> t.Any:
    path = CAPABILITY_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeApi:
    """Stand-in for the SDK ApiClient exposing the built-in list_items surface."""

    def __init__(self, pages: list[dict[str, t.Any]]) -> None:
        self.pages = list(pages)
        self.calls: list[dict[str, t.Any]] = []

    def list_items(
        self,
        org: str,
        workspace: str,
        project: str,
        **params: t.Any,
    ) -> dict[str, t.Any]:
        self.calls.append(params)
        return self.pages.pop(0)


def test_wiki_page_schema_rejects_unknown_fields() -> None:
    items = _load_module("llm_wiki_models", "items.py")
    page = items.WikiPage.model_validate(
        {
            "wiki_id": "auth-docs",
            "title": "Authentication",
            "kind": "concept",
            "summary": "How users authenticate.",
            "claims": [
                {
                    "statement": "Sessions use signed cookies.",
                    "evidence": ["src/auth.py:42"],
                    "confidence": "high",
                }
            ],
        }
    )
    assert page.claims[0].confidence == "high"

    with pytest.raises(ValueError):
        items.WikiPage.model_validate(
            {
                "wiki_id": "auth-docs",
                "title": "Authentication",
                "kind": "concept",
                "summary": "How users authenticate.",
                "unknown": True,
            }
        )

    with pytest.raises(ValueError):
        items.WikiPage.model_validate(
            {
                "wiki_id": "auth-docs",
                "title": "Authentication",
                "kind": "concept",
                "summary": "How users authenticate.",
                "claims": [{"statement": "Sessions use signed cookies."}],
            }
        )


def test_progress_aggregates_kinds_status_and_open_questions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("llm_wiki_tools_progress", "tools/wiki_items.py")
    api = FakeApi(
        [
            {
                "items": [
                    {
                        "data": {
                            "wiki_id": "auth-docs",
                            "kind": "concept",
                            "open_questions": ["why?"],
                        },
                        "disposition": {"status": "open"},
                    },
                    {
                        "data": {
                            "wiki_id": "auth-docs",
                            "kind": "concept",
                            "open_questions": [],
                        },
                        "disposition": {"status": "verified"},
                    },
                    {
                        "data": {"wiki_id": "other-wiki", "kind": "entity"},
                        "effective_status": None,
                    },
                ],
                "page": 1,
                "limit": 100,
                "total": 3,
                "has_next": False,
            }
        ]
    )
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    result = asyncio.run(tools.wiki_progress.fn(wiki_id="auth-docs"))

    assert result["pages_in_scan"] == 2
    assert result["by_kind"] == {"concept": 2}
    assert result["by_status"] == {"open": 1, "verified": 1}
    assert result["open_questions"] == 1
    assert result["pages_with_open_questions"] == 1
    assert result["open_questions_cleared"] is False
    assert result["complete_scan"] is True
    assert result["scan_truncated"] is False
    # Scans the wiki_page type through the built-in list surface, not a raw scan.
    assert api.calls[0]["item_type"] == "wiki_page"
    assert api.calls[0]["q"] == "auth-docs"


def test_progress_never_clears_questions_from_a_truncated_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("llm_wiki_tools_truncated", "tools/wiki_items.py")
    monkeypatch.setattr(tools, "_MAX_SCAN", 2)
    api = FakeApi(
        [
            {
                "items": [
                    {
                        "data": {
                            "wiki_id": "auth-docs",
                            "kind": "concept",
                            "open_questions": [],
                        }
                    },
                    {
                        "data": {
                            "wiki_id": "auth-docs",
                            "kind": "entity",
                            "open_questions": [],
                        }
                    },
                    {
                        "data": {
                            "wiki_id": "auth-docs",
                            "kind": "overview",
                            "open_questions": ["unseen"],
                        }
                    },
                ],
                "page": 1,
                "limit": 100,
                "total": 3,
                "has_next": False,
            }
        ]
    )
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    result = asyncio.run(tools.wiki_progress.fn(wiki_id="auth-docs"))

    assert result["pages_in_scan"] == 2
    assert result["scan_truncated"] is True
    assert result["complete_scan"] is False
    assert result["open_questions_cleared"] is False


def test_empty_wiki_is_not_a_positive_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _load_module("llm_wiki_tools_empty", "tools/wiki_items.py")
    api = FakeApi(
        [
            {
                "items": [],
                "page": 1,
                "limit": 100,
                "total": 0,
                "has_next": False,
            }
        ]
    )
    monkeypatch.setattr(
        tools,
        "_platform_context",
        lambda: (api, "acme", "main", "demo"),
    )

    result = asyncio.run(tools.wiki_progress.fn(wiki_id="auth-docs"))

    assert result["initialized"] is False
    assert result["complete_scan"] is True
    assert result["open_questions_cleared"] is False
