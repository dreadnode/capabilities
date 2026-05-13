"""Tests for goal_loader.py — category listing and goal filtering."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "goal_loader.py"


def _load():
    spec = importlib.util.spec_from_file_location("goal_loader", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


loader = _load()


class TestListCategories:
    def test_returns_categories(self) -> None:
        result = loader.list_categories({})
        assert "result" in result
        cats = result["result"]["categories"]
        assert len(cats) >= 2  # safety + security at minimum

    def test_total_goals_positive(self) -> None:
        result = loader.list_categories({})
        assert result["result"]["total_goals"] > 0

    def test_sub_categories_have_slugs(self) -> None:
        result = loader.list_categories({})
        for cat in result["result"]["categories"]:
            for sub in cat["sub_categories"]:
                assert "slug" in sub
                assert "count" in sub
                assert sub["count"] > 0

    def test_has_safety_and_security_tiers(self) -> None:
        result = loader.list_categories({})
        cat_names = {c["category"] for c in result["result"]["categories"]}
        assert "safety" in cat_names
        assert "security" in cat_names


class TestGetCategoryGoals:
    def test_returns_goals_for_valid_category(self) -> None:
        result = loader.get_category_goals({"sub_categories": ["cybersecurity"]})
        assert "result" in result
        assert result["result"]["count"] > 0

    def test_goals_have_id_and_category(self) -> None:
        result = loader.get_category_goals({"sub_categories": ["cybersecurity"]})
        for g in result["result"]["goals"]:
            assert "id" in g
            assert "category" in g
            assert "sub_category" in g

    def test_goals_do_not_expose_text(self) -> None:
        result = loader.get_category_goals({"sub_categories": ["cybersecurity"]})
        for g in result["result"]["goals"]:
            assert "goal" not in g  # Goal text must never leak

    def test_sample_size_limits_results(self) -> None:
        result = loader.get_category_goals({"sub_categories": ["cybersecurity"], "sample_size": 3})
        assert result["result"]["count"] <= 3

    def test_invalid_category_returns_error(self) -> None:
        result = loader.get_category_goals({"sub_categories": ["nonexistent_category"]})
        assert "error" in result

    def test_all_keyword_returns_all(self) -> None:
        result = loader.get_category_goals({"sub_categories": ["all"]})
        assert "result" in result
        assert result["result"]["count"] >= 100  # 260 bundled goals

    def test_empty_categories_returns_error(self) -> None:
        result = loader.get_category_goals({})
        assert "error" in result


class TestSubCategoryDisplayNames:
    def test_all_csv_subcategories_have_display_names(self) -> None:
        goals = loader._load_goals()
        slugs = {row["sub_category"] for row in goals}
        missing = slugs - set(loader.SUB_CATEGORY_DISPLAY_NAMES.keys())
        assert not missing, f"Sub-categories without display names: {missing}"
