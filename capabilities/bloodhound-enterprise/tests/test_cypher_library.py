"""Lint-style tests for the curated attack-pattern catalog.

Every entry must be:
- Read-only (no write clauses).
- LIMIT-bounded explicitly (the catalog leads by example; runtime
  also injects a default but explicit caps make the audit easier).
- Uniquely identified.
- Fully populated (id, category, name, description, cypher).
- Categorised under one of the known categories.

A handful of catalog-shape tests round it out: every category has
≥1 pattern; finding-type filters return non-empty when the type
is known; the index lookup matches the canonical list.
"""

from __future__ import annotations

import re

import pytest

from runtime.cypher_helpers import is_write_query
from runtime.cypher_library import (
    CATEGORIES,
    AttackPattern,
    all_patterns,
    category_counts,
    get_pattern,
    patterns_by_category,
    patterns_for_finding,
)


_LIMIT_RE = re.compile(r"\bLIMIT\s+\d+\b", re.IGNORECASE)


class TestCatalogShape:
    def test_non_empty(self) -> None:
        assert len(all_patterns()) > 0

    def test_at_least_thirty_patterns(self) -> None:
        # Plan called for 30-50; lower bound here keeps us honest.
        assert len(all_patterns()) >= 30

    def test_ids_unique(self) -> None:
        ids = [p.id for p in all_patterns()]
        assert len(ids) == len(set(ids))

    def test_every_category_has_patterns(self) -> None:
        counts = category_counts()
        for category in CATEGORIES:
            assert counts.get(category, 0) > 0, f"category {category!r} empty"

    def test_categories_cover_canonical_set(self) -> None:
        # The canonical categories the explore skill references.
        required = {
            "domain-admins",
            "tier-zero",
            "kerberos",
            "delegation",
            "adcs",
            "acl-abuse",
            "sessions-lateral",
            "gpo",
            "credentials",
            "azure",
        }
        assert required.issubset(set(CATEGORIES))


class TestPatternFields:
    @pytest.mark.parametrize("pattern", all_patterns(), ids=lambda p: p.id)
    def test_required_fields_present(self, pattern: AttackPattern) -> None:
        assert pattern.id, "id missing"
        assert pattern.category, "category missing"
        assert pattern.name, "name missing"
        assert pattern.description, "description missing"
        assert pattern.cypher, "cypher missing"

    @pytest.mark.parametrize("pattern", all_patterns(), ids=lambda p: p.id)
    def test_id_is_slug(self, pattern: AttackPattern) -> None:
        assert re.fullmatch(r"[a-z0-9-]+", pattern.id), pattern.id

    @pytest.mark.parametrize("pattern", all_patterns(), ids=lambda p: p.id)
    def test_category_known(self, pattern: AttackPattern) -> None:
        assert pattern.category in CATEGORIES, (
            f"{pattern.id}: unknown category {pattern.category!r}"
        )

    @pytest.mark.parametrize("pattern", all_patterns(), ids=lambda p: p.id)
    def test_description_meaningful(self, pattern: AttackPattern) -> None:
        # Descriptions are the agent's "why this matters" hint;
        # one-liners aren't enough.
        assert len(pattern.description) >= 50, (
            f"{pattern.id}: description too short ({len(pattern.description)} chars)"
        )

    @pytest.mark.parametrize("pattern", all_patterns(), ids=lambda p: p.id)
    def test_no_write_clauses(self, pattern: AttackPattern) -> None:
        assert not is_write_query(pattern.cypher), (
            f"{pattern.id}: contains a write clause"
        )

    @pytest.mark.parametrize("pattern", all_patterns(), ids=lambda p: p.id)
    def test_explicit_limit_present(self, pattern: AttackPattern) -> None:
        assert _LIMIT_RE.search(pattern.cypher), (
            f"{pattern.id}: missing explicit LIMIT"
        )

    @pytest.mark.parametrize("pattern", all_patterns(), ids=lambda p: p.id)
    def test_cypher_starts_with_match_or_with(self, pattern: AttackPattern) -> None:
        # Sanity — every catalog query is a read pipeline. Should
        # start with MATCH (or WITH for prefixed projections).
        head = pattern.cypher.lstrip().upper()[:6]
        assert head.startswith(("MATCH ", "WITH ")), (
            f"{pattern.id}: cypher starts with {head!r}"
        )


class TestLookups:
    def test_get_pattern_returns_known_id(self) -> None:
        sample = next(iter(all_patterns()))
        assert get_pattern(sample.id) is sample

    def test_get_pattern_returns_none_for_unknown(self) -> None:
        assert get_pattern("not-a-real-id") is None

    def test_patterns_by_category_filters(self) -> None:
        adcs = patterns_by_category("adcs")
        assert all(p.category == "adcs" for p in adcs)
        assert len(adcs) >= 5  # ESC1-ESC8-ish coverage

    def test_patterns_by_category_unknown_returns_empty(self) -> None:
        assert patterns_by_category("not-a-category") == ()

    def test_patterns_for_finding_known(self) -> None:
        kerb = patterns_for_finding("Kerberoastable")
        assert len(kerb) >= 1
        assert all(p.attack_path_type == "Kerberoastable" for p in kerb)

    def test_patterns_for_finding_unknown_returns_empty(self) -> None:
        assert patterns_for_finding("not-a-finding") == ()


class TestNamesUnique:
    def test_pattern_names_unique(self) -> None:
        names = [p.name for p in all_patterns()]
        assert len(names) == len(set(names))


class TestExpectedCoverage:
    """Coverage assertions for patterns the explore skill specifically
    expects to find in the catalog. Drift here would surprise the
    skill at runtime."""

    @pytest.mark.parametrize(
        "expected_id",
        [
            "da-all-members",
            "tier-zero-shortest-paths-to",
            "tier-zero-from-domain-users",
            "dcsync-rights",
            "kerb-roastable-tier-zero",
            "kerb-asreproast",
            "deleg-unconstrained-non-dc",
            "adcs-esc1",
            "adcs-esc8",
            "acl-genericall-on-tier-zero",
            "owned-to-tier-zero",
        ],
    )
    def test_canonical_pattern_present(self, expected_id: str) -> None:
        assert get_pattern(expected_id) is not None, expected_id
