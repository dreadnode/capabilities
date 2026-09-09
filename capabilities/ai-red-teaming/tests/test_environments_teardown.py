"""Tests for tools/environments.py — session registry + environment teardown.

A hosted sandbox bills for its whole lifetime, so every provisioned environment
is registered and reaped when the assessment completes (or via teardown_environment).
These tests exercise the pure teardown/registry logic with an injected fake API
client and a temp registry file — no network.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("dreadnode.agents.tools")

TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "environments.py"
ASSESSMENT_PATH = Path(__file__).resolve().parents[1] / "tools" / "assessment.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


env = _load(TOOL_PATH, "airt_environments_under_test")


class _FakeApi:
    """Records delete_environment calls; can be told to 404 specific ids."""

    def __init__(self, missing: set[str] | None = None, boom: set[str] | None = None):
        self.deleted: list[tuple[str, str, str]] = []
        self._missing = missing or set()
        self._boom = boom or set()

    def delete_environment(self, org: str, workspace: str, env_id: str) -> None:
        self.deleted.append((org, workspace, env_id))
        if env_id in self._boom:
            raise RuntimeError("provider exploded")
        if env_id in self._missing:
            raise _NotFound("environment not found (404)")


class _NotFound(Exception):
    pass


class _FakeEnv:
    def __init__(self, env_id):
        self.id = env_id


@pytest.fixture
def registry(tmp_path):
    return tmp_path / "environments.json"


class TestRegistry:
    def test_register_provisioned_adds_and_returns_id(self, registry) -> None:
        env_id = env._register_provisioned(
            _FakeEnv("env-1"), "ml-extraction-mnist-image", "org", "main", registry
        )
        assert env_id == "env-1"
        entries = env._registry_load(registry)
        assert len(entries) == 1
        assert entries[0]["id"] == "env-1"
        assert entries[0]["task_ref"] == "ml-extraction-mnist-image"
        assert "provisioned_at_ts" in entries[0]

    def test_register_no_id_is_noop(self, registry) -> None:
        assert env._register_provisioned(_FakeEnv(None), "x", "o", "w", registry) == ""
        assert env._registry_load(registry) == []

    def test_register_dedups_same_id(self, registry) -> None:
        env._register_provisioned(_FakeEnv("dup"), "a", "o", "w", registry)
        env._register_provisioned(_FakeEnv("dup"), "b", "o", "w", registry)
        entries = env._registry_load(registry)
        assert len(entries) == 1
        assert entries[0]["task_ref"] == "b"

    def test_load_tolerates_missing_and_corrupt(self, registry) -> None:
        assert env._registry_load(registry) == []
        registry.write_text("{ not json")
        assert env._registry_load(registry) == []


class TestTeardown:
    def test_teardown_all_deletes_and_empties_registry(self, registry) -> None:
        env._register_provisioned(_FakeEnv("a"), "t", "org", "main", registry)
        env._register_provisioned(_FakeEnv("b"), "t", "org", "main", registry)
        api = _FakeApi()
        result = env._teardown_environments(api, "org", "main", registry_path=registry)
        assert set(result["torn_down"]) == {"a", "b"}
        assert result["errors"] == {}
        assert env._registry_load(registry) == []
        assert {d[2] for d in api.deleted} == {"a", "b"}

    def test_teardown_single_id_leaves_others(self, registry) -> None:
        env._register_provisioned(_FakeEnv("a"), "t", "org", "main", registry)
        env._register_provisioned(_FakeEnv("b"), "t", "org", "main", registry)
        api = _FakeApi()
        result = env._teardown_environments(
            api, "org", "main", environment_id="a", registry_path=registry
        )
        assert result["torn_down"] == ["a"]
        remaining = [e["id"] for e in env._registry_load(registry)]
        assert remaining == ["b"]

    def test_teardown_missing_env_counts_as_success(self, registry) -> None:
        env._register_provisioned(_FakeEnv("gone"), "t", "org", "main", registry)
        api = _FakeApi(missing={"gone"})
        # _is_not_found matches on "404" in the message, so no SDK import needed.
        result = env._teardown_environments(api, "org", "main", registry_path=registry)
        assert result["torn_down"] == ["gone"]
        assert result["errors"] == {}
        assert env._registry_load(registry) == []

    def test_teardown_provider_error_is_reported_and_kept(self, registry) -> None:
        env._register_provisioned(_FakeEnv("bad"), "t", "org", "main", registry)
        api = _FakeApi(boom={"bad"})
        result = env._teardown_environments(api, "org", "main", registry_path=registry)
        assert result["torn_down"] == []
        assert "bad" in result["errors"]
        # A failed delete stays in the registry so a later sweep retries it.
        assert [e["id"] for e in env._registry_load(registry)] == ["bad"]

    def test_grace_window_skips_recent_envs(self, registry) -> None:
        env._register_provisioned(_FakeEnv("fresh"), "t", "org", "main", registry)
        entries = env._registry_load(registry)
        now = entries[0]["provisioned_at_ts"] + 5  # env is 5s old
        api = _FakeApi()
        result = env._teardown_environments(
            api, "org", "main", older_than_sec=60, registry_path=registry, now_ts=now
        )
        assert result["skipped"] == ["fresh"]
        assert result["torn_down"] == []
        assert api.deleted == []  # never called the platform

    def test_grace_window_reaps_old_envs(self, registry) -> None:
        env._register_provisioned(_FakeEnv("old"), "t", "org", "main", registry)
        entries = env._registry_load(registry)
        now = entries[0]["provisioned_at_ts"] + 120  # 2 minutes old
        api = _FakeApi()
        result = env._teardown_environments(
            api, "org", "main", older_than_sec=60, registry_path=registry, now_ts=now
        )
        assert result["torn_down"] == ["old"]

    def test_teardown_empty_registry_is_noop(self, registry) -> None:
        api = _FakeApi()
        result = env._teardown_environments(api, "org", "main", registry_path=registry)
        assert result == {"torn_down": [], "skipped": [], "errors": {}}
        assert api.deleted == []


class TestSessionHelper:
    def test_session_teardown_short_circuits_without_config(self, registry, monkeypatch) -> None:
        # Empty registry: must not call _configured() at all (no network).
        called = {"configured": False}

        def _boom():
            called["configured"] = True
            raise AssertionError("_configured must not be called for an empty registry")

        monkeypatch.setattr(env, "_configured", _boom)
        result = env.teardown_session_environments(registry_path=registry)
        assert result["torn_down"] == []
        assert called["configured"] is False

    def test_session_teardown_reaps_via_configured(self, registry, monkeypatch) -> None:
        env._register_provisioned(_FakeEnv("s1"), "t", "org", "main", registry)
        api = _FakeApi()
        monkeypatch.setattr(env, "_configured", lambda: (None, api, "org", "main"))
        result = env.teardown_session_environments(registry_path=registry)
        assert result["torn_down"] == ["s1"]
        assert api.deleted == [("org", "main", "s1")]


class TestAssessmentCompletionHook:
    """update_assessment_status must reap environments only when the assessment completes."""

    @pytest.fixture
    def assessment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIRT_ASSESSMENT_PATH", str(tmp_path / "assessment.json"))
        return _load(ASSESSMENT_PATH, "airt_assessment_under_test")

    def test_completion_triggers_teardown_and_appends_note(self, assessment, monkeypatch) -> None:
        calls = {"n": 0}

        def _spy() -> str:
            calls["n"] += 1
            return " Assessment complete - tore down 2 environment(s) to stop billing."

        monkeypatch.setattr(assessment, "_teardown_on_complete", _spy)
        assessment.register_assessment(
            name="demo", target="ml_classifier", planned_attacks=["hopskipjump_evasion"]
        )
        out = assessment.update_assessment_status(
            attack_name="hopskipjump_evasion", status="completed"
        )
        assert calls["n"] == 1
        assert "tore down 2 environment(s)" in out

    def test_partial_progress_does_not_tear_down(self, assessment, monkeypatch) -> None:
        calls = {"n": 0}
        monkeypatch.setattr(
            assessment, "_teardown_on_complete", lambda: calls.__setitem__("n", calls["n"] + 1) or ""
        )
        assessment.register_assessment(
            name="demo",
            target="ml_classifier",
            planned_attacks=["hopskipjump_evasion", "pwws_evasion"],
        )
        assessment.update_assessment_status(attack_name="hopskipjump_evasion", status="completed")
        assert calls["n"] == 0  # one of two done — not complete yet

    def test_teardown_fires_once_not_on_repeat_updates(self, assessment, monkeypatch) -> None:
        calls = {"n": 0}
        monkeypatch.setattr(
            assessment, "_teardown_on_complete", lambda: calls.__setitem__("n", calls["n"] + 1) or ""
        )
        assessment.register_assessment(
            name="demo", target="ml_classifier", planned_attacks=["hopskipjump_evasion"]
        )
        assessment.update_assessment_status(attack_name="hopskipjump_evasion", status="completed")
        # Re-recording the same attack must not re-trigger teardown.
        assessment.update_assessment_status(attack_name="hopskipjump_evasion", status="completed")
        assert calls["n"] == 1

    def test_real_teardown_on_complete_returns_empty_when_nothing_registered(
        self, assessment, monkeypatch
    ) -> None:
        # The real hook, with an empty/absent registry, short-circuits with no
        # platform call and returns "" (no note appended).
        monkeypatch.setenv("AIRT_ENV_REGISTRY_PATH", str(Path("/nonexistent/dir/registry.json")))
        assert assessment._teardown_on_complete() == ""


class TestTargetKind:
    """provision_environment must return the right endpoint per target type
    (ENG-8427: a classifier was steered to /attack and 404'd)."""

    @pytest.mark.parametrize("ref", [
        "ml-extraction-mnist-image", "ml-extraction-fraud-tabular",
        "ml-extraction-imdb-text", "some-classifier", "mnist-demo",
    ])
    def test_classifier_targets(self, ref):
        assert env._target_kind(ref) == "classifier"

    @pytest.mark.parametrize("ref", [
        "finops-mesh", "devsecops-mesh", "healthcare-mesh", "soc-mesh",
    ])
    def test_mesh_targets(self, ref):
        assert env._target_kind(ref) == "mesh"

    def test_unknown_target(self):
        assert env._target_kind("totally-custom-thing") == "unknown"


class TestResolveTaskOwner:
    """ENG-8434: a bare task name owned by another org (public catalog or a
    private task in a member org) must resolve to <org>/<name> efficiently."""

    class _Org:
        def __init__(self, key): self.key = key

    def _api(self, per_org):
        api = _FakeApi()
        def list_tasks(org, *, search=None, include_public=False, limit=50):
            return {"tasks": per_org.get((org, include_public), per_org.get(org, []))}
        api.list_tasks = list_tasks
        api.list_user_organizations = lambda: [self._Org("aisf"), self._Org("acme")]
        return api

    def test_public_catalog_hit_single_call(self):
        # caller-org+public search returns the public task -> resolved, no fan-out
        api = self._api({("aisf", True): [{"name": "ml-extraction-fraud-tabular", "org_key": "dreadnode"}]})
        assert env._resolve_task_owner(api, "aisf", "ml-extraction-fraud-tabular") == "dreadnode/ml-extraction-fraud-tabular"

    def test_private_member_org_via_fanout(self):
        # not in caller+public; found (private) in another member org
        api = self._api({("aisf", True): [], "acme": [{"name": "secret-mesh", "org_key": "acme"}]})
        assert env._resolve_task_owner(api, "aisf", "secret-mesh") == "acme/secret-mesh"

    def test_not_found_anywhere_returns_none(self):
        api = self._api({("aisf", True): [], "acme": []})
        assert env._resolve_task_owner(api, "aisf", "nope") is None

    def test_ambiguous_prefers_public_else_none(self):
        api = _FakeApi()
        api.list_tasks = lambda org, *, search=None, include_public=False, limit=50: {
            "tasks": [{"name": "dup", "org_key": "dreadnode"}, {"name": "dup", "org_key": "acme"}]
        }
        api.list_user_organizations = lambda: []
        assert env._resolve_task_owner(api, "aisf", "dup") == "dreadnode/dup"

    def test_exact_name_match_only(self):
        # search is fuzzy server-side; resolver must filter to an exact name match
        api = self._api({("aisf", True): [{"name": "ml-extraction-fraud-tabular-v2", "org_key": "dreadnode"}]})
        assert env._resolve_task_owner(api, "aisf", "ml-extraction-fraud-tabular") is None
