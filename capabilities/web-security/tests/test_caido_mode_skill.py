"""Tests for the vendored `caido-mode` skill (Caido TypeScript SDK CLI).

The web-security capability ships four Caido surfaces against one instance:

  * ``caido-cli``      — the headless Caido server binary.
  * ``caido`` MCP      — lightweight Python wrapper over ``caido-sdk-client``.
  * ``caido-go`` MCP   — full-surface upstream Go binary (see
                         ``test_caido_go_mcp.py``).
  * ``caido-mode``     — this skill: a vendored TypeScript CLI built on
                         ``@caido/sdk-client`` (``caido-ts``).

These tests lock the pieces that silently rot: the skill's SDK floor, the
matching server pin, the provision-time ``npm install``, the presence check,
and the Dreadnode skill-format frontmatter. They are pure static assertions
over the manifest, the install script, and the skill tree — no network, no
Node, and no running Caido instance required.

Version contract
----------------
``@caido/sdk-client`` 0.4.0 targets the Caido **0.57** replay schema
(``ReplaySession`` as an interface, ``kind: ReplaySessionKind!`` on
``createReplaySession``, task-based sending via ``startReplayTask``). Both the
server pin and the Python SDK floor must stay on that side of the break, or
replay silently fails with "Unknown field collection on type ReplaySession".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = yaml.safe_load((ROOT / "capability.yaml").read_text(encoding="utf-8"))
INSTALL_SCRIPT = (ROOT / "scripts" / "install_tools.sh").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "docker" / "Dockerfile.runtime").read_text(encoding="utf-8")

SKILL_DIR = ROOT / "skills" / "caido-mode"
SKILL_MD = SKILL_DIR / "SKILL.md"
PACKAGE_JSON = json.loads((SKILL_DIR / "package.json").read_text(encoding="utf-8"))

# Keep in lock-step with scripts/install_tools.sh. Bumping the server pin means
# bumping this constant, which forces a conscious re-check of the SDK contract.
CAIDO_SERVER_PIN = "0.57.1"

# Minimum Caido server that speaks the replay schema @caido/sdk-client 0.4.0
# expects. See the module docstring.
MIN_REPLAY_SCHEMA_SERVER = (0, 57)

# Python caido-sdk-client floor: 0.3.0 introduced the versioned transport split
# (transport/latest vs transport/v0_56) that negotiates 0.57 correctly.
PY_SDK_FLOOR = "caido-sdk-client>=0.3.0"


def _frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    assert match is not None, f"missing YAML frontmatter in {path}"
    data = yaml.safe_load(match.group(1))
    assert isinstance(data, dict), f"frontmatter must be a mapping in {path}"
    return data


def _version_tuple(spec: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", spec)[:3])


# =============================================================================
# Skill tree
# =============================================================================


class TestCaidoModeSkillTree:
    def test_skill_md_exists(self) -> None:
        assert SKILL_MD.is_file()

    def test_cli_entrypoint_is_vendored(self) -> None:
        assert (SKILL_DIR / "caido-client.ts").is_file()

    def test_command_modules_are_vendored(self) -> None:
        # The command surface the SKILL.md documents must actually be present.
        commands = SKILL_DIR / "lib" / "commands"
        for module in ("requests", "replay", "matchreplace", "findings", "info"):
            assert (commands / f"{module}.ts").is_file(), f"missing {module}.ts"

    def test_upstream_tests_are_vendored(self) -> None:
        tests = sorted(p.name for p in (SKILL_DIR / "test").glob("*.test.ts"))
        assert tests == [
            "exportcurl.test.ts",
            "matchreplace.test.ts",
            "rawedit.test.ts",
        ]

    def test_node_modules_not_committed(self) -> None:
        # 25 MB of node_modules must never enter the artifact; it is recreated
        # at provision time. Both .gitignore and the OCI packager exclude it.
        gitignore = (SKILL_DIR / ".gitignore").read_text(encoding="utf-8")
        assert "node_modules" in gitignore


# =============================================================================
# Dreadnode skill format
# =============================================================================


class TestCaidoModeFrontmatter:
    def test_name_matches_directory(self) -> None:
        assert _frontmatter(SKILL_MD)["name"] == "caido-mode"

    def test_description_within_loader_limit(self) -> None:
        # dreadnode/agents/skills.py enforces SKILL_DESCRIPTION_MAX_LENGTH=1024.
        description = _frontmatter(SKILL_MD)["description"]
        assert 0 < len(description) <= 1024

    def test_description_routes_against_sibling_surfaces(self) -> None:
        # The router picks between four Caido surfaces on description alone, so
        # this one must name its alternatives.
        description = _frontmatter(SKILL_MD)["description"].lower()
        assert "caido-sdk" in description
        assert "caido-proxy" in description

    def test_no_unsupported_tags_key(self) -> None:
        # Upstream ships `tags: [worker]`, which the Dreadnode loader silently
        # drops. The equivalent lives in `metadata.role`.
        frontmatter = _frontmatter(SKILL_MD)
        assert "tags" not in frontmatter
        assert frontmatter["metadata"]["role"] == "worker"

    def test_metadata_values_are_strings(self) -> None:
        # The loader rejects non-string metadata keys/values outright.
        for key, value in _frontmatter(SKILL_MD)["metadata"].items():
            assert isinstance(key, str) and isinstance(value, str)

    def test_declares_compatibility(self) -> None:
        compatibility = _frontmatter(SKILL_MD)["compatibility"]
        assert isinstance(compatibility, str) and compatibility.strip()
        assert len(compatibility) <= 500  # SKILL_COMPATIBILITY_MAX_LENGTH
        assert "Node" in compatibility

    def test_records_upstream_provenance(self) -> None:
        # A vendored skill must say where it came from, or the next re-sync
        # silently clobbers the local fork.
        metadata = _frontmatter(SKILL_MD)["metadata"]
        assert "caido/skills" in metadata["upstream"]

    def test_documents_local_fork_for_resync(self) -> None:
        body = SKILL_MD.read_text(encoding="utf-8")
        assert "VENDORED SKILL" in body
        assert "Preserve these local sections on re-sync" in body


# =============================================================================
# Version contract — the 0.57 replay schema break
# =============================================================================


class TestCaidoVersionContract:
    def test_skill_pins_sdk_client_major_minor(self) -> None:
        spec = PACKAGE_JSON["dependencies"]["@caido/sdk-client"]
        assert _version_tuple(spec)[:2] == (0, 4), (
            f"expected @caido/sdk-client 0.4.x, got {spec!r}. A major/minor bump "
            "may move the replay schema — re-verify the server pin."
        )

    def test_server_pin_speaks_the_same_replay_schema(self) -> None:
        match = re.search(r'CAIDO_VERSION="([\d.]+)"', INSTALL_SCRIPT)
        assert match is not None, "caido-cli version pin not found"
        assert match.group(1) == CAIDO_SERVER_PIN
        assert _version_tuple(match.group(1))[:2] >= MIN_REPLAY_SCHEMA_SERVER, (
            "caido-cli pin predates the 0.57 replay schema that "
            "@caido/sdk-client 0.4.0 targets"
        )

    def test_server_download_url_is_version_interpolated(self) -> None:
        # Guards against a bumped constant with a hardcoded URL left behind.
        assert (
            "https://caido.download/releases/v${CAIDO_VERSION}/"
            "caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz"
        ) in INSTALL_SCRIPT

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param("manifest", id="capability.yaml"),
            pytest.param("mcp", id="mcp/caido.py"),
            pytest.param("dockerfile", id="Dockerfile.runtime"),
        ],
    )
    def test_python_sdk_floor_declared_everywhere(self, source: str) -> None:
        # All three declaration sites must carry the floor; a bare
        # "caido-sdk-client" resolves 0.2.0, which breaks replay on 0.57.
        if source == "manifest":
            haystack = "\n".join(MANIFEST["dependencies"]["python"])
        elif source == "mcp":
            haystack = (ROOT / "mcp" / "caido.py").read_text(encoding="utf-8")
        else:
            haystack = DOCKERFILE
        assert PY_SDK_FLOOR in haystack

    def test_no_unpinned_python_sdk_reference_remains(self) -> None:
        # Catch a stray bare dependency line reintroducing the 0.2.0 resolution.
        for spec in MANIFEST["dependencies"]["python"]:
            if spec.startswith("caido-sdk-client"):
                assert spec == PY_SDK_FLOOR


# =============================================================================
# Provisioning contract
# =============================================================================


class TestCaidoModeInstall:
    def test_installs_node_deps_at_provision_time(self) -> None:
        assert "npm install --no-audit --no-fund" in INSTALL_SCRIPT

    def test_resolves_skill_dir_from_capability_root(self) -> None:
        # CAPABILITY_ROOT when exported, else the script's own parent — the
        # skill dir is mounted, not baked into the image.
        assert (
            'CAIDO_MODE_DIR="${CAPABILITY_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}'
            "/skills/caido-mode\"" in INSTALL_SCRIPT
        )

    def test_install_is_guarded_on_package_json(self) -> None:
        assert 'if [ -f "$CAIDO_MODE_DIR/package.json" ]; then' in INSTALL_SCRIPT

    def test_install_failure_is_non_fatal(self) -> None:
        # A missing Node toolchain must not abort the whole provision run.
        assert "WARN: caido-mode npm install failed, skipping" in INSTALL_SCRIPT

    def test_node_is_available_before_skill_install(self) -> None:
        # npm must exist by the time the skill block runs.
        node_setup = INSTALL_SCRIPT.index("deb.nodesource.com")
        skill_install = INSTALL_SCRIPT.index("CAIDO_MODE_DIR=")
        assert node_setup < skill_install

    def test_presence_check_registered(self) -> None:
        checks = {c["name"]: c["command"] for c in MANIFEST["checks"]}
        assert "caido-mode" in checks
        command = checks["caido-mode"]
        # Both the entrypoint and the installed deps — either alone is a
        # false green.
        assert "skills/caido-mode/caido-client.ts" in command
        assert "skills/caido-mode/node_modules" in command


# =============================================================================
# Cross-surface coexistence
# =============================================================================


class TestCaidoSurfacesCoexist:
    def test_all_four_surfaces_are_declared(self) -> None:
        servers = MANIFEST["mcp"]["servers"]
        checks = {c["name"] for c in MANIFEST["checks"]}
        assert "caido" in servers and "caido-go" in servers
        assert {"caido-cli", "caido-mcp-server", "caido-mode"} <= checks

    def test_sibling_caido_skills_present(self) -> None:
        for name in ("caido-sdk", "caido-proxy"):
            assert (ROOT / "skills" / name / "SKILL.md").is_file()

    def test_auth_stores_are_disjoint(self) -> None:
        # caido-mode keeps its own credential store so `setup` here never
        # clobbers the token file the Python SDK and both MCP servers share.
        body = SKILL_MD.read_text(encoding="utf-8")
        assert "~/.claude/config/secrets.json" in body
        assert "~/.caido-mcp/token.json" in body

    def test_skill_documents_surface_routing(self) -> None:
        body = SKILL_MD.read_text(encoding="utf-8")
        assert "Which Caido surface should I use?" in body
        for surface in ("caido-mode", "caido-sdk", "caido` MCP", "caido-go"):
            assert surface in body


# =============================================================================
# Sibling skill: caido-sdk example code
# =============================================================================


class TestCaidoSdkSkillExample:
    """The `caido-sdk` skill ships runnable Python that agents copy verbatim.

    A wrong signature there is worse than no example: it produces a confident
    `TypeError` at runtime. These assertions mirror the ones guarding
    ``mcp/caido.py`` in ``test_caido_mcp.py``.

    Verified against caido-sdk-client 0.3.0:
      ReplaySendOptions(raw, connection, settings)
      ConnectionInfoInput(host, port, is_tls, sni)
      ReplaySendResult(entry, status, error)
    """

    SKILL = (ROOT / "skills" / "caido-sdk" / "SKILL.md").read_text(encoding="utf-8")

    def _python_blocks(self) -> list[str]:
        return re.findall(r"```python\n(.*?)```", self.SKILL, re.DOTALL)

    def test_has_a_python_example(self) -> None:
        assert self._python_blocks()

    def test_examples_are_syntactically_valid(self) -> None:
        import ast

        for block in self._python_blocks():
            ast.parse(block)

    def test_example_sdk_constructor_kwargs_are_real(self) -> None:
        import ast

        valid = {
            "ReplaySendOptions": {"raw", "connection", "settings"},
            "ConnectionInfoInput": {"host", "port", "is_tls", "sni"},
            "CreateFindingOptions": {"title", "reporter", "description", "dedupe_key"},
            "CreateScopeOptions": {"name", "allowlist", "denylist"},
        }
        seen = 0
        for block in self._python_blocks():
            for node in ast.walk(ast.parse(block)):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in valid
                ):
                    seen += 1
                    kwargs = {kw.arg for kw in node.keywords if kw.arg}
                    extra = kwargs - valid[node.func.id]
                    assert not extra, (
                        f"{node.func.id}(...) in caido-sdk SKILL.md passes "
                        f"{sorted(extra)}, which the dataclass does not accept"
                    )
        assert seen, "no SDK constructions found to validate"

    def test_example_does_not_use_task_status(self) -> None:
        # ReplaySendResult exposes .status, never .task_status. Checked against
        # runnable code only — prose may name the wrong form to warn about it.
        for block in self._python_blocks():
            assert "task_status" not in block

    def test_example_does_not_flatten_connection_kwargs(self) -> None:
        for block in self._python_blocks():
            collapsed = " ".join(block.split())
            assert "ReplaySendOptions(" not in collapsed or "connection=" in collapsed

    def test_documents_the_python_sdk_floor(self) -> None:
        assert "caido-sdk-client>=0.3.0" in self.SKILL or ">= 0.3.0" in self.SKILL


# =============================================================================
# Sibling skill: caido-proxy tool names
# =============================================================================


class TestCaidoProxySkillToolNames:
    """The `caido-proxy` skill must describe tools that actually exist.

    It previously documented Go-server tool names (`list_requests`,
    `send_request`, the Automate family) as if they were on the Python server,
    under an `mcp__caido__` prefix that matched neither. An agent following it
    calls a tool that isn't in its schema.
    """

    SKILL = (ROOT / "skills" / "caido-proxy" / "SKILL.md").read_text(encoding="utf-8")

    @staticmethod
    def _python_server_tools() -> set[str]:
        import ast

        source = (ROOT / "mcp" / "caido.py").read_text(encoding="utf-8")
        return {
            node.name
            for node in ast.parse(source).body
            if isinstance(node, ast.AsyncFunctionDef)
            and any(getattr(d, "attr", "") == "tool" for d in node.decorator_list)
        }

    def test_every_python_server_tool_is_documented(self) -> None:
        missing = {t for t in self._python_server_tools() if t not in self.SKILL}
        assert not missing, f"undocumented `caido` tools: {sorted(missing)}"

    def test_no_stale_mcp_double_underscore_names(self) -> None:
        # `mcp__caido__list_requests` matched no real tool on either server.
        # The prefix may still be *named* when explaining namespacing, but it
        # must never be attached to a concrete tool name.
        stale = {
            match
            for match in re.findall(r"mcp__caido__(\w+)", self.SKILL)
            if match != "health"  # sole allowed mention: the namespacing example
        }
        assert not stale, f"stale mcp__caido__ tool references: {sorted(stale)}"

    def test_go_only_tools_are_marked_as_such(self) -> None:
        # Automate lives on caido-go; the skill must not imply the Python
        # server provides it.
        go_section = self.SKILL.index("On `caido-go` only")
        for tool in (
            "caido_list_automate_sessions",
            "caido_get_automate_session",
            "caido_get_automate_entry",
        ):
            assert tool in self.SKILL
            assert self.SKILL.index(tool) > go_section, (
                f"{tool} is a caido-go tool but appears before the caido-go section"
            )

    def test_documents_both_servers(self) -> None:
        assert "Two MCP servers, one instance" in self.SKILL
        assert "caido-go" in self.SKILL

    def test_warns_against_killing_caido_processes(self) -> None:
        # Troubleshooting must not suggest pkill: the desktop app runs its
        # backend as `caido-cli --listen`, so a broad kill takes down the
        # operator's live instance and in-flight project state.
        assert "pkill" in self.SKILL and "Never kill a Caido process" in self.SKILL
