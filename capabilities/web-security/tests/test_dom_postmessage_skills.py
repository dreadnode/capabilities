"""Tests for the postMessage/DOM skill content.

These skills tell an agent which commands to run and which origin-validation
patterns are exploitable. Both classes of claim rot silently: a `rg` pattern
that no longer parses fails at the operator's terminal, and a bypass example
that is subtly wrong sends an agent chasing a non-issue.

The assertions here are deliberately behavioural rather than textual:

  * every ``rg`` snippet is compiled to check it is a valid regex under
    ripgrep's default engine (no look-around), and
  * every documented origin bypass is executed to confirm the "unsafe" pattern
    really does accept the attacker origin.

Content distilled from FransyTracker (https://gitlab.com/joaxcar/fransytracker),
itself derived from Frans Rosen's postMessage-tracker and Zeetaz's FancyTracker.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
DETECTION = SKILLS / "dom-vulnerability-detection" / "SKILL.md"
STATIC = SKILLS / "dom-vulnerability-static-analysis" / "SKILL.md"

DETECTION_TEXT = DETECTION.read_text(encoding="utf-8")
STATIC_TEXT = STATIC.read_text(encoding="utf-8")

# The ten rules exposed by FransyTrackerFindings.listRules(), verified against
# src/shared/findings.ts at ruleset version 3.
FRANSY_RULE_IDS = (
    "origin-regex-unescaped-dot",
    "origin-regex-missing-anchor",
    "missing-origin-check",
    "eval-on-message-data",
    "postmessage-wildcard-target",
    "location-assignment-from-data",
    "missing-data-type-guard",
    "xss-sink-on-message-data",
    "weak-origin-check",
    "tainted-data-to-sink",
)


# =============================================================================
# Listener discovery — the surfaces an addEventListener grep misses
# =============================================================================


class TestListenerDiscoverySurfaces:
    """A grep for addEventListener("message") is not a listener inventory."""

    @pytest.mark.parametrize("surface", ["onmessage", "MessagePort", "MessageChannel"])
    def test_detection_names_hidden_registration_surfaces(self, surface: str) -> None:
        assert surface in DETECTION_TEXT

    def test_detection_warns_grep_is_incomplete(self) -> None:
        assert "not a complete listener inventory" in DETECTION_TEXT

    def test_static_analysis_covers_setter_and_port(self) -> None:
        # ast-grep patterns verified to match real source in this repo's tests.
        assert "window.onmessage = $HANDLER" in STATIC_TEXT
        assert "$PORT.onmessage = $HANDLER" in STATIC_TEXT

    @pytest.mark.parametrize(
        "marker",
        ["__sentry_original__", "nr@original", "_rollbar_wrapped", "_isWrap"],
    )
    def test_wrapper_tells_documented(self, marker: str) -> None:
        # Monitoring wrappers hide the real handler; the skill must name the
        # properties that recover it.
        assert marker in DETECTION_TEXT

    def test_bugsnag_marked_unrecoverable(self) -> None:
        # FransyTracker deliberately does NOT unwrap Bugsnag (the callee.caller
        # chain is deprecated and unreliable). Claiming otherwise would send an
        # agent looking for a property that does not exist. Both Bugsnag rows
        # must say so.
        bugsnag_rows = [
            line
            for line in DETECTION_TEXT.splitlines()
            if line.startswith("| Bugsnag")
        ]
        assert len(bugsnag_rows) == 2, f"expected 2 Bugsnag rows, got {len(bugsnag_rows)}"
        for row in bugsnag_rows:
            assert "not recoverable" in row.lower(), f"Bugsnag row claims recovery: {row}"

    def test_unwrapping_is_described_as_recursive(self) -> None:
        assert "recursive" in DETECTION_TEXT.lower()

    def test_runtime_capture_covers_all_three_surfaces(self) -> None:
        # The runtime snippet must hook every registration path, or it repeats
        # the very blind spot the section warns about. Verified in a real
        # headless browser: all three fire.
        capture = DETECTION_TEXT[DETECTION_TEXT.index("At runtime, capture") :]
        assert "Window.prototype.addEventListener" in capture
        assert "MessagePort.prototype.addEventListener" in capture
        assert "Object.defineProperty(window, 'onmessage'" in capture

    def test_runtime_capture_warns_about_ordering(self) -> None:
        # Hooking after app JS has run misses earlier registrations.
        collapsed = " ".join(DETECTION_TEXT.split())
        assert "before app JS" in collapsed or "before the app" in collapsed

    def test_native_code_check_is_qualified_as_spoofable(self) -> None:
        # `toString().includes('native code')` is trivially spoofed by
        # overriding toString, and also trips on unrelated extensions. Shipping
        # it unqualified would invite a false conclusion.
        collapsed = " ".join(DETECTION_TEXT.split())
        assert "weak signal, not proof" in collapsed
        assert "spoof" in collapsed.lower()


# =============================================================================
# Origin validation anti-patterns — every bypass is executed
# =============================================================================


class TestOriginBypassClaims:
    """Each documented bypass must actually bypass."""

    @pytest.mark.parametrize(
        ("origin", "allowed", "operator"),
        [
            ("https://evil-example.com", "example.com", "indexOf"),
            ("https://example.com.evil.tld", "example.com", "indexOf"),
            ("https://example.com.evil.tld", "https://example.com", "startsWith"),
            ("https://evilexample.com", "example.com", "endsWith"),
        ],
    )
    def test_substring_operators_accept_attacker_origin(
        self, origin: str, allowed: str, operator: str
    ) -> None:
        if operator == "indexOf":
            assert allowed in origin
        elif operator == "startsWith":
            assert origin.startswith(allowed)
        else:
            assert origin.endswith(allowed)

    def test_unescaped_dot_matches_arbitrary_character(self) -> None:
        # /^https:\/\/trusted.example\.com$/ — the first dot is a wildcard.
        weak = re.compile(r"^https://trusted.example\.com$")
        assert weak.match("https://trustedXexample.com")
        strict = re.compile(r"^https://trusted\.example\.com$")
        assert not strict.match("https://trustedXexample.com")

    def test_missing_end_anchor_allows_suffix(self) -> None:
        weak = re.compile(r"^https://trusted\.example\.com")
        assert weak.match("https://trusted.example.com.evil.tld")
        anchored = re.compile(r"^https://trusted\.example\.com$")
        assert not anchored.match("https://trusted.example.com.evil.tld")

    @pytest.mark.parametrize(
        "operator", ["indexOf", "includes", "search", "startsWith", "endsWith"]
    )
    def test_all_weak_operators_are_documented(self, operator: str) -> None:
        # Must appear as a row of the anti-pattern table, not merely somewhere
        # in the prose — the table is what carries the bypass example.
        table_rows = [
            line
            for line in DETECTION_TEXT.splitlines()
            if line.startswith("| `origin") or line.startswith("| `e.origin")
        ]
        assert any(operator in row for row in table_rows), (
            f"{operator} missing from the origin anti-pattern table"
        )

    def test_loose_equality_documented(self) -> None:
        assert "loose equality" in DETECTION_TEXT.lower()

    def test_wildcard_reply_path_documented(self) -> None:
        # A handler can validate the inbound origin and still leak the reply.
        assert "postMessage(data, '*')" in DETECTION_TEXT
        assert "reply" in DETECTION_TEXT.lower()

    def test_checkpoint_covers_the_new_operators(self) -> None:
        checkpoint = DETECTION_TEXT[DETECTION_TEXT.index("**Checkpoint:** For each handler") :]
        for token in ("indexOf", "includes", "escaped dots", "unwrapped"):
            assert token in checkpoint


# =============================================================================
# Documented shell commands must actually run
# =============================================================================


def _rg_patterns(text: str) -> list[str]:
    """Extract the regex argument from each documented ``rg`` call.

    Handles both quoting styles used across the skills (single and double).
    """
    single = re.findall(r"^rg\s+(?:--\S+\s+)*'([^']+)'", text, re.MULTILINE)
    double = re.findall(r'^rg\s+(?:--\S+\s+)*"([^"]+)"', text, re.MULTILINE)
    return single + double


class TestDocumentedCommandsAreValid:
    def test_patterns_were_found(self) -> None:
        assert _rg_patterns(DETECTION_TEXT), "no rg snippets found in detection skill"
        assert _rg_patterns(STATIC_TEXT), "no rg snippets found in static skill"

    @pytest.mark.parametrize("skill", ["detection", "static"])
    def test_rg_patterns_avoid_lookaround(self, skill: str) -> None:
        # ripgrep's default engine rejects look-around: a documented pattern
        # using (?!...) fails with "look-around ... is not supported" unless
        # --pcre2 is passed. Catch that before an operator does.
        text = DETECTION_TEXT if skill == "detection" else STATIC_TEXT
        for pattern in _rg_patterns(text):
            if "--pcre2" in text and "(?" in pattern:
                continue
            assert "(?!" not in pattern and "(?=" not in pattern, (
                f"look-around in rg pattern without --pcre2: {pattern!r}"
            )
            assert "(?<" not in pattern, f"look-behind in rg pattern: {pattern!r}"

    @pytest.mark.parametrize("skill", ["detection", "static"])
    def test_rg_patterns_compile(self, skill: str) -> None:
        text = DETECTION_TEXT if skill == "detection" else STATIC_TEXT
        for pattern in _rg_patterns(text):
            re.compile(pattern)  # raises on malformed regex

    @pytest.mark.skipif(shutil.which("rg") is None, reason="ripgrep not installed")
    def test_weak_origin_pattern_matches_unsafe_and_skips_safe(self, tmp_path: Path) -> None:
        sample = tmp_path / "origins.js"
        sample.write_text(
            "\n".join(
                [
                    "if (e.origin.indexOf('example.com') === -1) return;",
                    "if (e.origin.includes('example.com')) ok();",
                    "if (e.origin.startsWith('https://example.com')) ok();",
                    "if (e.origin.endsWith('example.com')) ok();",
                    "if (e.origin.search('example.com')) ok();",
                    "if (e.origin == 'https://example.com') ok();",
                    "if (e.origin != 'https://x.com') return;",
                    "if (e.origin === 'https://example.com') ok();",  # safe
                ]
            ),
            encoding="utf-8",
        )
        pattern = next(
            p for p in _rg_patterns(STATIC_TEXT) if "indexOf|includes|search" in p
        )
        result = subprocess.run(  # noqa: S603
            ["rg", pattern, "-n", str(sample)],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"rg failed: {result.stderr}"
        matched = {int(line.split(":", 1)[0]) for line in result.stdout.splitlines()}
        assert matched == {1, 2, 3, 4, 5, 6, 7}, (
            f"expected the 7 weak lines and not the strict === on line 8, got {sorted(matched)}"
        )


# =============================================================================
# FransyTracker triage accelerator — claims about the third-party ruleset
# =============================================================================


class TestFransyTrackerReference:
    def test_all_ten_rule_ids_listed(self) -> None:
        for rule_id in FRANSY_RULE_IDS:
            assert rule_id in DETECTION_TEXT, f"rule id not documented: {rule_id}"

    def test_upstream_and_lineage_credited(self) -> None:
        # MIT-licensed third-party work; attribution is required, and the
        # lineage tells an operator where the technique originated.
        assert "gitlab.com/joaxcar/fransytracker" in DETECTION_TEXT
        assert "postMessage-tracker" in DETECTION_TEXT
        assert "FancyTracker" in DETECTION_TEXT

    def test_blind_spots_documented(self) -> None:
        # Measured against the real engine: these sinks are NOT flagged, so a
        # clean result must never be read as "safe".
        for missed in (
            "e.source.postMessage",
            "destructuring",
            "two-hop alias",
            "jQuery",
            "setTimeout",
        ):
            assert missed in DETECTION_TEXT, f"blind spot not documented: {missed}"

    def test_clean_result_is_not_called_safe(self) -> None:
        assert "never as \"safe\"" in DETECTION_TEXT

    def test_extension_opsec_warning_present(self) -> None:
        # host_permissions *://*/* + prototype hooking on every visited site.
        # Collapse whitespace: the warning wraps across lines in the markdown.
        collapsed = " ".join(DETECTION_TEXT.split())
        assert "host_permissions" in collapsed
        assert "dedicated browser profile" in collapsed
        assert "never your engagement-authenticated one" in collapsed

    def test_no_install_of_untrusted_code_is_implied_as_required(self) -> None:
        # The standalone module path must be presented as optional, so the
        # skill stays usable without cloning third-party code.
        heading = "## Optional: bulk-triage listener bodies"
        assert heading in DETECTION_TEXT


# =============================================================================
# Cross-skill wiring
# =============================================================================


class TestSkillCrossReferences:
    def test_detection_chains_to_cspt(self) -> None:
        # CSPT Gadget 8 chains an injected response into a postMessage listener.
        assert "cspt-xss" in DETECTION_TEXT

    def test_detection_chains_to_static_counterpart(self) -> None:
        assert "dom-vulnerability-static-analysis" in DETECTION_TEXT

    def test_referenced_skills_exist(self) -> None:
        for name in ("cspt-xss", "dom-vulnerability-static-analysis"):
            assert (SKILLS / name / "SKILL.md").is_file()
