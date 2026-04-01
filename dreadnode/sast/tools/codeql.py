"""
CodeQL static analysis tool with interprocedural taint tracking.

Provides deep static analysis using GitHub's CodeQL engine for finding
vulnerabilities that span multiple functions/files.
"""

import asyncio
import contextlib
import json
import os
import platform
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from dreadnode.agents.tools import Toolset, tool_method
from loguru import logger
from pydantic import PrivateAttr

# File extension → CodeQL language ID
_LANG_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java",
    ".kt": "java",
    ".cs": "csharp",
    ".c": "cpp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "cpp",
}

# Languages that don't need a build command
_NO_BUILD_LANGS: set[str] = {"python", "javascript", "go", "ruby"}

# Default security query suites per language
_DEFAULT_SUITES: dict[str, str] = {
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "go": "codeql/go-queries:codeql-suites/go-security-extended.qls",
    "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
    "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
    "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-extended.qls",
    "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
}

OUTPUT_CHAR_LIMIT = 15000
PER_RULE_LIMIT = 10
TOTAL_LIMIT = 200

# --- Installation constants ---

_CODEQL_HOME = Path.home() / ".codeql"
_CODEQL_BUNDLE_URL = "https://github.com/github/codeql-action/releases/latest/download/"
_INSTALL_TIMEOUT = 300  # 5 minutes for install steps

_INSTALL_ERROR = (
    "Error: CodeQL CLI is not installed and automatic installation failed.\n"
    "Install manually:\n"
    "  macOS:  brew install --cask codeql\n"
    "  Linux:  Download bundle from https://github.com/github/codeql-action/releases\n"
    "  Docker: Add CodeQL to your Dockerfile"
)


def _get_bundle_filename() -> str | None:
    """Return the CodeQL bundle filename for the current platform, or None."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        return (
            "codeql-bundle-osx-arm64.tar.gz"
            if machine == "arm64"
            else "codeql-bundle-osx64.tar.gz"
        )
    if system == "linux" and machine in ("x86_64", "amd64"):
        return "codeql-bundle-linux64.tar.gz"
    return None


def _score_to_severity(score: float) -> str:
    """Convert CVSS-style security-severity score to a label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_location(result: dict[str, Any]) -> tuple[str, int, int]:
    """Extract (file, start_line, end_line) from a SARIF result."""
    locs = result.get("locations") or []
    if not locs or not isinstance(locs, list):
        return ("", 0, 0)
    phys = locs[0].get("physicalLocation", {})
    file_path = phys.get("artifactLocation", {}).get("uri", "")
    region = phys.get("region", {})
    start_line = region.get("startLine", 0)
    end_line = region.get("endLine", start_line)
    return (file_path, start_line, end_line)


def _extract_flow_steps(result: dict[str, Any]) -> list[str]:
    """Extract data flow steps from SARIF codeFlows."""
    steps: list[str] = []
    for code_flow in result.get("codeFlows", []):
        for thread_flow in code_flow.get("threadFlows", []):
            for loc_entry in thread_flow.get("locations", []):
                step_loc = loc_entry.get("location", {})
                step_phys = step_loc.get("physicalLocation", {})
                step_file = step_phys.get("artifactLocation", {}).get("uri", "")
                step_region = step_phys.get("region", {})
                step_line = step_region.get("startLine", 0)
                step_msg = step_loc.get("message", {}).get("text", "")
                if step_file and step_line:
                    step_text = f"{step_file}:{step_line}"
                    if step_msg:
                        step_text += f" — {step_msg}"
                    steps.append(step_text)
    return steps


def _resolve_severity(
    level: str, rule_id: str, rules_by_id: dict[str, dict[str, Any]]
) -> str:
    """Derive severity from rule metadata, falling back to SARIF level."""
    rule_meta = rules_by_id.get(rule_id, {})
    props = rule_meta.get("properties", {})
    if isinstance(props, dict):
        sec_sev = props.get("security-severity")
        if sec_sev is not None:
            try:
                return _score_to_severity(float(str(sec_sev)))
            except ValueError:
                pass
    return level


async def _run_subprocess(cmd: list[str], timeout: int) -> tuple[int, bytes, bytes]:
    """Run a subprocess, returning (returncode, stdout, stderr).

    Raises asyncio.TimeoutError on timeout (after killing the process).
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise
    assert proc.returncode is not None
    return (proc.returncode, stdout, stderr)


def _truncate_err(stderr: bytes, limit: int = 2000) -> str:
    err = stderr.decode(errors="replace").strip()
    if len(err) > limit:
        return err[:limit] + "\n... (truncated)"
    return err


def _try_unlink(path: str) -> None:
    """Best-effort file deletion."""
    with contextlib.suppress(OSError):
        os.unlink(path)


class CodeQLTool(Toolset):
    """CodeQL static analysis with interprocedural taint tracking."""

    _db_cache: dict[tuple[str, str], str] = PrivateAttr(default_factory=dict)
    _codeql_path: str | None = PrivateAttr(default=None)
    _install_attempted: bool = PrivateAttr(default=False)

    # --- CodeQL binary resolution and installation ---

    def _find_codeql(self) -> str | None:
        """Check PATH and known install locations for the codeql binary (sync)."""
        if self._codeql_path:
            return self._codeql_path
        # Check PATH
        path = shutil.which("codeql")
        if not path:
            # Check well-known install location
            local = _CODEQL_HOME / "codeql" / "codeql"
            if local.is_file():
                path = str(local)
        if path:
            self._codeql_path = path
        return path

    async def _ensure_codeql(self) -> tuple[str | None, str | None]:
        """Find or install CodeQL. Returns (binary_path, error_message)."""
        found = self._find_codeql()
        if found:
            return (found, None)

        if self._install_attempted:
            return (None, _INSTALL_ERROR)
        self._install_attempted = True

        logger.info("CodeQL CLI not found in PATH, attempting installation...")
        installed = await self._install_codeql()
        if installed:
            self._codeql_path = installed
            return (installed, None)

        return (None, _INSTALL_ERROR)

    async def _install_codeql(self) -> str | None:
        """Try brew then bundle download. Returns binary path or None."""
        path = await self._install_codeql_brew()
        if path:
            return path
        return await self._install_codeql_bundle()

    async def _install_codeql_brew(self) -> str | None:
        """Install CodeQL via Homebrew. Returns binary path or None."""
        brew = shutil.which("brew")
        if not brew:
            return None
        logger.info("Trying: brew install --cask codeql")
        try:
            rc, _, _ = await _run_subprocess(
                [brew, "install", "--cask", "codeql"], _INSTALL_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.warning("Homebrew CodeQL install timed out")
            return None
        if rc != 0:
            logger.warning("Homebrew CodeQL install failed")
            return None
        return shutil.which("codeql")

    async def _install_codeql_bundle(self) -> str | None:
        """Download CodeQL bundle from GitHub releases. Returns binary path or None."""
        bundle_name = _get_bundle_filename()
        curl = shutil.which("curl")
        tar_bin = shutil.which("tar")
        if not bundle_name or not curl or not tar_bin:
            return None

        url = _CODEQL_BUNDLE_URL + bundle_name
        os.makedirs(str(_CODEQL_HOME), exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".tar.gz")
        os.close(tmp_fd)

        try:
            logger.info(f"Downloading CodeQL bundle: {bundle_name}")
            rc, _, _ = await _run_subprocess(
                [curl, "-fsSL", "-o", tmp_path, url], _INSTALL_TIMEOUT
            )
            if rc != 0:
                logger.warning("CodeQL bundle download failed")
                return None

            logger.info("Extracting CodeQL bundle...")
            rc, _, _ = await _run_subprocess(
                [tar_bin, "-xzf", tmp_path, "-C", str(_CODEQL_HOME)],
                _INSTALL_TIMEOUT,
            )
            if rc != 0:
                logger.warning("CodeQL bundle extraction failed")
                return None
        except asyncio.TimeoutError:
            logger.warning("CodeQL bundle download/extraction timed out")
            return None
        finally:
            _try_unlink(tmp_path)

        return self._find_codeql()

    # --- Language detection ---

    def _detect_language(self, path: Path) -> str | None:
        """Walk directory, count file extensions, return most common supported language."""
        counts: Counter[str] = Counter()
        for f in path.rglob("*"):
            if f.is_file() and f.suffix in _LANG_MAP:
                counts[_LANG_MAP[f.suffix]] += 1
        if not counts:
            return None
        return counts.most_common(1)[0][0]

    # --- CodeQL database and analysis ---

    async def _create_database(
        self,
        codeql: str,
        path: Path,
        language: str,
        db_dir: str,
        build_command: str | None,
        timeout: int,
    ) -> str | None:
        """Run codeql database create. Returns error string or None on success."""
        cmd = [
            codeql,
            "database",
            "create",
            db_dir,
            f"--language={language}",
            f"--source-root={path}",
            "--overwrite",
        ]
        if build_command:
            cmd.append(f"--command={build_command}")

        logger.debug(f"CodeQL database create: {' '.join(cmd)}")
        try:
            rc, _, stderr = await _run_subprocess(cmd, timeout)
        except asyncio.TimeoutError:
            return f"Error: database creation timed out after {timeout}s"

        if rc != 0:
            return (
                f"Error creating CodeQL database (exit {rc}):\n{_truncate_err(stderr)}"
            )
        return None

    async def _run_analysis(
        self,
        codeql: str,
        db_dir: str,
        language: str,
        query_suite: str | None,
        timeout: int,
    ) -> tuple[str | None, str]:
        """Run codeql database analyze. Returns (error, sarif_path)."""
        sarif_fd, sarif_path = tempfile.mkstemp(suffix=".sarif")
        os.close(sarif_fd)  # CodeQL writes to the path directly
        suite = query_suite or _DEFAULT_SUITES.get(language, "")
        if not suite:
            return (
                f"Error: no default query suite for language '{language}'. "
                "Provide query_suite explicitly.",
                "",
            )

        cmd = [
            codeql,
            "database",
            "analyze",
            db_dir,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--threads=0",
            "--",
            suite,
        ]

        logger.debug(f"CodeQL analyze: {' '.join(cmd)}")
        try:
            rc, _, stderr = await _run_subprocess(cmd, timeout)
        except asyncio.TimeoutError:
            return (f"Error: analysis timed out after {timeout}s", "")

        if rc != 0:
            return (
                f"Error running CodeQL analysis (exit {rc}):\n{_truncate_err(stderr)}",
                "",
            )
        return (None, sarif_path)

    # --- SARIF parsing and formatting ---

    def _parse_sarif(self, sarif_path: str) -> list[dict[str, Any]]:
        """Parse SARIF JSON and extract findings."""
        with open(sarif_path, encoding="utf-8") as f:
            sarif = json.load(f)

        findings: list[dict[str, Any]] = []
        for run in sarif.get("runs", []):
            rules_by_id: dict[str, dict[str, Any]] = {}
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rules_by_id[rule.get("id", "")] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                level = result.get("level", "warning")
                message = result.get("message", {}).get("text", "")
                file_path, start_line, end_line = _extract_location(result)
                flow_steps = _extract_flow_steps(result)
                severity = _resolve_severity(level, rule_id, rules_by_id)

                findings.append(
                    {
                        "rule": rule_id,
                        "severity": severity,
                        "message": message,
                        "file": file_path,
                        "start_line": start_line,
                        "end_line": end_line,
                        "flow": flow_steps,
                    }
                )
        return findings

    def _format_results(self, findings: list[dict[str, Any]], path: Path) -> str:
        """Format findings into agent-readable text grouped by severity."""
        if not findings:
            return f"CodeQL analysis complete: no security findings in {path}"

        severity_order = [
            "critical",
            "high",
            "error",
            "medium",
            "warning",
            "low",
            "note",
        ]
        by_severity: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            sev = str(f.get("severity", "warning"))
            by_severity.setdefault(sev, []).append(f)

        parts: list[str] = [f"CodeQL analysis: {len(findings)} finding(s) in {path}\n"]
        total_emitted = 0
        rule_counts: Counter[str] = Counter()

        for sev in severity_order:
            group = by_severity.pop(sev, [])
            if not group:
                continue
            total_emitted = self._format_severity_group(
                sev, group, parts, total_emitted, rule_counts
            )
            if total_emitted >= TOTAL_LIMIT:
                break

        # Remaining severity groups not in our order
        for sev, group in by_severity.items():
            if total_emitted >= TOTAL_LIMIT:
                break
            total_emitted = self._format_severity_group(
                sev, group, parts, total_emitted, rule_counts
            )

        result = "\n".join(parts)
        if len(result) > OUTPUT_CHAR_LIMIT:
            result = result[:OUTPUT_CHAR_LIMIT] + "\n\n... output truncated"
        return result

    def _format_severity_group(
        self,
        sev: str,
        group: list[dict[str, Any]],
        parts: list[str],
        total_emitted: int,
        rule_counts: Counter[str],
    ) -> int:
        """Append formatted findings for one severity group."""
        parts.append(f"## {sev.upper()} ({len(group)})\n")
        for finding in group:
            rule = str(finding.get("rule", ""))
            if rule_counts[rule] >= PER_RULE_LIMIT:
                continue
            if total_emitted >= TOTAL_LIMIT:
                parts.append(
                    f"\n... total finding limit ({TOTAL_LIMIT}) reached, remaining skipped"
                )
                break

            rule_counts[rule] += 1
            total_emitted += 1

            file_str = str(finding.get("file", ""))
            start = finding.get("start_line", 0)
            end = finding.get("end_line", 0)
            message = str(finding.get("message", ""))

            parts.append(f"### [{rule}] {file_str}:{start}-{end}")
            parts.append(f"  {message}")

            flow = finding.get("flow")
            if flow and isinstance(flow, list):
                parts.append("  Data flow:")
                parts.extend(f"    {step}" for step in flow)
            parts.append("")

        return total_emitted

    # --- Input validation ---

    def _validate_path_and_language(
        self,
        path: str,
        language: str | None,
        build_command: str | None,
    ) -> tuple[str | None, Path | None, str | None]:
        """Validate path and language inputs."""
        search_path = Path(path)
        if not search_path.is_absolute():
            search_path = Path.cwd() / search_path
        search_path = search_path.resolve()

        if not search_path.exists() or not search_path.is_dir():
            kind = (
                "does not exist" if not search_path.exists() else "is not a directory"
            )
            return (f"Error: path {kind}: {search_path}", None, None)

        lang = language
        if not lang:
            lang = self._detect_language(search_path)
            if not lang:
                return (
                    f"Error: could not detect language from files in {search_path}. "
                    "Provide language explicitly.",
                    None,
                    None,
                )
            logger.info(f"CodeQL auto-detected language: {lang}")

        if lang not in _DEFAULT_SUITES:
            return (
                f"Error: unsupported language '{lang}'. "
                f"Supported: {', '.join(sorted(_DEFAULT_SUITES))}",
                None,
                None,
            )

        if lang not in _NO_BUILD_LANGS and not build_command:
            return (
                f"Error: language '{lang}' requires a build_command "
                f"(e.g. 'make', 'dotnet build', './gradlew build'). "
                f"Provide build_command or use a no-build language.",
                None,
                None,
            )

        return (None, search_path, lang)

    def _get_or_init_db_dir(self, search_path: Path, lang: str) -> tuple[str, bool]:
        """Get cached DB dir or create a temp dir."""
        cache_key = (str(search_path), lang)
        db_dir = self._db_cache.get(cache_key)
        if db_dir and Path(db_dir).is_dir():
            return (db_dir, True)
        return (tempfile.mkdtemp(prefix="codeql-db-"), False)

    # --- Public tool method ---

    @tool_method(catch=True)
    async def codeql_scan(
        self,
        path: str,
        language: str | None = None,
        build_command: str | None = None,
        query_suite: str | None = None,
        timeout: int = 600,
    ) -> str:
        """
        Run CodeQL static analysis on a codebase. This is a SLOW but thorough tool
        (minutes, not seconds) that performs interprocedural taint tracking — tracing
        data flow across function boundaries from sources (user input) to sinks
        (dangerous operations like SQL queries, shell commands, etc.).

        Use this AFTER initial exploration to confirm suspected vulnerabilities that
        span multiple functions/files, where grep/dangerous_functions cannot prove
        the data flow. Do NOT use this as a first-pass discovery tool.

        CodeQL is auto-installed if not already present (via Homebrew or GitHub
        bundle download).

        Args:
            path: Path to the codebase root directory to analyze.
            language: Exact CodeQL language identifier. Auto-detected if omitted.
                Valid values: "python", "javascript" (covers JS+TS+JSX+TSX),
                "go", "ruby", "java" (covers Java+Kotlin), "csharp", "cpp"
                (covers C/C++/headers).
                NOTE: Use "javascript" not "typescript", "cpp" not "c" or "c++".
            build_command: Build command for compiled languages. Required for java,
                csharp, and cpp. Ignored for python/javascript/go/ruby.
                Examples: "mvn compile -DskipTests", "./gradlew build",
                "dotnet build", "make -j$(nproc)".
            query_suite: Override the CodeQL query suite. Omit this to use the default
                security-extended suite, which is the best choice for vulnerability
                detection. Only override for specialized analysis.
            timeout: Max seconds for EACH CodeQL phase (database creation and
                analysis are separate phases). Default 600. Total wall time can
                be up to 2x this value.

        Returns:
            Findings grouped by severity (critical/high/medium/low) with rule IDs,
            file locations, and data flow paths showing how tainted data reaches
            each sink. Returns an error message if CodeQL cannot be installed.
        """
        codeql, install_err = await self._ensure_codeql()
        if install_err:
            return install_err
        assert codeql is not None

        err, search_path, lang = self._validate_path_and_language(
            path, language, build_command
        )
        if err:
            return err
        assert search_path is not None
        assert lang is not None

        # Check/populate DB cache
        db_dir, is_cached = self._get_or_init_db_dir(search_path, lang)

        if is_cached:
            logger.info(f"Using cached CodeQL database at {db_dir}")
        else:
            logger.info(f"Creating CodeQL database for {lang} at {db_dir}")
            db_err = await self._create_database(
                codeql, search_path, lang, db_dir, build_command, timeout
            )
            if db_err:
                return db_err
            self._db_cache[(str(search_path), lang)] = db_dir

        # Run analysis, parse, and format
        analysis_err, sarif_path = await self._run_analysis(
            codeql, db_dir, lang, query_suite, timeout
        )
        if analysis_err:
            return analysis_err

        try:
            findings = self._parse_sarif(sarif_path)
            return self._format_results(findings, search_path)
        except (json.JSONDecodeError, OSError) as e:
            return f"Error parsing SARIF results: {e}"
        finally:
            # Best-effort cleanup of temporary SARIF file
            with contextlib.suppress(FileNotFoundError, OSError):
                if isinstance(sarif_path, Path):
                    sarif_path.unlink()
                else:
                    os.remove(sarif_path)
