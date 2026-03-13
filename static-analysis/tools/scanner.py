"""Semgrep static analysis scanner.

Wraps semgrep CLI for parallel SAST scanning across configurable policy
groups, with SARIF output validation and metrics generation.

Derived from: github.com/gadievron/raptor (packages/static-analysis/scanner.py)
Original authors: Gadi Evron, Daniel Cuthbert, Thomas Dullien, Michael Bargury, John Cartwright
"""

import json
import os
import re
import subprocess
import typing as t
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method

# Semgrep registry packs keyed by policy group name.
POLICY_GROUP_PACKS: dict[str, tuple[str, str]] = {
    "crypto": ("semgrep_crypto", "category/crypto"),
    "secrets": ("semgrep_secrets", "p/secrets"),
    "injection": ("semgrep_injection", "p/command-injection"),
    "auth": ("semgrep_auth", "p/jwt"),
    "ssrf": ("semgrep_ssrf", "p/ssrf"),
    "deserialization": ("semgrep_deserialization", "p/insecure-deserialization"),
    "logging": ("semgrep_logging", "p/logging"),
    "filesystem": ("semgrep_filesystem", "p/path-traversal"),
    "xss": ("semgrep_sinks", "p/xss"),
}

BASELINE_PACKS: list[tuple[str, str]] = [
    ("semgrep_security_audit", "p/security-audit"),
    ("semgrep_owasp_top_10", "p/owasp-top-ten"),
    ("semgrep_secrets", "p/secrets"),
]


def _clean_env() -> dict[str, str]:
    """Return env dict with virtualenv/PYTHONPATH stripped for semgrep."""
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    env.pop("PYTHONPATH", None)
    if "VIRTUAL_ENV" in os.environ:
        venv_bin = str(Path(os.environ["VIRTUAL_ENV"]) / "bin")
        env["PATH"] = ":".join(
            p for p in env.get("PATH", "").split(":") if p != venv_bin
        )
    return env


def _validate_sarif(sarif_path: Path) -> bool:
    """Basic SARIF validation — checks JSON structure and version."""
    try:
        with open(sarif_path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return False
        if data.get("version") not in ("2.1.0", "2.0.0"):
            return False
        if "runs" not in data:
            return False
        return True
    except (json.JSONDecodeError, OSError):
        return False


def _parse_sarif_findings(sarif_path: Path) -> list[dict[str, t.Any]]:
    """Parse findings from a SARIF file into normalized dicts."""
    findings: list[dict[str, t.Any]] = []
    try:
        with open(sarif_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    for run in data.get("runs", []):
        for result in run.get("results", []):
            location = {}
            if result.get("locations"):
                phys = result["locations"][0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                location = {
                    "file": artifact.get("uri", ""),
                    "startLine": region.get("startLine", 0),
                    "endLine": region.get("endLine", region.get("startLine", 0)),
                    "snippet": region.get("snippet", {}).get("text", ""),
                }

            findings.append(
                {
                    "rule_id": result.get("ruleId", "unknown"),
                    "message": result.get("message", {}).get("text", ""),
                    "level": result.get("level", "warning"),
                    **location,
                }
            )
    return findings


class SemgrepScanner(Toolset):
    """Run Semgrep static analysis scans with SARIF output."""

    timeout: int = 900
    """Timeout per scan task in seconds."""

    max_workers: int = 4
    """Number of parallel semgrep scans."""

    @tool_method
    def scan(
        self,
        repo_path: t.Annotated[str, "Path to the repository or directory to scan"],
        policy_groups: t.Annotated[
            str,
            "Comma-separated policy groups: crypto, secrets, injection, auth, ssrf, "
            "deserialization, logging, filesystem, xss. Default: all baseline packs.",
        ] = "",
        output_dir: t.Annotated[
            str, "Directory to write SARIF output files. Default: <repo>/.sast-output/"
        ] = "",
    ) -> str:
        """Run parallel Semgrep scans across selected policy groups and return metrics summary."""
        repo = Path(repo_path)
        if not repo.is_dir():
            return f"Error: {repo_path} is not a directory"

        out = Path(output_dir) if output_dir else repo / ".sast-output"
        out.mkdir(parents=True, exist_ok=True)

        # Build config list: baseline packs + policy-specific packs
        configs: list[tuple[str, str]] = list(BASELINE_PACKS)
        if policy_groups:
            for group in policy_groups.split(","):
                group = group.strip().lower()
                if group in POLICY_GROUP_PACKS:
                    configs.append(POLICY_GROUP_PACKS[group])

        # Deduplicate by pack name
        seen: set[str] = set()
        unique_configs: list[tuple[str, str]] = []
        for name, config in configs:
            if name not in seen:
                seen.add(name)
                unique_configs.append((name, config))

        # Run scans in parallel
        sarif_paths: list[str] = []
        failures: list[str] = []
        env = _clean_env()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(
                    self._run_single, name, config, repo, out, env
                ): name
                for name, config in unique_configs
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    path, ok = future.result()
                    if ok:
                        sarif_paths.append(path)
                    else:
                        failures.append(name)
                except Exception as exc:
                    failures.append(f"{name}: {exc}")

        # Generate metrics
        total_findings = 0
        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for sp in sarif_paths:
            for f in _parse_sarif_findings(Path(sp)):
                total_findings += 1
                level = f.get("level", "warning")
                by_severity[level] = by_severity.get(level, 0) + 1
                rule = f.get("rule_id", "unknown")
                by_rule[rule] = by_rule.get(rule, 0) + 1

        lines = [
            f"Scanned: {repo_path}",
            f"Scans completed: {len(sarif_paths)}/{len(unique_configs)}",
            f"Total findings: {total_findings}",
        ]
        if by_severity:
            lines.append("By severity: " + ", ".join(f"{k}={v}" for k, v in sorted(by_severity.items())))
        if by_rule:
            top_rules = sorted(by_rule.items(), key=lambda x: -x[1])[:10]
            lines.append("Top rules: " + ", ".join(f"{k} ({v})" for k, v in top_rules))
        if failures:
            lines.append(f"Failed scans: {', '.join(failures)}")
        lines.append(f"SARIF output: {out}")

        return "\n".join(lines)

    def _run_single(
        self,
        name: str,
        config: str,
        repo: Path,
        out_dir: Path,
        env: dict[str, str],
    ) -> tuple[str, bool]:
        """Run a single semgrep scan and return (sarif_path, success)."""
        safe_name = re.sub(r"[/:]", "_", name)
        sarif_path = out_dir / f"semgrep_{safe_name}.sarif"

        cmd = [
            "semgrep", "scan",
            "--config", config,
            "--quiet",
            "--metrics", "off",
            "--sarif",
            "--output", str(sarif_path),
            str(repo),
        ]

        try:
            result = subprocess.run(
                cmd, env=env, capture_output=True, text=True, timeout=self.timeout
            )
            # semgrep exit 0=no findings, 1=findings found — both OK
            if result.returncode in (0, 1) and sarif_path.exists():
                if _validate_sarif(sarif_path):
                    return str(sarif_path), True

            # Write error log
            stderr_path = out_dir / f"semgrep_{safe_name}.stderr.log"
            stderr_path.write_text(result.stderr)
            return str(sarif_path), False

        except subprocess.TimeoutExpired:
            return str(sarif_path), False

    @tool_method
    def parse_findings(
        self,
        sarif_path: t.Annotated[str, "Path to a SARIF file to parse"],
        max_findings: t.Annotated[int, "Maximum number of findings to return"] = 50,
    ) -> str:
        """Parse a SARIF file and return findings as structured text."""
        path = Path(sarif_path)
        if not path.exists():
            return f"Error: {sarif_path} does not exist"

        findings = _parse_sarif_findings(path)
        if not findings:
            return "No findings in SARIF file."

        lines = [f"Total findings: {len(findings)}\n"]
        for i, f in enumerate(findings[:max_findings]):
            lines.append(
                f"[{i+1}] {f.get('level', '?').upper()} {f.get('rule_id', '?')}\n"
                f"    {f.get('file', '?')}:{f.get('startLine', '?')}\n"
                f"    {f.get('message', '')[:200]}"
            )
        if len(findings) > max_findings:
            lines.append(f"\n... and {len(findings) - max_findings} more findings")

        return "\n".join(lines)
