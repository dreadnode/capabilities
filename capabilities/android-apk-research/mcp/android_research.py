#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "fastmcp>=2.0",
# ]
# ///
"""Orchestration MCP for Android APK semantic-bug research.

Wraps the per-script scripts in `../scripts/` behind a typed tool surface so
agents get tools/list discovery and uniform return shapes, while the heavyweight
methodology (jadx heap tiers, semgrep rule-pack ensembles, joern recipes, codeql
query packs, rg pattern selection) stays in the skills as bash. See
`skills/android-semantic-vuln-hunting/references/workflow.md` for the
"Why bash, not MCP" rationale on JADX / Semgrep / Joern.

Tools registered:

  * inventory_status          — probe which underlying tools are wired up
  * run_corpus_inventory      — parallel Androguard+APKiD inventory of an APK set
  * extract_components        — one row per (apk, component) for ranking
  * rank_components           — apply risk priors; emit components_ranked.md
  * detect_runtime_kind       — classify APK runtime (native / RN / Flutter / ...)
  * detect_protector          — detect DexProtector / Promon Shield signals
  * dexprotector_unpack       — static libdp.so recovery (arm64-v8a only)
  * extract_api_map           — regex-based APK→backend API/DTO/auth map
  * rank_backend_richness     — sort backend_richness.json summaries
  * normalize_semantic_findings — render finding JSONL into Markdown/CSV/JSONL

Per-APK artifacts (inventory, findings, hypotheses, reports) are operator-owned
and live under the path the caller supplies (typically `findings/<run>/`). The
MCP itself does not own any cache. If the capability later grows a derived-
artifact cache, follow the sibling convention
`${ANDROID_RESEARCH_CACHE_ROOT:-~/.dreadnode/cache/android-apk-research/}`.

Script invocation style: scripts with third-party deps (`protector_detect.py`,
`dexprotector_unpack.py`) carry a `uv run --script` shebang + PEP 723 block and
are invoked directly; stdlib-only scripts are invoked via `python3 path/to.py`.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

from fastmcp import FastMCP

mcp = FastMCP("android-research")

CAPABILITY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = CAPABILITY_ROOT / "scripts"

MAX_OUTPUT_CHARS = int(os.environ.get("ANDROID_RESEARCH_MAX_OUTPUT_CHARS", "20000"))
DEFAULT_TIMEOUT = int(os.environ.get("ANDROID_RESEARCH_TIMEOUT", "300"))

RUNTIME_KINDS = {
    "native",
    "react_native_js",
    "react_native_hermes",
    "flutter_aot",
    "capacitor",
    "cordova",
    "unity",
    "xamarin",
    "maui",
    "unknown",
}


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]..."


def _resolve_existing(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"path does not exist: {p}")
    return p


def _resolve_out(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _which(name: str) -> str | None:
    return shutil.which(name)


async def _run(
    argv: list[str],
    *,
    timeout: int,
) -> tuple[int, str]:
    """Run a subprocess, return (returncode, merged_stdout_stderr_text).

    Output is truncated to MAX_OUTPUT_CHARS at the tail. Raises TimeoutError
    on timeout so the MCP surfaces it to the agent as a tool-call error.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"command timed out after {timeout}s: {argv[0]}") from None
    rc = proc.returncode if proc.returncode is not None else 1
    return rc, _truncate(stdout.decode("utf-8", errors="ignore"))


def _strip_none(d: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose values are None/empty so the agent doesn't pay tokens
    for null-coerced fields. Keeps 0 and False on purpose."""
    return {
        k: v for k, v in d.items() if v is not None and v != "" and v != [] and v != {}
    }


# ── inventory_status ─────────────────────────────────────────────────


@mcp.tool
async def inventory_status() -> dict[str, Any]:
    """Probe whether the underlying CLIs and scripts this MCP relies on are
    reachable on this host.

    Each value is either "ok" (present) or a one-line reason it isn't. The
    methodology tools (jadx, semgrep, joern, codeql) live in the skill prose
    but are checked here so the agent can decide which skill steps will work
    end-to-end. Read this once at session start, not before every tool call.
    """
    status: dict[str, Any] = {"capability_root": str(CAPABILITY_ROOT)}

    # Hard prerequisites for this MCP's tools.
    for name, hint in [
        ("python3", "needed for the orchestrator scripts"),
        (
            "uv",
            "PEP 723 scripts (androguard_inventory, protector_detect, dexprotector_unpack)",
        ),
        ("apkid", "packer/protector signal during run_corpus_inventory"),
        ("aapt2", "manifest fallback when androguard errors on multi-dex APKs"),
        ("aapt", "manifest fallback alternative"),
    ]:
        path = _which(name)
        status[name] = path if path else f"missing — {hint}"

    # Skill-step tools — not required to boot the MCP, but the agent should
    # know whether step 3-9 of android-semantic-vuln-hunting will work.
    for name in ("jadx", "semgrep", "joern", "codeql", "adb"):
        path = _which(name)
        status[name] = path if path else "missing"

    # Hybrid-runtime follow-ups (Step 7.5 / 7.6).
    for name in ("hbctool", "blutter", "prettier", "npx"):
        path = _which(name)
        status[name] = path if path else "missing"

    # Per-script presence is covered by mcp/test_server.py::TestScriptWiring.

    return _strip_none(status)


# ── run_corpus_inventory ─────────────────────────────────────────────


@mcp.tool
async def run_corpus_inventory(
    paths: Annotated[
        list[str], "APK files or directories containing APKs to inventory in parallel"
    ],
    out_dir: Annotated[
        str, "Output run directory for per-APK artifacts and aggregate JSONL"
    ],
    jobs: Annotated[int, "Parallel worker count"] = 4,
    resume: Annotated[bool, "Skip APKs with existing ok status"] = True,
    timeout: Annotated[int, "Per-APK inventory timeout in seconds"] = 180,
    limit: Annotated[int | None, "Optional APK limit for smoke tests"] = None,
    include_apkid: Annotated[
        bool, "Run APKiD when installed for packer/protector signal"
    ] = True,
    preview_limit: Annotated[
        int, "Number of compact preview records to return inline"
    ] = 20,
) -> dict[str, Any]:
    """Run a parallel, resumable first-pass inventory over an APK corpus.

    Each APK becomes a SHA256-keyed artifact directory with `inventory.json`,
    `androguard.json` (decoded manifest, components, schemes, hosts, browsable
    components), optional `apkid.json`, and `status.json`. Aggregate
    `attack_surface.jsonl` and `status.jsonl` files are written for ranking.
    """
    if not paths:
        raise ValueError("paths must contain at least one APK file or directory")
    out_path = _resolve_out(out_dir)
    cmd = [
        "python3",
        str(SCRIPTS / "run_corpus_inventory.py"),
        *[str(Path(p).expanduser().resolve()) for p in paths],
        "--out-dir",
        str(out_path),
        "--jobs",
        str(jobs),
        "--timeout",
        str(timeout),
        "--preview",
        str(preview_limit),
    ]
    if resume:
        cmd.append("--resume")
    if limit is not None:
        cmd.extend(["--limit", str(limit)])
    if include_apkid:
        cmd.append("--include-apkid")
    if limit is not None:
        outer_timeout = max(timeout * limit // max(1, jobs) + 600, 900)
    else:
        outer_timeout = 8 * 3600
    rc, output = await _run(cmd, timeout=outer_timeout)

    summary_path = out_path / "run_status.json"
    summary: dict[str, Any] = {}
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text())
        except Exception:
            summary = {}

    response: dict[str, Any] = {
        "returncode": rc,
        "out_dir": str(out_path),
        "attack_surface_jsonl": str(out_path / "attack_surface.jsonl"),
        "status_jsonl": str(out_path / "status.jsonl"),
        "summary_path": str(summary_path),
    }
    if summary:
        response["summary"] = summary
    else:
        response["output"] = output
    return _strip_none(response)


# ── extract_components ───────────────────────────────────────────────


@mcp.tool
async def extract_components(
    inventory_dir: Annotated[
        str,
        "Directory containing per-APK SHA256 subdirs (the apks/ root from run_corpus_inventory)",
    ],
    out: Annotated[str, "Output components.jsonl path (one row per component)"],
    triage_manifest: Annotated[
        str | None,
        "Optional triage manifest JSONL keyed by sha256 for apk_path / impact_class joins",
    ] = None,
    runtime_kind: Annotated[
        str | None,
        "Optional runtime_kind JSONL from detect_runtime_kind sweep",
    ] = None,
    timeout: Annotated[int, "Timeout in seconds"] = 600,
) -> dict[str, Any]:
    """Emit one JSONL row per (apk, component) by streaming every
    `androguard.json` under the inventory directory, falling back to
    `aapt2 dump xmltree` for APKs where Androguard errored.

    Output rows carry exported/permission/scheme/host/path/action facts plus
    APK-level joins (apkid_tier, impact_class, runtime_kind). Feeds
    `rank_components`. See `scripts/extract_corpus_components.py` for the
    full schema.
    """
    inv = _resolve_existing(inventory_dir)
    out_path = _resolve_out(out)
    cmd = [
        "python3",
        str(SCRIPTS / "extract_corpus_components.py"),
        "--inventory-dir",
        str(inv),
        "--out",
        str(out_path),
    ]
    if triage_manifest:
        cmd.extend(["--triage-manifest", str(_resolve_existing(triage_manifest))])
    if runtime_kind:
        cmd.extend(["--runtime-kind", str(_resolve_existing(runtime_kind))])
    rc, output = await _run(cmd, timeout=timeout)
    return _strip_none(
        {
            "returncode": rc,
            "components_jsonl": str(out_path),
            "row_count": _count_lines(out_path) if out_path.exists() else 0,
            "output": output,
        }
    )


# ── rank_components ──────────────────────────────────────────────────


@mcp.tool
async def rank_components(
    components: Annotated[str, "Input components.jsonl from extract_components"],
    out_jsonl: Annotated[str, "Output ranked components JSONL path"],
    out_md: Annotated[str | None, "Optional Markdown operator-inbox path"] = None,
    top_md: Annotated[int, "Max rows in the Markdown inbox (default 150)"] = 150,
    min_score: Annotated[
        int, "Drop components scoring below this in the Markdown inbox"
    ] = 4,
    timeout: Annotated[int, "Timeout in seconds"] = 300,
) -> dict[str, Any]:
    """Apply risk priors to each component row and emit a ranked inbox.

    The full prior table lives in `scripts/rank_components.py`. Short version:
    exported BROWSABLE without permission = +5; host wildcard or high-risk
    path/scheme = +3; heavy packer = -12. Each row gets a `read_budget` tag
    (`5m` if score>=7, `1m` if 3-6, `skip` otherwise) so Tier C can budget.
    """
    src = _resolve_existing(components)
    out_path = _resolve_out(out_jsonl)
    cmd = [
        "python3",
        str(SCRIPTS / "rank_components.py"),
        "--components",
        str(src),
        "--out-jsonl",
        str(out_path),
        "--top-md",
        str(top_md),
        "--min-score",
        str(min_score),
    ]
    md_out: Path | None = None
    if out_md:
        md_out = _resolve_out(out_md)
        cmd.extend(["--out-md", str(md_out)])
    rc, output = await _run(cmd, timeout=timeout)
    return _strip_none(
        {
            "returncode": rc,
            "ranked_jsonl": str(out_path),
            "ranked_md": str(md_out) if md_out else None,
            "row_count": _count_lines(out_path) if out_path.exists() else 0,
            "output": output,
        }
    )


# ── detect_runtime_kind ──────────────────────────────────────────────


@mcp.tool
async def detect_runtime_kind(
    apk: Annotated[str, "Path to a single APK to classify"],
    timeout: Annotated[int, "Timeout in seconds"] = 30,
) -> dict[str, Any]:
    """Classify an APK's runtime in one second using `unzip -l` only.

    Returns one of: `native`, `react_native_js`, `react_native_hermes`,
    `flutter_aot`, `capacitor`, `cordova`, `unity`, `xamarin`, `maui`,
    `unknown`. Drives JADX heap sizing and routes to Step 7.5 (JS bundle
    trace) or 7.6 (Dart AOT trace) when non-native.
    """
    apk_path = _resolve_existing(apk)
    cmd = [
        "bash",
        str(SCRIPTS / "detect_runtime_kind.sh"),
        "--jsonl",
        str(apk_path),
    ]
    rc, output = await _run(cmd, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"detect_runtime_kind.sh failed (rc={rc}): {output}")
    # Script prints JSONL — one line per APK.
    line = output.strip().splitlines()[-1] if output.strip() else ""
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"detect_runtime_kind.sh produced non-JSON: {line!r}"
        ) from exc
    kind = record.get("runtime_kind", "unknown")
    if kind not in RUNTIME_KINDS:
        # Defensive: surface the value but tag it.
        record["runtime_kind_warning"] = f"unrecognized runtime_kind: {kind!r}"
    return record


# ── detect_protector ─────────────────────────────────────────────────


@mcp.tool
async def detect_protector(
    target: Annotated[str, "APK path or inventory dir with per-SHA artifacts"],
    out: Annotated[
        str | None,
        "Optional output protector.json path; default is alongside the target",
    ] = None,
    timeout: Annotated[int, "Timeout in seconds"] = 120,
) -> dict[str, Any]:
    """Detect commercial Android protectors (DexProtector, Promon Shield) and
    recommend a triage strategy.

    Key fields in the returned record: `protector` (`dexprotector` /
    `promon_shield` / `unknown`), `confidence` (high/medium/low),
    `triage_strategy` (`protector_aware` vs `default`), and
    `artifacts.dexprotector_unpack_supported` (true when arm64-v8a libdexprotector
    is present and `dexprotector_unpack` will succeed).

    If `dexprotector_unpack_supported` is true, the next step is calling
    `dexprotector_unpack` on the same APK. Otherwise, the recommended path is
    documented in `skills/android-protector-triage/SKILL.md` §3 (adjacency
    analysis only).
    """
    target_path = _resolve_existing(target)
    cmd = [
        str(SCRIPTS / "protector_detect.py"),
        str(target_path),
    ]
    if out:
        out_path = _resolve_out(out)
        cmd.extend(["-o", str(out_path)])
    rc, output = await _run(cmd, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"protector_detect.py failed (rc={rc}): {output}")
    # The script writes the JSON to stdout or to -o; parse stdout when no -o.
    if out:
        try:
            return _strip_none(json.loads(Path(out).expanduser().resolve().read_text()))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"could not read protector_detect output at {out}: {exc}"
            ) from exc
    # Stdout path — last JSON object in the output.
    try:
        return _strip_none(json.loads(output))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"protector_detect.py produced non-JSON stdout: {output[:500]!r}"
        ) from exc


# ── dexprotector_unpack ──────────────────────────────────────────────


@mcp.tool
async def dexprotector_unpack(
    apk: Annotated[
        str,
        "Path to a DexProtector-protected APK (arm64-v8a libdexprotector required)",
    ],
    out: Annotated[str, "Output path for the recovered libdp.so"],
    timeout: Annotated[int, "Timeout in seconds (Unicorn emulation can be slow)"] = 600,
) -> dict[str, Any]:
    """Static-unpack DexProtector's libdp.so without an Android device.

    Emulates the libdexprotector.so bootstrap chain via Unicorn to recover the
    plain libdp.so (which is the entry point for subsequent classes.dex.dat
    and `assets/se.dat` recovery). Does NOT execute libdp.so; everything is
    static. Does NOT trigger the master-key corruption described in Romain
    Thomas's writeup (libdp.so is never hooked).

    Run `detect_protector` first and only call this if
    `artifacts.dexprotector_unpack_supported` is true. ARM64-v8a only today.
    """
    apk_path = _resolve_existing(apk)
    out_path = _resolve_out(out)
    cmd = [
        str(SCRIPTS / "dexprotector_unpack.py"),
        str(apk_path),
        "-o",
        str(out_path),
    ]
    rc, output = await _run(cmd, timeout=timeout)
    if rc != 0:
        raise RuntimeError(
            f"dexprotector_unpack.py failed (rc={rc}). "
            f"Check that the APK ships arm64-v8a libdexprotector.so and that "
            f"detect_protector reported dexprotector_unpack_supported=true. "
            f"Output: {output}"
        )
    if not out_path.exists():
        raise RuntimeError(
            f"dexprotector_unpack.py returned 0 but wrote no output at {out_path}"
        )
    return {
        "returncode": rc,
        "libdp_so": str(out_path),
        "size": out_path.stat().st_size,
        "output": output,
    }


# ── extract_api_map ──────────────────────────────────────────────────


@mcp.tool
async def extract_api_map(
    src: Annotated[
        str,
        "Decompiled source tree, JS bundle dir, or Dart blutter output dir to scan",
    ],
    out: Annotated[str, "Output api_map.jsonl path (one row per finding)"],
    summary: Annotated[
        str | None,
        "Optional output backend_richness.json path with aggregate scores",
    ] = None,
    dedupe: Annotated[bool, "Deduplicate rows by (kind, value, file)"] = True,
    timeout: Annotated[int, "Timeout in seconds"] = 600,
) -> dict[str, Any]:
    """Regex-extract API endpoints, generated clients, request-signing hints,
    feature flags, object IDs, and workflow verbs from decompiled APK sources.

    Output is a target map for APK→backend hypotheses, NOT proof of
    vulnerability. Backend findings default to `needs_backend_validation` per
    `references/backend-rich-apk-workflows.md` until tested against authorized
    accounts/QA. Also works on `findings/<pkg>/js-analysis` (Step 7.5 output)
    and `findings/<pkg>/dart-analysis` (Step 7.6 / blutter output).
    """
    src_path = _resolve_existing(src)
    out_path = _resolve_out(out)
    cmd = [
        "python3",
        str(SCRIPTS / "extract_api_map.py"),
        "--src",
        str(src_path),
        "--out",
        str(out_path),
    ]
    summary_path: Path | None = None
    if summary:
        summary_path = _resolve_out(summary)
        cmd.extend(["--summary", str(summary_path)])
    if dedupe:
        cmd.append("--dedupe")
    rc, output = await _run(cmd, timeout=timeout)
    summary_data: dict[str, Any] = {}
    if summary_path and summary_path.exists():
        try:
            summary_data = json.loads(summary_path.read_text())
        except Exception:
            pass
    return _strip_none(
        {
            "returncode": rc,
            "api_map_jsonl": str(out_path),
            "summary_path": str(summary_path) if summary_path else None,
            "row_count": _count_lines(out_path) if out_path.exists() else 0,
            "summary": summary_data,
            "output": output if not summary_data else None,
        }
    )


# ── rank_backend_richness ────────────────────────────────────────────


@mcp.tool
async def rank_backend_richness(
    summaries: Annotated[
        list[str],
        "List of backend_richness.json files produced by extract_api_map",
    ],
    out_jsonl: Annotated[str, "Output sorted JSONL path"],
    out_md: Annotated[str | None, "Optional Markdown inbox path"] = None,
    timeout: Annotated[int, "Timeout in seconds"] = 120,
) -> dict[str, Any]:
    """Sort backend_richness summaries by score and emit an operator inbox.

    Each row carries score / richness band / unique-value counts / synergy
    flags (signed_requests + tenant_ids + workflow_verbs, etc.). Read the
    Markdown top-down as the next-targets-to-probe queue.
    """
    if not summaries:
        raise ValueError("summaries must contain at least one backend_richness.json")
    out_path = _resolve_out(out_jsonl)
    cmd = [
        "python3",
        str(SCRIPTS / "rank_backend_richness.py"),
        *[str(_resolve_existing(s)) for s in summaries],
        "--out-jsonl",
        str(out_path),
    ]
    md_out: Path | None = None
    if out_md:
        md_out = _resolve_out(out_md)
        cmd.extend(["--out-md", str(md_out)])
    rc, output = await _run(cmd, timeout=timeout)
    return _strip_none(
        {
            "returncode": rc,
            "ranked_jsonl": str(out_path),
            "ranked_md": str(md_out) if md_out else None,
            "row_count": _count_lines(out_path) if out_path.exists() else 0,
            "output": output,
        }
    )


# ── normalize_semantic_findings ──────────────────────────────────────


@mcp.tool
async def normalize_semantic_findings(
    inputs: Annotated[
        list[str], "JSON or JSONL files containing semantic finding hypotheses"
    ],
    output_format: Annotated[
        Literal["markdown", "jsonl", "csv"], "Render format"
    ] = "markdown",
    out: Annotated[str | None, "Optional output file path"] = None,
    timeout: Annotated[int, "Timeout in seconds"] = 120,
) -> dict[str, Any]:
    """Normalize, deduplicate, and render Android semantic finding hypotheses.

    Enforces a deterministic schema (entrypoint, source, trust boundary, sink,
    impact, evidence, validation plan, MASVS / CWE / MASWE tags, scanner gap,
    confidence and validation tiers, missing evidence) so reports stay
    comparable across runs. See
    `skills/android-semantic-vuln-hunting/references/output-schema.md` for
    the per-field reference.
    """
    if not inputs:
        raise ValueError("inputs must contain at least one findings file")
    cmd = [
        "python3",
        str(SCRIPTS / "normalize_findings.py"),
        *[str(_resolve_existing(p)) for p in inputs],
        "--format",
        output_format,
    ]
    out_path: Path | None = None
    if out:
        out_path = _resolve_out(out)
        cmd.extend(["--out", str(out_path)])
    rc, output = await _run(cmd, timeout=timeout)
    response: dict[str, Any] = {
        "returncode": rc,
        "output": output,
    }
    if out_path:
        response["output_path"] = str(out_path)
        response["bytes"] = out_path.stat().st_size if out_path.exists() else 0
    return _strip_none(response)


# ── internal helpers ─────────────────────────────────────────────────


def _count_lines(path: Path) -> int:
    try:
        with path.open("rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


if __name__ == "__main__":
    mcp.run()
