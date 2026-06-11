"""BBOT reconnaissance scanning and Neo4j graph database query tools.

Provides run_bbot_scan for executing BBOT CLI scans and a suite of Neo4j
Cypher query tools for analyzing reconnaissance results stored in a
property graph. The Neo4j connection is lazily initialized on first query.

Prerequisites:
    - bbot CLI installed and in PATH
    - Neo4j database running (container or external)
    - Neo4j output module configured in BBOT
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import json
import logging
import os
import re
import shlex
import tempfile
import typing as t
import urllib.error
import urllib.request
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

try:
    from neo4j import AsyncDriver, AsyncGraphDatabase
except ImportError:
    AsyncDriver = None  # type: ignore[assignment, misc]
    AsyncGraphDatabase = None  # type: ignore[assignment, misc]

# Reduce Neo4j driver logging noise
logging.getLogger("neo4j").setLevel(logging.ERROR)


def _parse_serialized_dict(data: str) -> t.Any:
    """Parse string representations of JSON or Python literals into dicts."""
    if not isinstance(data, str):
        return data
    with contextlib.suppress(Exception):
        result = json.loads(data)
        return result if isinstance(result, dict) else {}
    with contextlib.suppress(Exception):
        result = ast.literal_eval(data)
        return result if isinstance(result, dict) else {}
    return data


def _coerce_string_list(value: t.Any) -> list[str]:
    """Accept native lists plus JSON/Python stringified lists from weaker tool callers."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        with contextlib.suppress(Exception):
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item)]
        with contextlib.suppress(Exception):
            parsed = ast.literal_eval(stripped)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item)]
        return [stripped]
    return [str(value)]


def _normalize_config(config: list[str]) -> list[str]:
    """Accept common stale BBOT config names emitted by older prompts/skills."""
    replacements = {
        "modules.httpx.timeout": "modules.http.timeout",
        "http.web_spider_distance": "web.spider_distance",
        "scope.distance": "scope.search_distance",
    }
    dropped = {
        "scope.report_distance",
    }
    normalized: list[str] = []
    for item in config:
        key, sep, value = item.partition("=")
        if key in dropped:
            continue
        if (
            key.startswith("modules.")
            and key.endswith(".enabled")
            and value.lower() == "false"
        ):
            continue
        normalized.append(f"{replacements.get(key, key)}{sep}{value}")
    return normalized


def _normalize_extra_args(args: list[str]) -> list[str]:
    """Drop stale BBOT CLI flags emitted by models."""
    normalized: list[str] = []
    skip_next = False
    drop_next_value_for = {
        "--timeout",
        "-x",
        "--modules",
        "-m",
    }
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in drop_next_value_for:
            skip_next = True
            continue
        if arg.startswith("--timeout="):
            continue
        if arg.startswith("--modules="):
            continue
        if arg == "--scope-distance":
            skip_next = True
            continue
        if arg.startswith("--scope-distance="):
            continue
        normalized.append(arg)
    return normalized


def _normalize_targets(targets: list[str]) -> list[str]:
    """Convert wildcard scope expressions into BBOT seed targets."""
    normalized: list[str] = []
    for target in targets:
        stripped = target.strip()
        if stripped.startswith("*.") and len(stripped) > 2:
            stripped = stripped[2:]
        if stripped:
            normalized.append(stripped)
    return normalized


def _query_graph_api(
    graph_api_url: str, cypher: str, params: dict[str, t.Any] | None = None
) -> list[dict[str, t.Any]]:
    """Execute Cypher through a task-local HTTP graph proxy."""
    url = graph_api_url.rstrip("/") + "/query"
    body = json.dumps({"cypher": cypher, "params": params or {}}).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"Graph API query failed ({exc.code}): {detail}") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
        raise RuntimeError(f"Graph API returned unexpected payload: {payload!r}")
    return payload["rows"]


_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)


def _summarize_bbot_stdout(output: str, max_chars: int) -> str:
    """Condense BBOT JSON/stdout output into LLM-friendly telemetry."""
    type_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    examples: list[dict[str, t.Any]] = []
    scans: list[dict[str, t.Any]] = []
    diagnostic_tail: list[str] = []
    event_count = 0

    for raw_line in output.splitlines():
        line = _strip_ansi(raw_line).strip()
        if not line:
            continue

        parsed: dict[str, t.Any] | None = None
        if line.startswith("{"):
            with contextlib.suppress(Exception):
                value = json.loads(line)
                if isinstance(value, dict):
                    parsed = value

        if parsed:
            event_count += 1
            event_type = str(parsed.get("type") or "UNKNOWN")
            scope = str(parsed.get("scope_description") or "unknown")
            module = str(parsed.get("module") or parsed.get("source") or "")
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
            scope_counts[scope] = scope_counts.get(scope, 0) + 1
            if module:
                module_counts[module] = module_counts.get(module, 0) + 1

            compact = {
                "type": event_type,
                "scope_description": scope,
                "data": parsed.get("data"),
            }
            if module:
                compact["module"] = module
            if event_type == "SCAN":
                scans.append(compact)
            elif len(examples) < 30 and event_type in {
                "DNS_NAME",
                "URL",
                "OPEN_TCP_PORT",
                "TECHNOLOGY",
                "FINDING",
                "IP_ADDRESS",
                "WEBSCREENSHOT",
                "STORAGE_BUCKET",
                "SOCIAL",
                "MOBILE_APP",
            }:
                examples.append(compact)
            continue

        diagnostic_tail.append(line[:300])
        diagnostic_tail = diagnostic_tail[-40:]

    summary = {
        "mode": "bbot_stdout_json_summary",
        "raw_output_chars": len(output),
        "event_count": event_count,
        "type_counts": dict(
            sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
        "scope_counts": dict(
            sorted(scope_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
        "module_counts": dict(
            sorted(module_counts.items(), key=lambda item: (-item[1], item[0]))[:20]
        ),
        "representative_events": examples,
        "scan_records": scans[-5:],
        "diagnostic_tail": diagnostic_tail,
    }
    text = (
        "BBOT completed with JSON/stdout evidence. The raw event stream was "
        "summarized to keep the agent context small; use the counts and "
        "representative_events below for ASM statistics and leads.\n\n"
        + json.dumps(summary, indent=2, default=str)
    )
    if len(text) > max_chars:
        text = (
            text[:max_chars] + f"\n\n... [SUMMARY TRUNCATED: {len(text)} chars total]"
        )
    return text


def _count_bbot_json_events(output: str) -> int:
    """Count JSON event lines in BBOT stdout."""
    event_count = 0
    for raw_line in output.splitlines():
        line = _strip_ansi(raw_line).strip()
        if not line.startswith("{"):
            continue
        with contextlib.suppress(Exception):
            value = json.loads(line)
            if isinstance(value, dict):
                event_count += 1
    return event_count


def _bbot_output_has_blocking_diagnostic(output: str) -> bool:
    """Detect BBOT diagnostics that mean no useful scan ran."""
    blocking_markers = (
        "Setup hard-failed",
        "[ERRR]",
        "[ERROR]",
        "Please specify --allow-deadly to continue",
        "No modules to scan",
    )
    return any(marker in output for marker in blocking_markers)


def _has_dependency_control_arg(args: list[str]) -> bool:
    dependency_args = {
        "--no-deps",
        "--force-deps",
        "--retry-deps",
        "--ignore-failed-deps",
        "--install-all-deps",
    }
    return any(arg in dependency_args for arg in args)


def _has_module_exclusion_arg(args: list[str]) -> bool:
    return any(arg in {"--exclude-modules", "-em"} for arg in args)


def _requests_baddns(modules: list[str]) -> bool:
    return any(module.startswith("baddns") for module in modules)


def _allows_deadly(args: list[str]) -> bool:
    return "--allow-deadly" in args


def _normalize_modules(modules: list[str], extra_args: list[str]) -> list[str]:
    """Drop common non-BBOT/deadly module guesses that would abort a scan."""
    replacements = {
        "aws_s3_scan": "bucket_amazon",
        "azure_blob_scan": "bucket_microsoft",
        "azure_blobs": "bucket_microsoft",
        "gcp_storage": "bucket_google",
        "gcp_storage_buckets": "bucket_google",
        "gcp_storage_scan": "bucket_google",
        "http-probes": "httpx",
        "http_probe": "httpx",
        "http-probe": "httpx",
        "http_probes": "httpx",
        "s3_buckets": "bucket_amazon",
        "s3_scan": "bucket_amazon",
        "censys": "censys_ip",
        "subenum": "subdomaincenter",
        "subdomain_enum": "subdomaincenter",
        "subdomain-enum": "subdomaincenter",
        "subdomainenum": "subdomaincenter",
        "technologies": "httpx",
        "web-basic": "httpx",
        "web_basic": "httpx",
    }
    unsupported = {
        "amass",
        "assetfinder",
        "crtsh",
        "dns_zone_transfer",
        "fastdial",
        "find_subdomains",
        "findomain",
        "gau",
        "massdns",
        "naabu",
        "active",
        "passive",
        "portscan",
        "safe",
        "screenshot",
        "shuffledns",
        "subdomain-finder",
        "subdomain_find",
        "subdomain_bruteforce",
        "subdomain-bruteforce",
        "subdomainfinder",
        "subfinder",
        "sublist3r",
        "web_enum",
        "web-enum",
        "web_screenshot",
        "web-screenshot",
        "web_screenshots",
        "web-screenshots",
        "webenum",
        "wappalyzer",
    }
    normalized: list[str] = []
    for module in modules:
        module = replacements.get(module, module)
        if module in unsupported:
            continue
        if module == "nuclei" and not _allows_deadly(extra_args):
            continue
        normalized.append(module)
    return normalized


def _normalize_presets(presets: list[str], extra_args: list[str]) -> list[str]:
    """Avoid BBOT deadly preset aborts unless explicitly requested."""
    replacements = {
        "asset-discovery-and-enrichment": "subdomain-enum",
        "asset-discovery": "subdomain-enum",
        "asset_discovery": "subdomain-enum",
        "asset-discovery-web-endpoints": "web-basic",
        "asset_discovery_web_endpoints": "web-basic",
        "asset_discovery_and_enrichment": "subdomain-enum",
        "discovery": "subdomain-enum",
        "subdomain_discovery": "subdomain-enum",
        "subdomain-discovery": "subdomain-enum",
        "subdomain_enumeration": "subdomain-enum",
        "subdomain-enumeration": "subdomain-enum",
        "web_breach": "web-basic",
        "web_basic": "web-basic",
        "web_discovery": "web-basic",
        "web_scan": "web-basic",
        "web-port-scan-and-tech-detect": "web-basic",
        "web_port_scan_and_tech_detect": "web-basic",
    }
    supported = {
        "subdomain-enum",
        "web-basic",
        "web-thorough",
        "cloud-enum",
        "code-enum",
        "email-enum",
        "spider",
        "nuclei",
        "nuclei-intense",
        "dirbust-light",
        "dirbust-heavy",
        "lightfuzz-light",
        "lightfuzz-medium",
        "tech-detect",
        "kitchen-sink",
    }
    presets = [replacements.get(preset, preset) for preset in presets]
    presets = [preset for preset in presets if preset in supported]
    if _allows_deadly(extra_args):
        return presets
    return [
        preset
        for preset in presets
        if not preset.startswith("nuclei") and preset != "kitchen-sink"
    ]


def _normalize_flags(flags: list[str]) -> list[str]:
    """Drop CLI switches and stale flag names emitted as BBOT flags."""
    supported = {
        "active",
        "passive",
        "safe",
        "aggressive",
        "subdomain-enum",
        "web-basic",
        "web-thorough",
        "cloud-enum",
        "code-enum",
        "email-enum",
    }
    return [flag for flag in flags if flag in supported]


def _sandbox_suppression_note(
    requested_modules: list[str], graph_api_url: str | None
) -> str:
    if not graph_api_url or not requested_modules:
        return ""
    suppressed = sorted(
        {module for module in requested_modules if module in {"gowitness", "portscan"}}
    )
    if not suppressed:
        return ""
    return (
        "Sandbox note: "
        + ", ".join(suppressed)
        + " requested but suppressed in Graph API mode for runtime reliability; "
        "use returned DNS/URL/FINDING evidence, `httpx`, and safe web presets for bounded validation.\n\n"
    )


def _bbot_subprocess_env(graph_api_url: str | None) -> dict[str, str]:
    env = os.environ.copy()
    if graph_api_url:
        bbot_home = Path(tempfile.mkdtemp(prefix="asm-bbot-home-"))
        env["HOME"] = str(bbot_home)
        env["BBOT_HOME"] = str(bbot_home / ".bbot")
    return env


def _summarize(data: dict[str, t.Any]) -> dict[str, t.Any]:
    """Condense a node record to essential fields, truncating long values."""
    summary: dict[str, t.Any] = {}
    essential = [
        "id",
        "type",
        "data",
        "host",
        "netloc",
        "port",
        "tags",
        "scope_description",
        "scope_distance",
    ]
    for field in essential:
        if field in data and data[field] is not None:
            value = data[field]
            if isinstance(value, list) and len(value) > 5:
                summary[field] = value[:5]
                summary[f"{field}_truncated"] = True
            elif isinstance(value, str) and len(value) > 200:
                summary[field] = value[:200] + "..."
            else:
                summary[field] = value
    if "id" in summary and isinstance(summary["id"], str) and len(summary["id"]) > 40:
        summary["id"] = summary["id"][:40] + "..."
    return summary


class BbotTools(Toolset):
    """Execute BBOT reconnaissance scans and query results from the Neo4j graph database."""

    neo4j_uri: str = "bolt://localhost:7687"
    """Neo4j bolt URI. Override with NEO4J_URI env var or set directly."""

    neo4j_user: str = "neo4j"
    """Neo4j username."""

    neo4j_password: str = "bbotislife"
    """Neo4j password."""

    bbot_data_dir: str = ".bbot"
    """Directory where BBOT stores scan data."""

    scan_timeout: int = 3600
    """Maximum time in seconds for a BBOT scan to run."""

    max_output_chars: int = 7_000
    """Maximum characters returned from scan output."""

    _drivers: dict[tuple[str, str, str], t.Any] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: t.Any) -> None:
        """Apply environment variable overrides after initialization."""
        if uri := os.environ.get("NEO4J_URI"):
            self.neo4j_uri = uri
        if user := os.environ.get("NEO4J_USER"):
            self.neo4j_user = user
        if password := os.environ.get("NEO4J_PASSWORD"):
            self.neo4j_password = password

    def _connection(
        self,
        neo4j_uri: str | None = None,
        neo4j_user: str | None = None,
        neo4j_password: str | None = None,
    ) -> tuple[str, str, str]:
        """Resolve a Neo4j connection, allowing task-local endpoint overrides."""
        return (
            neo4j_uri or self.neo4j_uri,
            neo4j_user or self.neo4j_user,
            neo4j_password or self.neo4j_password,
        )

    async def _ensure_driver(
        self,
        neo4j_uri: str | None = None,
        neo4j_user: str | None = None,
        neo4j_password: str | None = None,
    ) -> "AsyncDriver":
        """Lazily initialize and return the Neo4j async driver."""
        uri, user, password = self._connection(neo4j_uri, neo4j_user, neo4j_password)
        key = (uri, user, password)
        if key not in self._drivers:
            if AsyncGraphDatabase is None:
                raise RuntimeError(
                    "neo4j package is not installed. Install with: pip install neo4j>=5.28.1"
                )
            driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
            await driver.verify_connectivity()
            self._drivers[key] = driver
        return self._drivers[key]

    async def _query(
        self,
        cypher: str,
        params: dict[str, t.Any] | None = None,
        neo4j_uri: str | None = None,
        neo4j_user: str | None = None,
        neo4j_password: str | None = None,
        graph_api_url: str | None = None,
    ) -> list[dict[str, t.Any]]:
        """Execute a Cypher query and return results as list of dicts."""
        if graph_api_url:
            return await asyncio.to_thread(
                _query_graph_api, graph_api_url, cypher, params
            )
        driver = await self._ensure_driver(neo4j_uri, neo4j_user, neo4j_password)
        async with driver.session() as session:
            result = await session.run(cypher, params or {})
            return [record.data() async for record in result]

    async def _get_nodes(
        self,
        label: str,
        filters: dict[str, t.Any] | None = None,
        limit: int = 100,
        neo4j_uri: str | None = None,
        neo4j_user: str | None = None,
        neo4j_password: str | None = None,
        graph_api_url: str | None = None,
    ) -> list[dict[str, t.Any]]:
        """Fetch nodes by label with optional property filtering."""
        where_clauses = ["$label IN labels(n)"]
        if filters:
            where_clauses.extend(f"n.`{key}` = ${key}" for key in filters)

        cypher = f"""
            MATCH (n)
            WHERE {" AND ".join(where_clauses)}
            RETURN n
            {"LIMIT " + str(limit) if limit else ""}
        """
        params: dict[str, t.Any] = {"label": label}
        if filters:
            params.update(filters)
        result = await self._query(
            cypher, params, neo4j_uri, neo4j_user, neo4j_password, graph_api_url
        )
        return [record["n"] for record in result]

    # ── Scanning ──────────────────────────────────────────────────────────

    @tool_method(name="run_bbot_scan", catch=True)
    async def run_scan(
        self,
        targets: t.Annotated[
            list[str] | str,
            "Targets to scan (e.g., ['example.com', '10.0.0.0/24'])",
        ],
        modules: t.Annotated[
            list[str] | str | None,
            "Modules to run (e.g., ['httpx', 'nuclei'])",
        ] = None,
        presets: t.Annotated[
            list[str] | str | None,
            "Presets to use (e.g., ['subdomain-enum', 'web-basic']). "
            "Available: subdomain-enum, web-basic, web-thorough, cloud-enum, code-enum, "
            "email-enum, spider, nuclei, nuclei-intense, dirbust-light, dirbust-heavy, "
            "lightfuzz-light, lightfuzz-medium, tech-detect, kitchen-sink",
        ] = None,
        flags: t.Annotated[
            list[str] | str | None,
            "Flags to enable module groups (e.g., ['passive', 'safe']). "
            "Available: active, passive, safe, aggressive, subdomain-enum, web-basic, "
            "web-thorough, cloud-enum, code-enum, portscan, web-screenshots",
        ] = None,
        config: t.Annotated[
            list[str] | str | None,
            "Custom config in key=value format (e.g., ['modules.http.timeout=5'])",
        ] = None,
        extra_args: t.Annotated[
            list[str] | str | None,
            "Additional bbot CLI flags (e.g., ['--strict-scope', '--proxy http://127.0.0.1:8080'])",
        ] = None,
        neo4j_uri: t.Annotated[
            str | None,
            "Neo4j bolt URI for storing scan results. Defaults to configured NEO4J_URI.",
        ] = None,
        neo4j_user: t.Annotated[
            str | None,
            "Neo4j username. Defaults to configured NEO4J_USER.",
        ] = None,
        neo4j_password: t.Annotated[
            str | None,
            "Neo4j password. Defaults to configured NEO4J_PASSWORD.",
        ] = None,
        graph_api_url: t.Annotated[
            str | None,
            "Task-local Graph API URL. When supplied, run BBOT in stdout JSON mode "
            "so sandboxed evaluations do not require raw Bolt access.",
        ] = None,
        timeout: t.Annotated[
            int | None,
            "Optional per-call scan timeout in seconds.",
        ] = None,
    ) -> str:
        """Execute a BBOT reconnaissance scan against targets.

        Assembles and runs a `bbot` command, automatically configuring it to
        report findings to the Neo4j database. Results are stored in the graph
        and can be queried with the other tools.

        The scan runs locally via the bbot CLI which must be installed and in PATH.
        """
        targets = _normalize_targets(_coerce_string_list(targets))
        flags = _normalize_flags(_coerce_string_list(flags))
        config = _normalize_config(_coerce_string_list(config))
        extra_args = _normalize_extra_args(_coerce_string_list(extra_args))
        requested_modules = _coerce_string_list(modules)
        modules = _normalize_modules(requested_modules, extra_args)
        presets = _normalize_presets(_coerce_string_list(presets), extra_args)

        if not targets:
            raise ValueError("At least one target is required to run a scan.")
        scan_timeout = max(
            30, min(int(timeout or self.scan_timeout), self.scan_timeout)
        )

        # In platform sandboxes, task services are often exposed through HTTP
        # proxies that do not support the Bolt protocol. A graph_api_url signals
        # that graph queries should use HTTP, so scan output must remain local to
        # the tool response instead of forcing BBOT's Neo4j output module.
        if graph_api_url:
            parts = ["bbot", "--yes", "--json", "--brief", "--output-modules", "stdout"]
        else:
            uri, user, password = self._connection(
                neo4j_uri, neo4j_user, neo4j_password
            )
            config.extend(
                [
                    f"modules.neo4j.uri={uri}",
                    f"modules.neo4j.username={user}",
                    f"modules.neo4j.password={password}",
                ]
            )
            parts = ["bbot", "--yes", "--output-modules", "neo4j", "--brief"]

        parts.extend(["--targets", *targets])

        if modules:
            parts.extend(["--modules", *modules])
        if flags:
            parts.extend(["--flags", *flags])
        if presets:
            parts.extend(["--preset", *presets])
        if config:
            parts.extend(["--config", *config])
        if extra_args:
            parts.extend(extra_args)
        if graph_api_url and not _has_dependency_control_arg(extra_args):
            parts.append("--no-deps")
        if graph_api_url and not _has_module_exclusion_arg(extra_args):
            excluded = ["portscan", "gowitness"]
            if not _allows_deadly(extra_args):
                excluded.append("nuclei")
            if not _requests_baddns(modules):
                excluded.extend(["baddns", "baddns_direct", "baddns_zone"])
            parts.extend(["--exclude-modules", *excluded])

        command_str = " ".join(parts)

        # Execute the scan
        try:
            process = await asyncio.create_subprocess_exec(
                *shlex.split(command_str),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=_bbot_subprocess_env(graph_api_url),
            )

            output_chunks: list[str] = []

            async def stream() -> None:
                if not process or not process.stdout:
                    return
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    output_chunks.append(line.decode(errors="replace").strip())

            await asyncio.wait_for(stream(), timeout=scan_timeout)
            await process.wait()

            exit_code = process.returncode or 0

        except asyncio.TimeoutError:
            if process:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
            output = "\n".join(output_chunks)
            return f"Scan timed out after {scan_timeout}s. Partial output:\n{output}"

        except FileNotFoundError:
            return (
                "Error: bbot command not found. "
                "Install BBOT: pip install bbot (https://github.com/blacklanternsecurity/bbot)"
            )

        output = "\n".join(output_chunks)

        if exit_code != 0:
            if graph_api_url:
                output = _summarize_bbot_stdout(output, self.max_output_chars)
            return f"BBOT scan exited with code {exit_code}:\n{output}"

        if graph_api_url:
            note = _sandbox_suppression_note(requested_modules, graph_api_url)
            event_count = _count_bbot_json_events(output)
            summarized = _summarize_bbot_stdout(output, self.max_output_chars)
            if event_count == 0 or _bbot_output_has_blocking_diagnostic(output):
                return (
                    "Scan produced no usable BBOT JSON events.\n\n"
                    f"{note}{summarized}"
                )
            output = note + summarized
        elif len(output) > self.max_output_chars:
            output = (
                output[: self.max_output_chars]
                + f"\n\n... [TRUNCATED: {len(output)} chars total]"
            )

        return f"Scan completed successfully.\n\n{output}"

    # ── Graph Queries ─────────────────────────────────────────────────────

    @tool_method(name="query_graph", catch=True)
    async def query_graph(
        self,
        cypher: t.Annotated[str, "The Cypher query to execute"],
        params: t.Annotated[
            dict[str, t.Any] | None,
            "Optional parameters to safely inject values (prevents injection). "
            "Use $param syntax in the query.",
        ] = None,
        neo4j_uri: t.Annotated[
            str | None,
            "Task Neo4j bolt URI, for example bolt://host:7687.",
        ] = None,
        neo4j_user: t.Annotated[str | None, "Task Neo4j username."] = None,
        neo4j_password: t.Annotated[str | None, "Task Neo4j password."] = None,
        graph_api_url: t.Annotated[
            str | None,
            "Task-local Graph API URL for querying Neo4j over HTTP when raw Bolt is unavailable.",
        ] = None,
    ) -> str:
        """Execute a Cypher query against the Neo4j graph database.

        This is the primary analysis tool for exploring reconnaissance data.
        Use parameterized queries ($param) for user input to prevent injection.

        Common patterns:
            Count by type: MATCH (n) RETURN labels(n)[0] as type, count(n) as count ORDER BY count DESC
            Find domains: MATCH (n:DNS_NAME) WHERE n.name CONTAINS 'api' RETURN n.name LIMIT 20
            DNS to IP: MATCH (d:DNS_NAME)-[:RESOLVES_TO]->(ip:IP_ADDRESS) RETURN d.name, ip.address
            Critical findings: MATCH (f:FINDING) WHERE f.severity IN ['critical', 'high'] RETURN f
            Tech stack: MATCH (n:TECHNOLOGY) RETURN DISTINCT n.name, n.version
            Shared hosting: MATCH (ip:IP_ADDRESS)<-[:RESOLVES_TO]-(d) WITH ip, count(d) as cnt WHERE cnt > 1 RETURN ip.address, cnt
        """
        result = await self._query(
            cypher, params, neo4j_uri, neo4j_user, neo4j_password, graph_api_url
        )
        return json.dumps(result, indent=2, default=str)

    @tool_method(name="get_scan_metadata", catch=True)
    async def get_scans(
        self,
        scope_distance: t.Annotated[
            int, "Filter by scope distance (0 = direct targets)"
        ] = 0,
        tags: t.Annotated[list[str] | None, "Filter by scan tags"] = None,
        neo4j_uri: t.Annotated[str | None, "Task Neo4j bolt URI."] = None,
        neo4j_user: t.Annotated[str | None, "Task Neo4j username."] = None,
        neo4j_password: t.Annotated[str | None, "Task Neo4j password."] = None,
        graph_api_url: t.Annotated[str | None, "Task-local Graph API URL."] = None,
    ) -> str:
        """Retrieve metadata about completed BBOT scans.

        Returns scan IDs, targets, modules used, and timing information.
        """
        scans = await self._get_nodes(
            label="SCAN",
            filters={
                "scope_distance": scope_distance,
                **({"tags": tags} if tags else {}),
            },
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
            graph_api_url=graph_api_url,
        )
        summarized = [_summarize(scan) for scan in scans]
        return json.dumps(summarized, indent=2, default=str)

    @tool_method(name="get_findings", catch=True)
    async def get_findings(
        self,
        scope_distance: t.Annotated[
            int, "Filter by scope distance (0 = direct targets)"
        ] = 0,
        tags: t.Annotated[
            list[str] | None, "Filter by tags (e.g., ['critical', 'authentication'])"
        ] = None,
        neo4j_uri: t.Annotated[str | None, "Task Neo4j bolt URI."] = None,
        neo4j_user: t.Annotated[str | None, "Task Neo4j username."] = None,
        neo4j_password: t.Annotated[str | None, "Task Neo4j password."] = None,
        graph_api_url: t.Annotated[str | None, "Task-local Graph API URL."] = None,
    ) -> str:
        """Retrieve security findings and vulnerabilities from scans.

        Returns finding type, severity, description, affected resource,
        and evidence. Use this to quickly identify confirmed issues.
        """
        findings = await self._get_nodes(
            label="FINDING",
            filters={
                "scope_distance": scope_distance,
                **({"tags": tags} if tags else {}),
            },
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
            graph_api_url=graph_api_url,
        )
        summarized = [_summarize(finding) for finding in findings]
        return json.dumps(summarized, indent=2, default=str)

    @tool_method(name="get_db_schema", catch=True)
    async def get_schema(
        self,
        neo4j_uri: t.Annotated[str | None, "Task Neo4j bolt URI."] = None,
        neo4j_user: t.Annotated[str | None, "Task Neo4j username."] = None,
        neo4j_password: t.Annotated[str | None, "Task Neo4j password."] = None,
        graph_api_url: t.Annotated[str | None, "Task-local Graph API URL."] = None,
    ) -> str:
        """Retrieve the Neo4j database schema.

        Returns node labels, relationship types, and their properties.
        Essential for understanding the data model and constructing queries.
        """
        queries = {
            "node_labels": "CALL db.labels() YIELD label",
            "relationship_types": "CALL db.relationshipTypes() YIELD relationshipType",
            "node_properties": "CALL db.schema.nodeTypeProperties()",
            "relationship_properties": "CALL db.schema.relTypeProperties()",
        }

        results = await asyncio.gather(
            *(
                self._query(
                    q, None, neo4j_uri, neo4j_user, neo4j_password, graph_api_url
                )
                for q in queries.values()
            )
        )
        node_labels_res, rel_types_res, node_props_res, rel_props_res = results

        schema: dict[str, t.Any] = {
            "node_labels": sorted([r["label"] for r in node_labels_res]),
            "relationship_types": sorted(
                [r["relationshipType"] for r in rel_types_res]
            ),
            "node_properties": {},
            "relationship_properties": {},
        }

        for record in node_props_res:
            label = record.get("nodeType", "").lstrip(":")
            if not label:
                continue
            if label not in schema["node_properties"]:
                schema["node_properties"][label] = []
            schema["node_properties"][label].append(
                {
                    "property": record.get("propertyName"),
                    "types": record.get("propertyTypes"),
                    "mandatory": record.get("mandatory"),
                }
            )

        for record in rel_props_res:
            rel_type = record.get("relType", "").lstrip(":")
            if not rel_type:
                continue
            if rel_type not in schema["relationship_properties"]:
                schema["relationship_properties"][rel_type] = []
            schema["relationship_properties"][rel_type].append(
                {
                    "property": record.get("propertyName"),
                    "types": record.get("propertyTypes"),
                    "mandatory": record.get("mandatory"),
                }
            )

        return json.dumps(schema, indent=2, default=str)

    @tool_method(name="explore_nodes", catch=True)
    async def explore_nodes(
        self,
        label: t.Annotated[
            str | None, "Node type (e.g., 'DNS_NAME', 'URL', 'FINDING')"
        ] = None,
        property_filter: t.Annotated[
            str | None,
            "Filter: 'property=value' for exact match, 'property CONTAINS value' for substring",
        ] = None,
        limit: t.Annotated[int, "Maximum nodes to return (1-1000)"] = 100,
        neo4j_uri: t.Annotated[str | None, "Task Neo4j bolt URI."] = None,
        neo4j_user: t.Annotated[str | None, "Task Neo4j username."] = None,
        neo4j_password: t.Annotated[str | None, "Task Neo4j password."] = None,
        graph_api_url: t.Annotated[str | None, "Task-local Graph API URL."] = None,
    ) -> str:
        """Explore nodes in the graph database interactively.

        Flexible tool for discovering and examining nodes when you're not sure
        exactly what you're looking for. Use get_db_schema() first to see
        available node labels.
        """
        if limit < 1 or limit > 1000:
            raise ValueError("Limit must be between 1 and 1000.")

        query_parts = [f"MATCH (node:{label})" if label else "MATCH (node)"]
        params: dict[str, t.Any] = {}

        if property_filter:
            if "CONTAINS" in property_filter:
                parts = property_filter.split("CONTAINS", 1)
                if len(parts) == 2:
                    prop, value = parts
                    query_parts.append(f"WHERE node.{prop.strip()} CONTAINS $value")
                    params["value"] = value.strip()
            elif "=" in property_filter:
                prop, value = property_filter.split("=", 1)
                query_parts.append(f"WHERE node.{prop.strip()} = $value")
                params["value"] = value.strip()

        query_parts.append("RETURN node LIMIT $limit")

        result = await self._query(
            " ".join(query_parts),
            {"limit": limit, **params},
            neo4j_uri,
            neo4j_user,
            neo4j_password,
            graph_api_url,
        )
        return json.dumps(result, indent=2, default=str)

    @tool_method(name="explore_relationships", catch=True)
    async def explore_relationships(
        self,
        source_label: t.Annotated[
            str | None, "Source node type (e.g., 'DNS_NAME')"
        ] = None,
        relationship_type: t.Annotated[
            str | None, "Relationship type (e.g., 'RESOLVES_TO')"
        ] = None,
        target_label: t.Annotated[
            str | None, "Target node type (e.g., 'IP_ADDRESS')"
        ] = None,
        limit: t.Annotated[int, "Maximum relationships to return (1-1000)"] = 100,
        neo4j_uri: t.Annotated[str | None, "Task Neo4j bolt URI."] = None,
        neo4j_user: t.Annotated[str | None, "Task Neo4j username."] = None,
        neo4j_password: t.Annotated[str | None, "Task Neo4j password."] = None,
        graph_api_url: t.Annotated[str | None, "Task-local Graph API URL."] = None,
    ) -> str:
        """Discover how nodes are connected in the graph database.

        Use get_db_schema() to see available relationship types.
        """
        if limit < 1 or limit > 1000:
            raise ValueError("Limit must be between 1 and 1000.")

        source = f"(source:{source_label})" if source_label else "(source)"
        rel = (
            f"-[relationship:{relationship_type}]->"
            if relationship_type
            else "-[relationship]->"
        )
        target = f"(target:{target_label})" if target_label else "(target)"

        query = f"MATCH {source}{rel}{target} RETURN source, relationship, target LIMIT $limit"
        result = await self._query(
            query,
            {"limit": limit},
            neo4j_uri,
            neo4j_user,
            neo4j_password,
            graph_api_url,
        )
        return json.dumps(result, indent=2, default=str)

    @tool_method(name="get_screenshot", catch=True)
    async def get_screenshot(
        self,
        uuid: t.Annotated[str | None, "The UUID of the WEBSCREENSHOT node"] = None,
        url: t.Annotated[str | None, "The URL to find a screenshot of"] = None,
        neo4j_uri: t.Annotated[str | None, "Task Neo4j bolt URI."] = None,
        neo4j_user: t.Annotated[str | None, "Task Neo4j username."] = None,
        neo4j_password: t.Annotated[str | None, "Task Neo4j password."] = None,
        graph_api_url: t.Annotated[str | None, "Task-local Graph API URL."] = None,
    ) -> str:
        """Retrieve a screenshot from the database.

        Identify a screenshot by its UUID (from explore_nodes) or by the
        original URL that was screenshotted. Returns the file path for viewing.
        """
        if not uuid and not url:
            raise ValueError("Either 'uuid' or 'url' must be provided.")

        if url and not uuid:
            nodes = await self._query(
                "MATCH (node:WEBSCREENSHOT) WHERE node.url CONTAINS $url RETURN node LIMIT 1",
                {"url": url},
                neo4j_uri,
                neo4j_user,
                neo4j_password,
                graph_api_url,
            )
            if not nodes:
                return f"No screenshot found for URL '{url}'."
            uuid = nodes[0].get("node", {}).get("uuid")
            if not uuid:
                return f"No screenshot found for URL '{url}'."

        cypher = """
        MATCH (w:WEBSCREENSHOT {uuid: $uuid})
        MATCH (s:SCAN {id: w.scan})
        RETURN w.data AS web_data, s.data AS scan_data
        """
        result = await self._query(
            cypher,
            {"uuid": uuid},
            neo4j_uri,
            neo4j_user,
            neo4j_password,
            graph_api_url,
        )
        if not result:
            return f"No screenshot data found for UUID '{uuid}'."

        scan_data = _parse_serialized_dict(result[0].get("scan_data", ""))
        web_data = _parse_serialized_dict(result[0].get("web_data", ""))

        scan_name = str(scan_data.get("name", ""))
        relative_path = str(web_data.get("path", ""))
        original_url = str(web_data.get("url", ""))

        if not all([scan_name, relative_path]):
            return "Screenshot data is missing required fields."

        bbot_home = Path(self.bbot_data_dir).expanduser().resolve()
        full_path = bbot_home / "scans" / scan_name / relative_path

        if not full_path.exists():
            return f"Screenshot file not found at: {full_path}"

        return json.dumps(
            {
                "path": str(full_path),
                "url": original_url,
                "uuid": uuid,
            },
            indent=2,
        )
