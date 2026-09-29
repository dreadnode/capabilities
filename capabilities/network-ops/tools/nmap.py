import hashlib
import ipaddress
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import dreadnode as dn
from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger

CAPABILITY_VERSION = "3.0.0"
ADAPTER_INPUT_VERSION = "nmap-xml@1"
SOURCE_CONTRACT_VERSION = 1
_ENDPOINT_STATES = {"closed", "filtered", "open", "open|filtered", "unreachable"}


def _normalize_ip(value: str) -> str:
    if "%" in value:
        raise ValueError(f"Scoped IP addresses are not supported: {value!r}")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc


def normalize_target(value: str) -> dict[str, str]:
    """Return one canonical target identity while retaining its exact input."""
    if not value or value != value.strip():
        raise ValueError("Targets must be non-empty and may not contain outer whitespace")

    if "/" in value:
        try:
            normalized = ipaddress.ip_network(value, strict=False).with_prefixlen
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR target: {value!r}") from exc
        return {"kind": "cidr", "original": value, "normalized": normalized}

    try:
        normalized_ip = _normalize_ip(value)
    except ValueError:
        pass
    else:
        return {
            "kind": "ip_address",
            "original": value,
            "normalized": normalized_ip,
        }

    hostname = value[:-1] if value.endswith(".") else value
    try:
        normalized_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"Invalid hostname target: {value!r}") from exc
    if len(normalized_hostname) > 253:
        raise ValueError(f"Hostname target is too long: {value!r}")
    labels = normalized_hostname.split(".")
    if len(labels) < 2:
        raise ValueError(f"Single-label hostnames are not supported: {value!r}")
    if all(label.isdigit() for label in labels):
        raise ValueError(f"Invalid IP address target: {value!r}")
    if any(
        not label or len(label) > 63 or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise ValueError(f"Invalid hostname target: {value!r}")
    return {
        "kind": "hostname",
        "original": value,
        "normalized": normalized_hostname,
    }


def _normalize_targets(values: list[str]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        target = normalize_target(value)
        key = (target["kind"], target["normalized"])
        if key not in seen:
            normalized.append(target)
            seen.add(key)
    if not normalized:
        raise ValueError("At least one target is required")
    return normalized


def _iso_timestamp(value: str) -> str:
    try:
        timestamp = float(value)
    except ValueError as exc:
        raise ValueError(f"Invalid Nmap timestamp: {value!r}") from exc
    return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")


def _parse_port_ranges(value: str) -> list[dict[str, int]]:
    ranges: list[dict[str, int]] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
        else:
            start_text = end_text = part
        try:
            start, end = int(start_text), int(end_text)
        except ValueError as exc:
            raise ValueError(f"Unsupported Nmap port coverage: {part!r}") from exc
        if not (1 <= start <= end <= 65535):
            raise ValueError(f"Invalid Nmap port coverage: {part!r}")
        port_range = {"start": start, "end": end}
        if port_range not in ranges:
            ranges.append(port_range)
    return sorted(ranges, key=lambda item: (item["start"], item["end"]))


def _ip_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


def parse_nmap_xml(xml: bytes, evidence_locator: str) -> dict[str, Any]:
    """Parse deterministic claims from exact Nmap XML without inferring omissions."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed Nmap XML: {exc}") from exc
    if root.tag != "nmaprun" or root.get("scanner") != "nmap":
        raise ValueError("Unsupported scanner XML: expected an Nmap nmaprun document")

    scanner_version = root.get("version")
    xml_version = root.get("xmloutputversion")
    if not scanner_version or not xml_version:
        raise ValueError("Nmap XML is missing scanner or XML format version provenance")

    transports: set[str] = set()
    ports: list[dict[str, int]] = []
    for scaninfo in root.findall("scaninfo"):
        transport = scaninfo.get("protocol")
        if transport not in {"tcp", "udp"}:
            raise ValueError(f"Unsupported Nmap transport: {transport!r}")
        transports.add(transport)
        services = scaninfo.get("services")
        if services:
            for port_range in _parse_port_ranges(services):
                if port_range not in ports:
                    ports.append(port_range)
    if not transports:
        raise ValueError("Nmap XML does not declare TCP or UDP scan coverage")

    ip_addresses: set[str] = set()
    dns_results: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    seen_dns: set[tuple[Any, ...]] = set()
    seen_endpoints: set[tuple[Any, ...]] = set()
    seen_fingerprints: set[tuple[Any, ...]] = set()

    root_started_at = _iso_timestamp(root.get("start", ""))
    host_end_times: list[str] = []
    for host in root.findall("host"):
        host_ips: list[str] = []
        for address in host.findall("address"):
            if address.get("addrtype") not in {"ipv4", "ipv6"}:
                continue
            ip = _normalize_ip(address.get("addr", ""))
            if ip not in host_ips:
                host_ips.append(ip)
                ip_addresses.add(ip)

        host_observed_at = _iso_timestamp(host.get("endtime", "")) if host.get("endtime") else root_started_at
        host_end_times.append(host_observed_at)
        hostnames: list[str] = []
        for hostname_element in host.findall("./hostnames/hostname"):
            name = hostname_element.get("name", "")
            try:
                normalized_name = normalize_target(name)["normalized"]
            except ValueError:
                continue
            if normalized_name not in hostnames:
                hostnames.append(normalized_name)

        for hostname in hostnames:
            for version, query_type in ((4, "A"), (6, "AAAA")):
                returned = sorted(
                    (value for value in host_ips if ipaddress.ip_address(value).version == version),
                    key=_ip_sort_key,
                )
                if not returned:
                    continue
                key = (hostname, query_type, tuple(returned), host_observed_at)
                if key in seen_dns:
                    continue
                dns_results.append(
                    {
                        "query_name": hostname,
                        "query_type": query_type,
                        "returned_ip_addresses": returned,
                        "resolver": "nmap",
                        "response_status": "reported",
                        "observed_at": host_observed_at,
                    }
                )
                seen_dns.add(key)

        for port_element in host.findall("./ports/port"):
            transport = port_element.get("protocol")
            if transport not in {"tcp", "udp"}:
                raise ValueError(f"Unsupported Nmap endpoint transport: {transport!r}")
            try:
                port = int(port_element.get("portid", ""))
            except ValueError as exc:
                raise ValueError("Nmap XML contains an invalid endpoint port") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"Nmap XML contains an invalid endpoint port: {port}")
            state_element = port_element.find("state")
            if state_element is None:
                continue
            state = state_element.get("state")
            if state not in _ENDPOINT_STATES:
                raise ValueError(f"Unsupported Nmap endpoint state: {state!r}")

            for ip in host_ips:
                endpoint_key = (ip, transport, port, state)
                if endpoint_key not in seen_endpoints:
                    endpoints.append(
                        {
                            "ip_address": ip,
                            "transport": transport,
                            "port": port,
                            "state": state,
                        }
                    )
                    seen_endpoints.add(endpoint_key)

                service = port_element.find("service")
                if service is None or not service.get("name"):
                    continue
                protocol = service.get("name", "")
                if service.get("tunnel"):
                    protocol = f"{service.get('tunnel')}/{protocol}"
                fingerprint: dict[str, Any] = {
                    "endpoint": {
                        "ip_address": ip,
                        "transport": transport,
                        "port": port,
                    },
                    "application_protocol": protocol,
                    "method": f"nmap-{service.get('method') or 'service-detection'}",
                    "evidence_locator": evidence_locator,
                }
                for field in ("product", "version"):
                    if service.get(field):
                        fingerprint[field] = service.get(field)
                summary = " ".join(
                    value
                    for value in (
                        service.get("name"),
                        service.get("product"),
                        service.get("version"),
                        service.get("extrainfo"),
                    )
                    if value
                )
                if summary:
                    fingerprint["summary"] = summary
                fingerprint_key = (
                    ip,
                    transport,
                    port,
                    protocol,
                    fingerprint.get("product"),
                    fingerprint.get("version"),
                    fingerprint["method"],
                )
                if fingerprint_key not in seen_fingerprints:
                    fingerprints.append(fingerprint)
                    seen_fingerprints.add(fingerprint_key)

    finished = root.find("./runstats/finished")
    finished_at = _iso_timestamp(finished.get("time", "")) if finished is not None else None
    exit_state = finished.get("exit") if finished is not None else None
    has_results = bool(ip_addresses or dns_results or endpoints or fingerprints)
    if exit_state == "success":
        completion_state = "completed"
        completion_reason = None
    elif has_results:
        completion_state = "partial"
        completion_reason = finished.get("summary") if finished is not None else "Nmap output ended early"
    else:
        completion_state = "failed"
        completion_reason = finished.get("summary") if finished is not None else "Nmap produced no results"

    return {
        "scanner_version": scanner_version,
        "xml_version": xml_version,
        "transports": sorted(transports),
        "ports": sorted(ports, key=lambda item: (item["start"], item["end"])),
        "started_at": root_started_at,
        "ended_at": finished_at or max(host_end_times, default=root_started_at),
        "completion_state": completion_state,
        "completion_reason": completion_reason,
        "dns_results": sorted(
            dns_results,
            key=lambda item: (
                item["query_name"],
                item["query_type"],
                tuple(item["returned_ip_addresses"]),
            ),
        ),
        "ip_addresses": sorted(ip_addresses, key=_ip_sort_key),
        "endpoints": sorted(
            endpoints,
            key=lambda item: (
                _ip_sort_key(item["ip_address"]),
                item["transport"],
                item["port"],
                item["state"],
            ),
        ),
        "service_fingerprints": sorted(
            fingerprints,
            key=lambda item: (
                _ip_sort_key(item["endpoint"]["ip_address"]),
                item["endpoint"]["transport"],
                item["endpoint"]["port"],
                item["application_protocol"],
            ),
        ),
    }


def _exclusions(args: list[str]) -> list[dict[str, str]]:
    values: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"--excludefile", "--exclude-file"} or arg.startswith(("--excludefile=", "--exclude-file=")):
            raise ValueError("Nmap exclusion files are not supported")
        if arg == "--exclude":
            index += 1
            if index >= len(args):
                raise ValueError("--exclude requires a target")
            values.extend(args[index].split(","))
        elif arg.startswith("--exclude="):
            values.extend(arg.split("=", 1)[1].split(","))
        index += 1
    return _normalize_targets(values) if values else []


def _operation_reference() -> dict[str, str]:
    from dreadnode.tracing.span import current_session_id, current_task_span

    group_id = os.environ.get("DREADNODE_SESSION_GROUP_ID", "").strip()
    operation_id = group_id or current_session_id.get()
    span = current_task_span.get()
    project_id = span.project_id if span is not None else None
    try:
        UUID(str(operation_id))
        UUID(str(project_id))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "Structured Nmap reconnaissance requires a platform-connected session with operation and project UUIDs"
        ) from exc
    return {
        "kind": "session_group" if group_id else "session",
        "id": str(operation_id),
        "project_id": str(project_id),
    }


def build_nmap_result(
    xml: bytes,
    *,
    targets: list[str],
    exclusions: list[dict[str, str]],
    scanner_profile: str,
    operation: dict[str, str],
    evidence_locator: str,
    content_hash: str,
    execution_failed: bool = False,
) -> dict[str, Any]:
    """Build report_item arguments for one registry-backed recon source record."""
    parsed = parse_nmap_xml(xml, evidence_locator)
    scanner_version = parsed.pop("scanner_version")
    xml_version = parsed.pop("xml_version")
    completion_state = parsed.pop("completion_state")
    completion_reason = parsed.pop("completion_reason")
    if execution_failed and completion_state == "completed":
        completion_state = "partial" if parsed["ip_addresses"] else "failed"
        completion_reason = "Nmap exited unsuccessfully after writing XML output"

    result: dict[str, Any] = {
        "item_type": "network_recon_result",
        "operation": operation,
        "capability": {
            "kind": "capability",
            "name": "network-ops",
            "version": os.environ.get("DREADNODE_CAPABILITY_VERSION", CAPABILITY_VERSION),
        },
        "scanner": {
            "kind": "scanner",
            "name": "nmap",
            "version": scanner_version,
        },
        "adapter_input_version": ADAPTER_INPUT_VERSION,
        "source_contract_version": SOURCE_CONTRACT_VERSION,
        "targets": _normalize_targets(targets),
        "known_address_scope": list(parsed["ip_addresses"]),
        "transports": parsed.pop("transports"),
        "ports": parsed.pop("ports"),
        "exclusions": exclusions,
        "scanner_profile": {"name": scanner_profile, "version": "1"},
        **parsed,
        "completion_state": completion_state,
        "evidence_candidates": [
            {
                "source_kind": "scan_output",
                "locator": evidence_locator,
                "content_hash": content_hash,
                "source_version": f"nmap-xml@{xml_version}",
                "media_type": "application/xml",
            }
        ],
    }
    if completion_reason:
        result["completion_reason"] = completion_reason
    return result


class Nmap(Toolset):
    """
    A toolset for network scanning using the nmap utility.
    """

    variant: str | None = Config(default="all")
    """Enable only quick scans, allow service scans, or both."""
    timeout: int = Config(default=120)
    """Default timeout for commands in seconds."""

    @tool_method(catch=True, variants=["all"])
    async def nmap(self, targets: list[str], args: list[str]) -> dict[str, Any]:
        """
        Execute one Nmap scan and return validated arguments for `report_item`.

        Pass the returned fields unchanged to the injected `report_item` tool once.

        Args:
            targets: A list of IP addresses, hostnames, or CIDR ranges.
            args: A list of nmap command-line arguments (e.g., ['-sU', '-p', '161']).
        """
        return await self._scan(targets, args, scanner_profile="custom-nmap")

    async def _scan(self, targets: list[str], args: list[str], *, scanner_profile: str) -> dict[str, Any]:
        _normalize_targets(targets)
        exclusions = _exclusions(args)
        if any(
            arg in {"-oA", "-oG", "-oN", "-oS", "-oX"} or arg.startswith(("-oA", "-oG", "-oN", "-oS", "-oX"))
            for arg in args
        ):
            raise ValueError("Nmap output options are managed by network-ops")

        operation = _operation_reference()
        with tempfile.TemporaryDirectory(prefix="network-ops-nmap-") as temp_dir:
            xml_path = Path(temp_dir) / "scan.xml"
            cmd = ["nmap", *args, "-oX", str(xml_path), *targets]
            logger.info("Running nmap: {}", " ".join(cmd))
            execution_failed = False
            try:
                await execute(cmd, timeout=self.timeout)
            except (RuntimeError, TimeoutError):
                execution_failed = True
            xml = xml_path.read_bytes() if xml_path.exists() else b""
            if not xml:
                raise RuntimeError("Nmap did not produce XML output")
            content_hash = hashlib.sha256(xml).hexdigest()
            artifact_name = f"nmap-{content_hash}.xml"
            dn.log_artifact(xml_path, name=artifact_name)
            return build_nmap_result(
                xml,
                targets=targets,
                exclusions=exclusions,
                scanner_profile=scanner_profile,
                operation=operation,
                evidence_locator=f"artifact://{artifact_name}",
                content_hash=content_hash,
                execution_failed=execution_failed,
            )

    @tool_method(catch=True, variants=["quick", "detailed", "all"])
    async def nmap_quick_scan(self, targets: list[str]) -> dict[str, Any]:
        """
        Performs a fast scan for the top 100 most common open TCP ports.

        This scan is optimized for speed (`-F -T4 --open -Pn`) and is ideal for initial
        reconnaissance to quickly identify potentially interesting services.

        Args:
            targets: A list of IP addresses, hostnames, or CIDR ranges.
        """
        return await self._scan(
            targets,
            ["-F", "-T4", "--open", "-Pn"],
            scanner_profile="quick-tcp",
        )

    @tool_method(catch=True, variants=["detailed", "all"])
    async def nmap_service_scan(self, targets: list[str], ports: str | None = None) -> dict[str, Any]:
        """
        Performs a detailed TCP scan to identify service versions and run default scripts.

        This scan (`-sV -sC -T4 --open -Pn`) provides more context than a simple port scan.
        If no ports are specified, it scans the top 1000 most common ports.

        Args:
            targets: A list of IP addresses, hostnames, or CIDR ranges.
            ports: Optional ports to scan (X,Y or X-Y format).
        """
        args = ["-sV", "-sC", "-T4", "--open", "-Pn"]
        cleaned_ports = ports.strip().strip("\"'") if ports else ""
        if cleaned_ports:
            args.extend(["-p", cleaned_ports])
        return await self._scan(targets, args, scanner_profile="service-detection")
