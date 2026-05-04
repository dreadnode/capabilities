from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger


class Nmap(Toolset):
    """
    A toolset for network scanning using the nmap utility.
    """

    variant: str | None = Config(default="all")
    """Enable only quick scans, allow service scans, or both."""
    timeout: int = Config(default=120)
    """Default timeout for commands in seconds."""

    @tool_method(catch=True, variants=["all"])
    async def nmap(self, targets: list[str], args: list[str]) -> str:
        """
        Execute an nmap scan with the specified arguments on the given targets.

        Args:
            targets: A list of IP addresses, hostnames, or CIDR ranges.
            args: A list of nmap command-line arguments (e.g., ['-sU', '-p', '161']).
        """
        cmd = ["nmap", *args, *targets]
        logger.info(f"Running nmap: {' '.join(cmd)}")
        return await execute(cmd, timeout=self.timeout)

    @tool_method(catch=True, variants=["quick", "detailed", "all"])
    async def nmap_quick_scan(self, targets: list[str]) -> str:
        """
        Performs a fast scan for the top 100 most common open TCP ports.

        This scan is optimized for speed (`-F -T4 --open -Pn`) and is ideal for initial
        reconnaissance to quickly identify potentially interesting services.

        Args:
            targets: A list of IP addresses, hostnames, or CIDR ranges.
        """
        return await self.nmap(targets, ["-F", "-T4", "--open", "-Pn"])

    @tool_method(catch=True, variants=["detailed", "all"])
    async def nmap_service_scan(self, targets: list[str], ports: str | None = None) -> str:
        """
        Performs a detailed TCP scan to identify service versions and run default scripts.

        This scan (`-sV -sC -T4 --open -Pn`) provides more context than a simple port scan.
        If no ports are specified, it scans the top 1000 most common ports.

        Args:
            targets: A list of IP addresses, hostnames, or CIDR ranges.
            ports: Optional ports to scan (X,Y or X-Y format).
        """
        args = ["-sV", "-sC", "-T4", "--open", "-Pn"]
        if ports:
            args.extend(["-p", ports])
        return await self.nmap(targets, args)
