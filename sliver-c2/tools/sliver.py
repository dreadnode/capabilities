import asyncio
import shutil
import typing as t
from pathlib import Path

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger
from sliver import SliverClient, SliverClientConfig  # type: ignore[import-untyped]

SLIVER_DEFAULT_LHOST = "localhost"
SLIVER_DEFAULT_LPORT = 31337
SLIVER_DEFAULT_OPERATOR = "operator"
SLIVER_DEFAULT_CONFIG_DIR = str(Path.home() / ".sliver-client" / "configs")


class Sliver(Toolset):
    """
    A toolset for the Sliver C2 framework. Tools are for interacting with the Sliver server
    (listing sessions/beacons, managing jobs/listeners).

    If config_file is not provided, the toolset will:
      1. Look for an existing config in ~/.sliver-client/configs/
      2. If none found, start a local sliver-server daemon and generate an operator config

    When using this toolset directly (not via an agent), you must use the toolset within an
    async context manager (async with) to initialize the Sliver client.

    Example:
        # Connect to existing server with config
        async with Sliver(config_file="/home/op/.sliver-client/configs/op.cfg") as sliver:
            sessions = await sliver.get_sessions()

        # Auto-start local server (no config needed)
        async with Sliver() as sliver:
            sessions = await sliver.get_sessions()
    """

    config_file: str | None = Config(
        default=None,
        description="path to Sliver operator config file (.cfg). If not provided, "
        "auto-discovers or starts a local server.",
    )
    server_binary: str = Config(
        default="sliver-server",
        description="path or name of the sliver-server binary",
    )
    lhost: str = Config(
        default=SLIVER_DEFAULT_LHOST,
        description="gRPC listener host for the local server",
    )
    lport: int = Config(
        default=SLIVER_DEFAULT_LPORT,
        description="gRPC listener port for the local server",
    )
    timeout: int = Config(default=60, description="timeout for Sliver gRPC requests in seconds")

    variant: str | None = Config(default="all")

    _server_process: asyncio.subprocess.Process | None = None

    async def __aenter__(self):
        config_path = await self._resolve_config()

        try:
            config = SliverClientConfig.parse_config_file(Path(config_path))
            self._client = SliverClient(config)
            await self._client.connect()
            version = await self._client.version()
            logger.info(
                f"Connected to Sliver server v{version.Major}.{version.Minor}.{version.Patch}"
            )
        except Exception as e:
            await self._stop_server()
            logger.error(f"Failed to connect to Sliver server: {e}")
            raise RuntimeError(f"Failed to connect to Sliver server: {e}") from e
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self._stop_server()
        if exc_type is not None:
            logger.error(f"{exc_type}: {exc}.\n{tb}")

    async def _resolve_config(self) -> str:
        """Resolve an operator config file: use provided path, discover existing, or start a server."""
        # 1. Explicit config provided
        if self.config_file:
            if not Path(self.config_file).is_file():  # noqa: ASYNC240
                raise FileNotFoundError(f"Sliver config file not found: {self.config_file}")
            logger.info(f"Using provided config: {self.config_file}")
            return self.config_file

        # 2. Try to discover an existing config
        discovered = self._discover_config()
        if discovered:
            logger.info(f"Discovered existing config: {discovered}")
            return discovered

        # 3. No config found — start a local server and generate one
        logger.info("No config file provided or found. Starting local Sliver server...")
        return await self._start_server_and_generate_config()

    @staticmethod
    def _discover_config() -> str | None:
        """Look for existing operator configs in the default Sliver client config directory."""
        cfg_dir = Path(SLIVER_DEFAULT_CONFIG_DIR)
        if not cfg_dir.is_dir():
            return None
        configs = sorted(cfg_dir.glob("*.cfg"), key=lambda p: p.stat().st_mtime, reverse=True)
        return str(configs[0]) if configs else None

    async def _start_server_and_generate_config(self) -> str:
        """Start sliver-server in daemon mode and generate an operator config file."""
        binary = shutil.which(self.server_binary)
        if binary is None:
            raise FileNotFoundError(
                f"'{self.server_binary}' not found on PATH. "
                "Install Sliver or set server_binary to the full path."
            )

        # Unpack assets if this is a fresh install (idempotent)
        logger.info("Ensuring Sliver assets are unpacked...")
        await execute([binary, "unpack", "--force"], timeout=120)

        # Start daemon
        logger.info(f"Starting sliver-server daemon on {self.lhost}:{self.lport}...")
        self._server_process = await asyncio.create_subprocess_exec(
            binary,
            "daemon",
            "--lhost",
            self.lhost,
            "--lport",
            str(self.lport),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Give the daemon time to initialize and open the gRPC port
        await asyncio.sleep(3)
        if self._server_process.returncode is not None:
            stderr = b""
            if self._server_process.stderr:
                stderr = await self._server_process.stderr.read()
            raise RuntimeError(
                f"sliver-server daemon exited immediately (code {self._server_process.returncode}): "
                f"{stderr.decode(errors='replace')}"
            )
        logger.info(f"sliver-server daemon started (PID {self._server_process.pid})")

        # Generate operator config
        return await self._generate_operator_config(binary)

    async def _generate_operator_config(self, binary: str) -> str:
        """Generate an operator config file using sliver-server operator command."""
        Path(SLIVER_DEFAULT_CONFIG_DIR).mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240
        config_path = str(Path(SLIVER_DEFAULT_CONFIG_DIR) / f"{SLIVER_DEFAULT_OPERATOR}.cfg")

        logger.info(f"Generating operator config: {config_path}")
        output = await execute(
            [
                binary,
                "operator",
                "--name",
                SLIVER_DEFAULT_OPERATOR,
                "--lhost",
                self.lhost,
                "--lport",
                str(self.lport),
                "--permissions",
                "all",
                "--save",
                config_path,
            ],
            timeout=30,
        )
        logger.info(f"Operator config generated: {output.strip()}")

        if not Path(config_path).is_file():  # noqa: ASYNC240
            raise RuntimeError(
                f"Operator config was not created at {config_path}. Server output: {output.strip()}"
            )
        return config_path

    async def _stop_server(self) -> None:
        """Stop the locally started sliver-server daemon, if any."""
        if self._server_process is None:
            return
        logger.info(f"Stopping sliver-server daemon (PID {self._server_process.pid})...")
        try:
            self._server_process.terminate()
            await asyncio.wait_for(self._server_process.wait(), timeout=10)
        except (ProcessLookupError, asyncio.TimeoutError):
            self._server_process.kill()
        finally:
            self._server_process = None

    @tool_method(variants=["all"])
    async def get_sessions(self) -> list[dict]:
        """
        Retrieve all active Sliver sessions (interactive real-time implant connections).

        Returns a list of session details including ID, name, remote address, hostname,
        username, OS, architecture, and transport protocol.
        """
        sessions = await self._client.sessions()
        return [
            {
                "id": s.ID,
                "name": s.Name,
                "remote_address": s.RemoteAddress,
                "hostname": s.Hostname,
                "username": s.Username,
                "os": s.OS,
                "arch": s.Arch,
                "transport": s.Transport,
                "pid": s.PID,
                "filename": s.Filename,
                "active_c2": s.ActiveC2,
            }
            for s in sessions
        ]

    @tool_method(variants=["all"])
    async def get_beacons(self) -> list[dict]:
        """
        Retrieve all active Sliver beacons (asynchronous callback implants).

        Returns a list of beacon details including ID, name, hostname, username,
        OS, architecture, transport, interval, and jitter.
        """
        beacons = await self._client.beacons()
        return [
            {
                "id": b.ID,
                "name": b.Name,
                "hostname": b.Hostname,
                "username": b.Username,
                "os": b.OS,
                "arch": b.Arch,
                "transport": b.Transport,
                "remote_address": b.RemoteAddress,
                "interval": b.Interval,
                "jitter": b.Jitter,
                "pid": b.PID,
                "filename": b.Filename,
                "active_c2": b.ActiveC2,
            }
            for b in beacons
        ]

    @tool_method(variants=["all"])
    async def get_jobs(self) -> list[dict]:
        """
        List all active jobs (listeners) on the Sliver server.

        Returns job details including ID, name, protocol, port, and description.
        """
        jobs = await self._client.jobs()
        return [
            {
                "id": j.ID,
                "name": j.Name,
                "protocol": j.Protocol,
                "port": j.Port,
                "description": j.Description,
            }
            for j in jobs
        ]

    @tool_method(variants=["all"])
    async def kill_job(
        self,
        job_id: t.Annotated[int, "The ID of the job (listener) to kill."],
    ) -> str:
        """
        Kill an active job (listener) on the Sliver server by its ID.
        """
        result = await self._client.kill_job(job_id)
        return f"Killed job {result.ID}"

    @tool_method(variants=["all"])
    async def start_mtls_listener(
        self,
        host: t.Annotated[str, "Interface to bind the listener on."] = "0.0.0.0",
        port: t.Annotated[int, "Port for the mTLS listener."] = 8888,
    ) -> str:
        """
        Start a Mutual TLS (mTLS) listener on the Sliver server.
        mTLS provides encrypted, authenticated C2 communications.
        """
        result = await self._client.start_mtls_listener(host=host, port=port)
        return f"Started mTLS listener — Job ID: {result.JobID}"

    @tool_method(variants=["all"])
    async def start_https_listener(
        self,
        host: t.Annotated[str, "Interface to bind the listener on."] = "0.0.0.0",
        port: t.Annotated[int, "Port for the HTTPS listener."] = 443,
        domain: t.Annotated[str, "Domain for the HTTPS listener."] = "",
    ) -> str:
        """
        Start an HTTPS listener on the Sliver server.
        HTTPS listeners blend C2 traffic with normal web traffic.
        """
        result = await self._client.start_https_listener(host=host, port=port, domain=domain)
        return f"Started HTTPS listener — Job ID: {result.JobID}"

    @tool_method(variants=["all"])
    async def start_http_listener(
        self,
        host: t.Annotated[str, "Interface to bind the listener on."] = "0.0.0.0",
        port: t.Annotated[int, "Port for the HTTP listener."] = 80,
        domain: t.Annotated[str, "Domain for the HTTP listener."] = "",
    ) -> str:
        """
        Start an HTTP listener on the Sliver server.
        HTTP provides unencrypted C2 — use HTTPS or mTLS when possible.
        """
        result = await self._client.start_http_listener(host=host, port=port, domain=domain)
        return f"Started HTTP listener — Job ID: {result.JobID}"

    @tool_method(variants=["all"])
    async def start_dns_listener(
        self,
        domains: t.Annotated[list[str], "DNS domains for the listener (e.g. ['c2.example.com'])."],
        host: t.Annotated[str, "Interface to bind the listener on."] = "0.0.0.0",
        port: t.Annotated[int, "Port for the DNS listener."] = 53,
    ) -> str:
        """
        Start a DNS listener on the Sliver server.
        DNS C2 is slow but highly evasive, tunneling data through DNS queries.
        """
        result = await self._client.start_dns_listener(domains=domains, host=host, port=port)
        return f"Started DNS listener — Job ID: {result.JobID}"

    @tool_method(variants=["all"])
    async def kill_session(
        self,
        session_id: t.Annotated[str, "The ID of the session to terminate."],
        *,
        force: t.Annotated[bool, "Force kill the session without graceful shutdown."] = False,
    ) -> str:
        """
        Terminate a Sliver session. The implant process will exit on the target host.
        """
        await self._client.kill_session(session_id, force=force)
        return f"Session {session_id} terminated."

    @tool_method(variants=["all"])
    async def kill_beacon(
        self,
        beacon_id: t.Annotated[str, "The ID of the beacon to terminate."],
    ) -> str:
        """
        Terminate a Sliver beacon. The implant process will exit on the target host.
        """
        await self._client.kill_beacon(beacon_id)
        return f"Beacon {beacon_id} terminated."

    @tool_method(variants=["all"])
    async def get_implant_builds(self) -> list[dict]:
        """
        List all previously generated implant builds stored on the Sliver server.

        Returns implant build names and their configuration details.
        """
        builds = await self._client.implant_builds()
        return [
            {
                "name": name,
                "os": config.GOOS,
                "arch": config.GOARCH,
                "format": str(config.Format),
                "c2": [c2.URL for c2 in config.C2],
                "is_beacon": config.IsBeacon,
            }
            for name, config in builds.items()
        ]

    @tool_method(variants=["all"])
    async def regenerate_implant(
        self,
        implant_name: t.Annotated[str, "Name of a previously generated implant to regenerate."],
    ) -> str:
        """
        Regenerate a previously compiled implant by name. Returns the implant binary
        which can then be deployed to a target.
        """
        result = await self._client.regenerate_implant(implant_name, timeout=360)
        size_kb = len(result.File.Data) / 1024
        return f"Regenerated implant '{implant_name}' ({size_kb:.1f} KB)"
