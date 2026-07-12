import asyncio
import contextlib
import os
import shutil
import tempfile

from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger


def _require_smbclient() -> str:
    """Return the smbclient binary path, raising a clear error if missing."""
    path = shutil.which("smbclient")
    if path is None:
        raise FileNotFoundError(
            "smbclient is not installed or not on PATH. "
            "Install via: apt install smbclient"
        )
    return path


_SMBCLIENT_UNSAFE_CHARS = set(';!"\n\r')


def _sanitize_smb_path(path: str) -> str:
    """Quote a path for smbclient ``-c`` commands, rejecting unsafe characters.

    smbclient's command language treats ``;`` as a command separator and
    ``!`` as a shell escape.  These cannot be safely quoted, so we reject
    them outright.
    """
    bad = _SMBCLIENT_UNSAFE_CHARS & set(path)
    if bad:
        raise ValueError(
            f"SMB path contains unsafe characters {bad!r}: {path!r}"
        )
    return f'"{path}"'


class SmbClient(Toolset):
    """
    Toolset for interacting with SMB shares using smbclient.
    """

    @tool_method(catch=True)
    async def smb_list_files(
        self,
        target: str,
        share_name: str,
        username: str,
        password: str,
        path: str = "\\",
    ) -> str:
        """
        Recursively lists files and directories in an SMB share using smbclient.

        Args:
            target: The target IP address or hostname.
            share_name: The name of the SMB share (e.g., 'SYSVOL', 'C$').
            username: The username for authentication.
            password: The password for authentication.
            path: The subdirectory within the share to start listing from (default is root '\\').

        Returns:
            The text output of the recursive file listing.
        """
        share_path = f"//{target}/{share_name}"
        smb_command = f"recurse ON; ls {_sanitize_smb_path(path)}"

        logger.info(f"Recursively listing files in {share_path}\\{path}")

        # smbclient returns non-zero when any subdirectory is inaccessible
        # during recursive listing, even when most of the tree enumerates
        # successfully. We capture stdout regardless of exit code to preserve
        # partial output.
        timeout = 120
        proc = await asyncio.create_subprocess_exec(
            _require_smbclient(),
            share_path,
            "-U",
            f"{username}%{password}",
            "-c",
            smb_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(
                f"smbclient timed out after {timeout}s listing {share_path}\\{path}"
            )
        output = stdout.decode(errors="replace")
        errors = stderr.decode(errors="replace")

        if proc.returncode != 0 and output.strip():
            if errors.strip():
                logger.warning(
                    f"smbclient exited {proc.returncode} with partial output. Errors: {errors.strip()}"
                )
            warning = "\n\n[smbclient exited non-zero — listing may be incomplete]"
            if errors.strip():
                warning += f"\n{errors}"
            return f"{output}{warning}"

        if proc.returncode != 0:
            raise RuntimeError(
                f"Command failed ({proc.returncode}):\n{errors or output}"
            )

        return output

    @tool_method(catch=True)
    async def smb_download_file(
        self,
        target: str,
        share_name: str,
        remote_path: str,
        username: str,
        password: str,
    ) -> str:
        """
        Downloads and returns the content of a single file from an SMB share.

        Args:
            target: The target IP address or hostname.
            share_name: The name of the SMB share.
            remote_path: The full path to the file within the share (e.g., 'scripts\\login.ps1').
            username: The username for authentication.
            password: The password for authentication.

        Returns:
            The content of the downloaded file as a string.
        """
        share_path = f"//{target}/{share_name}"
        smb_command = f"get {_sanitize_smb_path(remote_path)} /dev/stdout"

        logger.info(f"Downloading file {remote_path} from {share_path}")
        return await execute(
            [
                _require_smbclient(),
                share_path,
                "-U",
                f"{username}%{password}",
                "-c",
                smb_command,
            ]
        )

    @tool_method(catch=True)
    async def smb_upload_file(
        self,
        target: str,
        share_name: str,
        remote_path: str,
        content: str,
        username: str,
        password: str,
    ) -> str:
        """
        Upload a file to an SMB share.

        Writes ``content`` to a temporary local file, then uploads it to the
        specified path on the remote share via smbclient ``put``.

        Args:
            target: The target IP address or hostname.
            share_name: The name of the SMB share (e.g., 'C$', 'SYSVOL').
            remote_path: Destination path within the share (e.g., 'temp\\payload.txt').
            content: The file content to upload.
            username: The username for authentication.
            password: The password for authentication.

        Returns:
            The smbclient output confirming the upload.
        """
        share_path = f"//{target}/{share_name}"

        local_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False) as tmp:
                tmp.write(content)
                local_path = tmp.name

            smb_command = f"put {_sanitize_smb_path(local_path)} {_sanitize_smb_path(remote_path)}"
            logger.info(f"Uploading to {share_path}\\{remote_path}")

            return await execute(
                [
                    _require_smbclient(),
                    share_path,
                    "-U",
                    f"{username}%{password}",
                    "-c",
                    smb_command,
                ]
            )
        finally:
            if local_path is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(local_path)
