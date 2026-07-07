import asyncio

from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger


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
        smb_command = f"recurse ON; ls {path}"

        logger.info(f"Recursively listing files in {share_path}\\{path}")

        # smbclient returns non-zero when any subdirectory is inaccessible
        # during recursive listing, even when most of the tree enumerates
        # successfully. We capture stdout regardless of exit code to preserve
        # partial output.
        timeout = 120
        proc = await asyncio.create_subprocess_exec(
            "smbclient",
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
            return (
                f"{output}\n\n[smbclient warnings — some paths may be inaccessible]\n{errors}"
                if errors.strip()
                else output
            )

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
        smb_command = f"get {remote_path} /dev/stdout"

        logger.info(f"Downloading file {remote_path} from {share_path}")
        return await execute(
            [
                "smbclient",
                share_path,
                "-U",
                f"{username}%{password}",
                "-c",
                smb_command,
            ]
        )
