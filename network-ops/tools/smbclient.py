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
