import typing as t

from dreadnode import Config
from dreadnode.agents.tools import Toolset, fs, tool_method
from loguru import logger
from mythic import mythic as mythic_scripting


class Mythic(Toolset):
    """
    A toolset for the Mythic C2 framework. Tools are specifically for interacting with the Mythic server.

    When using this toolset directly (not via an agent), you must use the toolset within an async context manager (async with) to initialize the Mythic client.

    Example:
        async with Mythic(username="admin", password="secret", server_ip="10.0.0.1") as mythic:
            callbacks = await mythic.get_active_callbacks()
    """

    username: str = Config(default="mythic_admin", description="username for Mythic C2 server")
    password: str = Config(description="password for Mythic C2 server")
    server_ip: str = Config(default="127.0.0.1", description="IP of Mythic C2 server")
    server_port: int = Config(default=443, description="port of Mythic C2 server")
    timeout: int = Config(default=-1, description="timeout for Mythic C2 server requests")

    variant: str | None = Config(default="all")

    async def __aenter__(self):
        """context manager for Mythic Toolset. Primarily initializes Mythic client for Mythic tool."""
        try:
            self._client = await mythic_scripting.login(
                username=self.username,
                password=self.password,
                server_ip=self.server_ip,
                server_port=self.server_port,
                timeout=self.timeout,
            )

        except Exception as e:
            logger.error(f"Failed to login to Mythic: {e}")
            raise RuntimeError(f"Failed to login to Mythic: {e}") from e

        self._local_fs = fs.Filesystem(path="/")
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """ """
        if exc_type is not None:
            logger.error(f"{exc_type}: {exc}.\n{tb}")

    @tool_method(variants=["all"])
    async def get_active_callbacks(self) -> list[dict]:
        """
        Retrieve all active Mythic callbacks from deployed implants.

        This method queries the Mythic server for active callbacks (established connections
        from implants) and returns them sorted by most recent check-in timestamp. This is
        useful for identifying which implants are currently active and when they last communicated
        with the server.

        Returns:
            A list of dictionaries containing callback information, including display_id, host,
            user, domain, integrity_level, IP address, process details, payload information,
            and last check-in timestamp. Results are ordered by most recent check-in first.
        """
        cbs = await mythic_scripting.get_all_active_callbacks(
            self._client,
            "display_id,id,host,user,domain,integrity_level,ip,process_name,pid,payload{os,payloadtype{name},description},last_checkin",
        )
        return sorted(cbs, key=lambda x: x["last_checkin"], reverse=True)

    @tool_method(variants=["all"])
    async def upload_file_to_server(
        self,
        filepath: t.Annotated[str, "local filepath to upload to the Mythic server"],
        *,
        reupload: t.Annotated[bool, "re-upload if file already exists on the Mythic server"] = True,
    ) -> dict | str:
        """
        Upload a local file to the Mythic server for use with callbacks.

        This method registers a file with the Mythic server, making it available for
        download by implants or for use in post-exploitation tasks. The file is read
        from the local filesystem and transferred to the Mythic server.

        Args:
            filename: The path to the local file to upload to the Mythic server.
            reupload: Whether to re-upload the file if it already exists on the Mythic
                server. If False and the file exists, the existing file's information
                is returned instead. Defaults to True.

        Returns:
            A dictionary containing the filename and file_id of the uploaded file on
            the Mythic server. The file_id can be used to reference this file in
            subsequent operations.
        """
        filename = filepath.split("/")[-1]

        if not reupload:
            file_record = await self.check_file_exists_on_server(filename=filename)
            if file_record is not None:
                logger.info(
                    f"'{filename}' found on Mythic server. Not re-uploading.\n\n{file_record}"
                )
                return {"filename": filename, "file_id": file_record["agent_file_id"]}

        file_contents = await self._local_fs.read_file(path=filepath)

        if not isinstance(file_contents, str):
            err_msg = f"Cannot upload non-text file to Mythic: {filename}"
            logger.error(err_msg)
            return err_msg

        try:
            file_bytes = file_contents.encode("utf-8")
        except UnicodeEncodeError:
            err_msg = f"Couldnt encode file for upload to Mythic: {filename}"
            logger.error(err_msg)
            return err_msg

        file_id = await mythic_scripting.register_file(
            mythic=self._client, filename=filename, contents=file_bytes
        )

        return {"filename": filename, "file_id": file_id}

    @tool_method(variants=["all"])
    async def check_file_exists_on_server(
        self, filename: t.Annotated[str, "filename to check if exists on Mythic server"]
    ) -> dict | None:
        """
        Check if a file exists on the Mythic server.

        This method searches through all uploaded files on the Mythic server to determine
        if a file with the specified name exists and is not marked as deleted. This is
        useful for verifying file availability before operations or avoiding duplicate uploads.

        Args:
            filename: The name of the file to check for on the Mythic server.

        Returns:
            A dictionary containing the file record with details such as agent_file_id,
            filename_utf8, timestamp, SHA1, MD5, and other metadata if the file exists.
            Returns None if the file is not found or has been deleted.
        """
        custom_return_attributes = "agent_file_id,filename_utf8,timestamp,deleted,is_download_from_agent,sha1,md5,is_payload,complete"
        file_record = None
        async for batch in mythic_scripting.get_all_uploaded_files(
            mythic=self._client,
            custom_return_attributes=custom_return_attributes,
            batch_size=50,
        ):
            for file_record_ in batch:
                if file_record_["filename_utf8"] == filename and not file_record_["deleted"]:
                    file_record = file_record_
                    break
        return file_record

    @tool_method(variants=["all"])
    async def download_file_from_server(
        self,
        filename: t.Annotated[str, "name of the file to download from the Mythic server"],
    ) -> bytes | None:
        """
        Download a file from the Mythic server's downloaded files by filename.

        This method searches for a file by name among all downloaded files on the Mythic
        server and retrieves its contents. This is useful for obtaining files that have
        been exfiltrated from target systems via implant callbacks.

        Args:
            filename: The name of the file to download from the Mythic server.

        Returns:
            The file contents as bytes if the file is found, or None if the file
            does not exist on the server.
        """
        file_uuid = None
        async for item in mythic_scripting.get_all_downloaded_files(
            mythic=self._client,
            custom_return_attributes="agent_file_id,filename_utf8,is_download_from_agent",
            batch_size=50,
        ):
            logger.debug(item)
            for file_ in item:
                logger.debug(file_)
                if file_["filename_utf8"] == filename:
                    file_uuid = file_["agent_file_id"]
                    break
            break

        if file_uuid is None:
            return file_uuid

        return await mythic_scripting.download_file(mythic=self._client, file_uuid=file_uuid)
