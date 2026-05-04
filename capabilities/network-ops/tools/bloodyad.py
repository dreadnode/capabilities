import shutil
import types
from typing import override

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger

# BloodyAD is typically installed via pip and available as 'bloodyAD' command
g_default_bloodyad_cmd = "bloodyAD"


class BloodyAD(Toolset):
    """
    Toolset for Active Directory privilege escalation and manipulation using bloodyAD.

    BloodyAD is a Python-based Active Directory privilege escalation framework that performs
    LDAP operations on domain controllers. It supports multiple authentication methods including
    cleartext passwords, pass-the-hash, pass-the-ticket, and certificates.

    Repository: https://github.com/CravateRouge/bloodyAD
    Install: pip install bloodyAD
    """

    timeout: int = Config(default=60)
    """Default timeout for commands in seconds."""
    bloodyad_cmd: str = Config(default=g_default_bloodyad_cmd)
    """Command to execute bloodyAD (default: bloodyAD)."""

    @override
    async def __aenter__(self):
        """Initialize BloodyAD toolset and verify bloodyAD is installed."""
        # Check if bloodyAD command is available
        if not shutil.which(self.bloodyad_cmd):
            logger.warning(
                f"bloodyAD command '{self.bloodyad_cmd}' not found in PATH. Install it with: pip install bloodyAD"
            )
        return self

    @override
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ):
        """Clean up BloodyAD toolset resources."""
        return

    def _build_connection_options(
        self,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
    ) -> list[str]:
        """
        Build connection option arguments for bloodyAD commands.

        Args:
            domain: Domain name.
            username: Username for authentication.
            host: Domain controller hostname or IP.
            password: Password for authentication.
            hashes: NTLM hashes for pass-the-hash.
            use_kerberos: Use Kerberos authentication.
            dc_ip: Optional DC IP to override DNS.

        Returns:
            List of connection option arguments.
        """
        cmd = ["-u", username, "-d", domain, "-H", host]

        if password:
            cmd.extend(["-p", password])
        elif hashes:
            cmd.extend(["--hashes", hashes])

        if use_kerberos:
            cmd.append("-k")

        if dc_ip:
            cmd.extend(["--dc-ip", dc_ip])

        return cmd

    @tool_method(catch=True)
    async def bloodyad_get_object(
        self,
        object_name: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        attributes: list[str] | None = None,
        resolve: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Get specific AD object attributes using bloodyAD.

        <documentation>
        Retrieve attributes of a specific Active Directory object.
        </documentation>

        Args:
            object_name: The AD object to query (DN, sAMAccountName, or other identifier).
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            attributes: List of specific attributes to retrieve (e.g., ['memberOf', 'mail']).
            resolve: Resolve DNs in attributes to human-readable names.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["get", "object", object_name])

        if attributes:
            for attr in attributes:
                cmd.extend(["--attr", attr])

        if resolve:
            cmd.append("--resolve")

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_get_children(
        self,
        target_dn: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        object_type: str | None = None,
        attributes: list[str] | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Get child objects from an AD container using bloodyAD.

        <documentation>
        Retrieve child objects from a specified AD container or organizational unit.
        </documentation>

        Args:
            target_dn: The target DN or container to query (e.g., 'DC=domain,DC=local').
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            object_type: Filter by object type (e.g., 'user', 'computer', 'group').
            attributes: List of specific attributes to retrieve.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["get", "children", target_dn])

        if object_type:
            cmd.extend(["--type", object_type])

        if attributes:
            for attr in attributes:
                cmd.extend(["--attr", attr])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_get_membership(
        self,
        object_name: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        no_recurse: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Get group membership information using bloodyAD.

        <documentation>
        Retrieve group membership information for a user or group.
        </documentation>

        Args:
            object_name: The user or group to query for memberships.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            no_recurse: Don't recurse into nested groups.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["get", "membership", object_name])

        if no_recurse:
            cmd.append("--no-recurse")

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_get_writable(
        self,
        target_username: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Find objects writable by a specific user using bloodyAD.

        <documentation>
        Find all objects that a user has write access to.
        </documentation>

        Args:
            target_username: The user to check for write access.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["get", "writable", target_username])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_get_dnsdump(
        self,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Dump DNS records from Active Directory using bloodyAD.

        <documentation>
        Retrieve DNS records stored in Active Directory.
        </documentation>

        Args:
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["get", "dnsDump"])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_get_trusts(
        self,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Get domain trust relationships using bloodyAD.

        <documentation>
        Retrieve domain trust information.
        </documentation>

        Args:
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["get", "trusts"])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_get_search(
        self,
        ldap_filter: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        base_dn: str | None = None,
        attributes: list[str] | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Perform a generic LDAP search using bloodyAD.

        <documentation>
        Execute custom LDAP search queries.
        </documentation>

        Args:
            ldap_filter: LDAP filter query (e.g., '(objectClass=user)' or '(servicePrincipalName=*)').
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            base_dn: Base DN for the search (e.g., 'DC=domain,DC=local').
            attributes: List of attributes to retrieve.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["get", "search", "--filter", ldap_filter])

        if base_dn:
            cmd.extend(["--base", base_dn])

        if attributes:
            for attr in attributes:
                cmd.extend(["--attr", attr])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_add_groupmember(
        self,
        group_name: str,
        member_name: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Add a member to a group using bloodyAD.

        <documentation>
        Add a user or computer to an Active Directory group.
        </documentation>

        Args:
            group_name: The group to add the member to.
            member_name: The user or computer to add to the group.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["add", "groupMember", group_name, member_name])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_add_computer(
        self,
        computer_name: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        computer_password: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Add a computer account to AD using bloodyAD.

        <documentation>
        Create a new computer account in Active Directory.
        </documentation>

        Args:
            computer_name: The name of the computer account to create.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            computer_password: Optional password for the computer account.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["add", "computer", computer_name])

        if computer_password:
            cmd.extend(["--computer-pass", computer_password])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_add_user(
        self,
        new_username: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        user_password: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Add a user account to AD using bloodyAD.

        <documentation>
        Create a new user account in Active Directory.
        </documentation>

        Args:
            new_username: The username for the new account to create.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication (the account performing the action).
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            user_password: Optional password for the new user account.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["add", "user", new_username])

        if user_password:
            cmd.extend(["--user-pass", user_password])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_add_dcsync(
        self,
        target_username: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Grant DCSync rights to a user using bloodyAD.

        <documentation>
        Grant DCSync permissions (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All).
        </documentation>

        Args:
            target_username: The user to grant DCSync rights to.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication (the account performing the action).
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["add", "dcsync", target_username])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_add_rbcd(
        self,
        delegate_to: str,
        delegate_from: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Configure Resource-Based Constrained Delegation using bloodyAD.

        <documentation>
        Add RBCD (Resource-Based Constrained Delegation) to allow delegation.
        </documentation>

        Args:
            delegate_to: The target object that will allow delegation.
            delegate_from: The object that can impersonate to delegate_to.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["add", "rbcd", delegate_to, delegate_from])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_add_shadowcredentials(
        self,
        target_object: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        pfx_password: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Add shadow credentials for authentication using bloodyAD.

        <documentation>
        Add shadow credentials (msDS-KeyCredentialLink) to enable Key Trust authentication.
        </documentation>

        Args:
            target_object: The target object to add shadow credentials to.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            pfx_password: Optional password for the PFX certificate.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["add", "shadowCredentials", target_object])

        if pfx_password:
            cmd.extend(["--pfx-password", pfx_password])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_add_genericall(
        self,
        target_object: str,
        principal: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Grant GenericAll rights using bloodyAD.

        <documentation>
        Grant GenericAll permissions on a target object.
        </documentation>

        Args:
            target_object: The object to grant GenericAll rights on.
            principal: The principal to grant GenericAll rights to.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["add", "genericAll", target_object, principal])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_add_dnsrecord(
        self,
        record_name: str,
        ip_address: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Add a DNS record to Active Directory using bloodyAD.

        <documentation>
        Add a DNS record to AD-integrated DNS.
        </documentation>

        Args:
            record_name: The DNS record name to create.
            ip_address: The IP address for the DNS record.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["add", "dnsRecord", record_name, ip_address])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_set_password(
        self,
        target_username: str,
        new_password: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Change a user's password using bloodyAD.

        <documentation>
        Set or change a user's password in Active Directory.
        </documentation>

        Args:
            target_username: The user account whose password will be changed.
            new_password: The new password to set for the target user.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication (the account performing the action).
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["set", "password", target_username, new_password])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_set_object(
        self,
        object_name: str,
        attribute: str,
        values: list[str],
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Set object attributes using bloodyAD.

        <documentation>
        Modify attributes of an Active Directory object.
        </documentation>

        Args:
            object_name: The object to modify.
            attribute: The attribute to set.
            values: The value(s) to set for the attribute.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["set", "object", object_name, attribute])
        cmd.extend(values)

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_remove_groupmember(
        self,
        group_name: str,
        member_name: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Remove a member from a group using bloodyAD.

        <documentation>
        Remove a user or computer from an Active Directory group.
        </documentation>

        Args:
            group_name: The group to remove the member from.
            member_name: The user or computer to remove from the group.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["remove", "groupMember", group_name, member_name])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_remove_object(
        self,
        object_name: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Delete an AD object using bloodyAD.

        <documentation>
        Remove an object from Active Directory.
        </documentation>

        Args:
            object_name: The object to delete from Active Directory.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["remove", "object", object_name])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_remove_dcsync(
        self,
        target_username: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Remove DCSync rights from a user using bloodyAD.

        <documentation>
        Remove DCSync permissions from a principal.
        </documentation>

        Args:
            target_username: The user to remove DCSync rights from.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication (the account performing the action).
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["remove", "dcsync", target_username])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_remove_rbcd(
        self,
        delegate_to: str,
        delegate_from: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Remove Resource-Based Constrained Delegation configuration using bloodyAD.

        <documentation>
        Remove RBCD configuration from a target.
        </documentation>

        Args:
            delegate_to: The target object to remove delegation from.
            delegate_from: The object that can no longer impersonate to delegate_to.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["remove", "rbcd", delegate_to, delegate_from])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_remove_shadowcredentials(
        self,
        target_object: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Remove shadow credentials using bloodyAD.

        <documentation>
        Remove shadow credentials (msDS-KeyCredentialLink) from a target.
        </documentation>

        Args:
            target_object: The target object to remove shadow credentials from.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["remove", "shadowCredentials", target_object])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_remove_dnsrecord(
        self,
        record_name: str,
        ip_address: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Remove a DNS record from Active Directory using bloodyAD.

        <documentation>
        Remove a DNS record from AD-integrated DNS.
        </documentation>

        Args:
            record_name: The DNS record name to remove.
            ip_address: The IP address of the DNS record to remove.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["remove", "dnsRecord", record_name, ip_address])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def bloodyad_remove_genericall(
        self,
        target_object: str,
        principal: str,
        *,
        domain: str,
        username: str,
        host: str,
        password: str | None = None,
        hashes: str | None = None,
        use_kerberos: bool = False,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Remove GenericAll rights using bloodyAD.

        <documentation>
        Remove GenericAll permissions from a principal on a target object.
        </documentation>

        Args:
            target_object: The object to remove GenericAll rights from.
            principal: The principal to remove GenericAll rights from.
            domain: Domain name (e.g., 'domain.local').
            username: Username for authentication.
            host: Hostname or IP address of the domain controller.
            password: Password for authentication. Use either this or hashes.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            use_kerberos: Use Kerberos authentication (requires -k flag).
            dc_ip: Optional DC IP address to override DNS resolution.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        cmd = [
            self.bloodyad_cmd,
            *self._build_connection_options(
                domain=domain,
                username=username,
                host=host,
                password=password,
                hashes=hashes,
                use_kerberos=use_kerberos,
                dc_ip=dc_ip,
            ),
        ]

        cmd.extend(["remove", "genericAll", target_object, principal])

        return await execute(
            cmd,
            timeout=self.timeout,
            input=input,
            env=env,
        )
