import shlex
import typing as t

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute

if t.TYPE_CHECKING:
    pass  # TODO: Apollo type hint removed — SharpView can run standalone or with Mythic C2 capability


class SharpView(Toolset):
    """
    Toolset for Active Directory reconnaissance using SharpView.

    SharpView is a .NET port of PowerView for Windows domain enumeration.

    # Local execution
    sharpview = SharpView()
    users = await sharpview.get_domain_user("-Identity admin")

    # Remote via Mythic C2 (Apollo)
    apollo = Apollo(...)
    sharpview = SharpView(apollo=apollo)
    users = await sharpview.get_domain_user("-Identity admin")
    """

    timeout: int = Config(default=120)
    """Default timeout for commands in seconds."""

    apollo: t.Any | None = Config(default=None)
    """Optional Apollo instance for remote execution via Mythic C2."""

    async def _execute(self, method: str, method_args: str = "") -> str:
        """Internal method to route execution to Apollo or command."""
        if self.apollo:
            return await self.apollo.sharpview(method=method, method_args=method_args)
        args = ["SharpView.exe", method]
        if method_args:
            args.extend(shlex.split(method_args))
        return await execute(args, timeout=self.timeout)

    @tool_method(catch=True, variants=["all"])
    async def get_domain(self, args: str = "") -> str:
        """
        Get information about the current or specified domain.

        Args:
            args: Optional arguments string. Available options:
                -Domain <string>: Target domain to query
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-Domain", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_computer(self, args: str = "") -> str:
        """
        Get all computers in the domain or specific computers.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: Computer name or SAM account name to filter
                -Unconstrained: Filter for computers with unconstrained delegation
                -TrustedToAuth: Filter for computers trusted for authentication delegation
                -Printers: Filter to include printer objects
                -SPN <string>: Filter by service principal name
                -OperatingSystem <string>: Filter by operating system type
                -ServicePack <string>: Filter by service pack version
                -SiteName <string>: Filter by Active Directory site
                -Ping: Perform ping verification on results
                -Domain <string>: Target Active Directory domain
                -LDAPFilter <string>: Custom LDAP filter for search
                -Properties <string[]>: Specific attributes to retrieve
                -SearchBase <string>: Distinguished name search root path
                -Server <string>: Specific domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted/tombstone objects
                -FindOne: Return only first result
                -Credential <domain\\user>: Alternate credentials
                -Raw: Return unprocessed results
                -UACFilter <flags>: Filter by user account control flags
        """
        return await self._execute("Get-DomainComputer", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_controller(self, args: str = "") -> str:
        """
        Get domain controllers for the current or specified domain.

        Args:
            args: Optional arguments string. Available options:
                -Domain <string>: Target Active Directory domain to query
                -Server <string>: Specific server to connect to
                -LDAP: Enable LDAP protocol for directory queries
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-DomainController", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_user(self, args: str = "") -> str:
        """
        Get all users in the domain or specific users.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: User name or SAM account name to filter
                -SPN: Filter for users with Service Principal Names (kerberoastable)
                -AdminCount: Filter for users with adminCount attribute set
                -AllowDelegation: Filter for users that allow delegation
                -DisallowDelegation: Filter for users with restricted delegation
                -TrustedToAuth: Filter for users trusted for authentication
                -PreauthNotRequired: Filter for users without Kerberos preauth (ASREProastable)
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -Properties <string[]>: Specific attributes to retrieve
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -FindOne: Return only first result
                -Credential <domain\\user>: Alternate credentials
                -Raw: Return unprocessed results
                -UACFilter <flags>: Filter by user account control flags
        """
        return await self._execute("Get-DomainUser", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_group(self, args: str = "") -> str:
        """
        Get all groups in the domain or specific groups.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: Group name or SAM account name to filter
                -MemberIdentity <string>: Filter groups by member identity
                -AdminCount: Filter for groups with adminCount attribute set
                -GroupScope <scope>: Filter by group scope (DomainLocal, Global, Universal)
                -GroupProperty <property>: Filter by specific group properties
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -Properties <string[]>: Specific attributes to retrieve
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -FindOne: Return only first result
                -Credential <domain\\user>: Alternate credentials
                -Raw: Return unprocessed results
        """
        return await self._execute("Get-DomainGroup", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_group_member(self, args: str = "") -> str:
        """
        Get members of a domain group.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: Group name or SAM account name (required)
                -Recurse: Enable recursive member enumeration through nested groups
                -RecurseUsingMatchingRule: Use LDAP matching rule for recursive queries
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("Get-DomainGroupMember", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_gpo(self, args: str = "") -> str:
        """
        Get Group Policy Objects in the domain.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: GPO name or GUID to filter
                -ComputerIdentity <string>: Filter GPOs applied to specific computer
                -UserIdentity <string>: Filter GPOs applied to specific user
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -Properties <string[]>: Specific attributes to retrieve
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -FindOne: Return only first result
                -Credential <domain\\user>: Alternate credentials
                -Raw: Return unprocessed results
        """
        return await self._execute("Get-DomainGPO", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_ou(self, args: str = "") -> str:
        """
        Get Organizational Units in the domain.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: OU name or distinguished name to filter
                -GPLink <string>: Filter OUs by linked Group Policy GUID
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -Properties <string[]>: Specific attributes to retrieve
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -FindOne: Return only first result
                -Credential <domain\\user>: Alternate credentials
                -Raw: Return unprocessed results
        """
        return await self._execute("Get-DomainOU", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_object_acl(self, args: str = "") -> str:
        """
        Get ACLs for domain objects.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: Object name or distinguished name to query
                -ResolveGUIDs: Convert GUIDs to readable names in results
                -Sacl: Include System Access Control Lists in ACL retrieval
                -RightsFilter <rights>: Filter results by specific access rights
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("Get-DomainObjectAcl", args)

    @tool_method(catch=True, variants=["all"])
    async def find_interesting_domain_acl(self, args: str = "") -> str:
        """
        Find interesting ACLs in the domain (potential privilege escalation paths).

        Args:
            args: Optional arguments string. Available options:
                -ResolveGUIDs: Convert GUIDs to readable names in results
                -RightsFilter <rights>: Filter results by specific access rights
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("Find-InterestingDomainAcl", args)

    @tool_method(catch=True, variants=["all"])
    async def get_forest(self, args: str = "") -> str:
        """
        Get information about the current or specified forest.

        Args:
            args: Optional arguments string. Available options:
                -Forest <string>: Target forest name to query
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-Forest", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_trust(self, args: str = "") -> str:
        """
        Get domain trust relationships.

        Args:
            args: Optional arguments string. Available options:
                -Domain <string>: Target domain for trust enumeration
                -API: Use API-based query method
                -NET: Use NET-based query method
                -LDAPFilter <string>: Custom LDAP query filter
                -Properties <string[]>: Specific attributes to retrieve
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -FindOne: Return only first result
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("Get-DomainTrust", args)

    @tool_method(catch=True, variants=["all"])
    async def get_forest_trust(self, args: str = "") -> str:
        """
        Get forest trust relationships.

        Args:
            args: Optional arguments string. Available options:
                -Forest <string>: Target forest name to query
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-ForestTrust", args)

    @tool_method(catch=True, variants=["all"])
    async def invoke_kerberoast(self, args: str = "") -> str:
        """
        Request service tickets for kerberoastable accounts.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: Specific user to target for kerberoasting
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (Base, OneLevel, Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("Invoke-Kerberoast", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_spn_ticket(self, args: str = "") -> str:
        """
        Request a service ticket for a specific SPN.

        Args:
            args: Optional arguments string. Available options:
                -SPN <string>: Service Principal Name to request ticket for (required)
                -User <string>: User account for which to obtain the Kerberos ticket
                -OutputFormat <format>: Output format for the ticket (Hashcat, John)
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-DomainSPNTicket", args)

    @tool_method(catch=True, variants=["all"])
    async def test_admin_access(self, args: str = "") -> str:
        """
        Test if current user has local admin access on specified computer(s).

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) to test (default: localhost)
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Test-AdminAccess", args)

    @tool_method(catch=True, variants=["all"])
    async def find_local_admin_access(self, args: str = "") -> str:
        """
        Find computers where the current user has local admin access.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) to check
                -ComputerDomain <string>: Domain associated with computers
                -ComputerLDAPFilter <string>: LDAP filter for computer queries
                -ComputerSearchBase <string>: LDAP search base path
                -ComputerOperatingSystem <string>: Filter by operating system
                -ComputerServicePack <string>: Filter by service pack level
                -ComputerSiteName <string>: Filter by Active Directory site
                -CheckShareAccess: Enable share access verification
                -Server <string>: Domain controller to query
                -SearchScope <scope>: LDAP search scope (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -Credential <domain\\user>: Alternate credentials
                -Delay <int>: Milliseconds between operations (1-10000)
                -Jitter <double>: Random delay variance (0.0-1.0, default: 0.3)
                -Threads <int>: Concurrent threads (1-100, default: 20)
        """
        return await self._execute("Find-LocalAdminAccess", args)

    @tool_method(catch=True, variants=["all"])
    async def get_net_share(self, args: str = "") -> str:
        """
        Get shares on the specified computer.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) (default: localhost)
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-NetShare", args)

    @tool_method(catch=True, variants=["all"])
    async def find_domain_share(self, args: str = "") -> str:
        """
        Find shares in the domain.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) to search
                -ComputerDomain <string>: Domain to search within
                -ComputerLDAPFilter <string>: LDAP filter for computer searches
                -ComputerSearchBase <string>: LDAP search base for computers
                -ComputerOperatingSystem <string>: Filter by operating system
                -ComputerServicePack <string>: Filter by service pack
                -ComputerSiteName <string>: Filter by AD site
                -CheckShareAccess: Validate access to discovered shares
                -Server <string>: Domain controller to query
                -SearchScope <scope>: LDAP search scope (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include tombstoned objects
                -Credential <domain\\user>: Alternate credentials
                -Delay <int>: Milliseconds between operations (1-10000)
                -Jitter <double>: Random delay variance (0.0-1.0, default: 0.3)
                -Threads <int>: Concurrent threads (1-100, default: 20)
        """
        return await self._execute("Find-DomainShare", args)

    @tool_method(catch=True, variants=["all"])
    async def find_interesting_domain_share_file(self, args: str = "") -> str:
        """
        Find interesting files on domain shares.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) to search
                -ComputerDomain <string>: Domain of target computers
                -ComputerLDAPFilter <string>: LDAP filter for computer queries
                -ComputerSearchBase <string>: LDAP search base for computers
                -ComputerOperatingSystem <string>: Filter by OS type
                -ComputerServicePack <string>: Filter by service pack
                -ComputerSiteName <string>: Filter by AD site
                -Include <string[]>: File patterns to search for (defaults: password, sensitive,
                    admin, login, secret, unattend*.xml, *.vmdk, creds, credential, *.config)
                -SharePath <string[]>: Specific shares to search
                -ExcludedShares <string[]>: Shares to skip (defaults: C$, Admin$, Print$, IPC$)
                -LastAccessTime <DateTime>: Filter files by last access date
                -LastWriteTime <DateTime>: Filter files by last write date
                -CreationTime <DateTime>: Filter files by creation date
                -OfficeDocs: Include Office documents in search
                -FreshEXEs: Include recent executables
                -Server <string>: Domain controller to query
                -SearchScope <scope>: LDAP search scope (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include tombstoned objects
                -Credential <domain\\user>: Alternate credentials
                -StopOnSuccess: Halt on successful search result
                -Delay <int>: Milliseconds between operations (1-10000)
                -Jitter <double>: Random delay variance (0.0-1.0, default: 0.3)
                -Threads <int>: Concurrent threads (1-100, default: 20)
        """
        return await self._execute("Find-InterestingDomainShareFile", args)

    @tool_method(catch=True, variants=["all"])
    async def get_net_session(self, args: str = "") -> str:
        """
        Get active sessions on the specified computer.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) (default: localhost)
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-NetSession", args)

    @tool_method(catch=True, variants=["all"])
    async def get_net_loggedon(self, args: str = "") -> str:
        """
        Get logged on users on the specified computer.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) (default: localhost)
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-NetLoggedon", args)

    @tool_method(catch=True, variants=["all"])
    async def get_net_local_group(self, args: str = "") -> str:
        """
        Get local groups on the specified computer.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) (default: local machine)
                -Method <type>: Collection method (API or WinNT, default: API)
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-NetLocalGroup", args)

    @tool_method(catch=True, variants=["all"])
    async def get_net_local_group_member(self, args: str = "") -> str:
        """
        Get members of a local group on the specified computer.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) (default: local machine)
                -GroupName <string>: Local group to query (default: Administrators)
                -Method <type>: Collection method (API or WinNT, default: API)
                -Credential <domain\\user>: Alternate credentials for authentication
        """
        return await self._execute("Get-NetLocalGroupMember", args)

    @tool_method(catch=True, variants=["all"])
    async def find_domain_local_group_member(self, args: str = "") -> str:
        """
        Find computers where a domain user/group is a member of a local group.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) to search
                -ComputerDomain <string>: Domain associated with computers
                -ComputerLDAPFilter <string>: LDAP filter for computer searches
                -ComputerSearchBase <string>: Base DN for computer searches
                -ComputerOperatingSystem <string>: Filter by operating system
                -ComputerServicePack <string>: Filter by service pack
                -ComputerSiteName <string>: Filter by AD site
                -GroupName <string>: Group to enumerate members from (default: Administrators)
                -Method <type>: Query method (API or WinNT, default: API)
                -Server <string>: Domain controller to query
                -SearchScope <scope>: LDAP search scope (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include tombstoned objects
                -Credential <domain\\user>: Alternate credentials
                -Delay <int>: Milliseconds between requests (1-10000)
                -Jitter <double>: Random delay variance (0.0-1.0, default: 0.3)
                -Threads <int>: Concurrent threads (1-100, default: 20)
        """
        return await self._execute("Find-DomainLocalGroupMember", args)

    @tool_method(catch=True, variants=["all"])
    async def find_domain_user_location(self, args: str = "") -> str:
        """
        Find computers where specific users are logged in.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) to search
                -Domain <string>: Domain to query
                -ComputerDomain <string>: Domain for computer filtering
                -ComputerLDAPFilter <string>: LDAP filter for computers
                -ComputerSearchBase <string>: LDAP search base for computers
                -ComputerUnconstrained: Filter for unconstrained delegation computers
                -ComputerOperatingSystem <string>: Filter by OS type
                -ComputerServicePack <string>: Filter by service pack
                -ComputerSiteName <string>: Filter by AD site
                -UserIdentity <string[]>: Specific users to locate
                -UserDomain <string>: Domain for user filtering
                -UserLDAPFilter <string>: LDAP filter for users
                -UserSearchBase <string>: LDAP search base for users
                -UserGroupIdentity <string[]>: Target groups (default: Domain Admins)
                -UserAdminCount: Filter users with adminCount attribute
                -UserAllowDelegation: Filter by delegation permissions
                -CheckAccess: Verify access to discovered locations
                -Server <string>: Domain controller to query
                -SearchScope <scope>: LDAP search scope (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include tombstoned objects
                -Credential <domain\\user>: Alternate credentials
                -StopOnSuccess: Halt after finding target
                -Delay <int>: Milliseconds between requests (1-10000)
                -Jitter <double>: Random delay variance (0.0-1.0, default: 0.3)
                -ShowAll: Return all results without filtering
                -Stealth: Enable stealth mode
                -Threads <int>: Concurrent threads (1-100, default: 20)
        """
        return await self._execute("Find-DomainUserLocation", args)

    @tool_method(catch=True, variants=["all"])
    async def find_domain_process(self, args: str = "") -> str:
        """
        Find processes running on domain computers.

        Args:
            args: Optional arguments string. Available options:
                -ComputerName <string[]>: Target computer(s) to search
                -Domain <string>: Domain to query
                -ComputerDomain <string>: Domain for computer filtering
                -ComputerLDAPFilter <string>: LDAP filter for computers
                -ComputerSearchBase <string>: LDAP search base for computers
                -ComputerUnconstrained: Filter for unconstrained delegation computers
                -ComputerOperatingSystem <string>: Filter by OS type
                -ComputerServicePack <string>: Filter by service pack
                -ComputerSiteName <string>: Filter by AD site
                -ProcessName <string[]>: Process name(s) to search for
                -UserIdentity <string[]>: User account(s) to target
                -UserDomain <string>: Domain for user filtering
                -UserLDAPFilter <string>: LDAP filter for users
                -UserSearchBase <string>: LDAP search base for users
                -UserGroupIdentity <string[]>: Target groups (default: Domain Admins)
                -UserAdminCount: Filter users with adminCount attribute
                -Server <string>: Domain controller to query
                -SearchScope <scope>: LDAP search scope (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include tombstoned objects
                -Credential <domain\\user>: Alternate credentials
                -StopOnSuccess: Halt on successful result
                -Delay <int>: Milliseconds between requests (1-10000)
                -Jitter <double>: Random delay variance (0.0-1.0, default: 0.3)
                -Threads <int>: Concurrent threads (1-100, default: 20)
        """
        return await self._execute("Find-DomainProcess", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_file_server(self, args: str = "") -> str:
        """
        Get file servers in the domain.

        Args:
            args: Optional arguments string. Available options:
                -Domain <string[]>: Target domain(s) to query
                -LDAPFilter <string>: Custom LDAP filter for searches
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("Get-DomainFileServer", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_dfs_share(self, args: str = "") -> str:
        """
        Get DFS shares in the domain.

        Args:
            args: Optional arguments string. Available options:
                -Domain <string[]>: Target domain(s) to query
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -Credential <domain\\user>: Alternate credentials
                -Version <version>: DFS version filter (default: All)
        """
        return await self._execute("Get-DomainDFSShare", args)

    @tool_method(catch=True, variants=["all"])
    async def convert_from_sid(self, args: str = "") -> str:
        """
        Convert a SID to a name.

        Args:
            args: Arguments string. Available options:
                -ObjectSID <string[]>: Security Identifier(s) to convert (required)
                -Domain <string>: Target domain for the conversion
                -Server <string>: Domain controller to query
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("ConvertFrom-SID", args)

    @tool_method(catch=True, variants=["all"])
    async def convert_to_sid(self, args: str = "") -> str:
        """
        Convert a name to a SID.

        Args:
            args: Arguments string. Available options:
                -ObjectName <string[]>: Object name(s) to convert (required)
                -Domain <string>: Target domain for the conversion
                -Server <string>: Domain controller to query
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("ConvertTo-SID", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_site(self, args: str = "") -> str:
        """
        Get sites in the domain.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: Site name to filter
                -GPLink <string>: Filter sites by linked Group Policy GUID
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -Properties <string[]>: Specific attributes to retrieve
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -FindOne: Return only first result
                -Credential <domain\\user>: Alternate credentials
                -Raw: Return unprocessed results
        """
        return await self._execute("Get-DomainSite", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_subnet(self, args: str = "") -> str:
        """
        Get subnets in the domain.

        Args:
            args: Optional arguments string. Available options:
                -Identity <string>: Subnet name to filter (e.g., '10.0.0.0/24')
                -SiteName <string>: Filter subnets by AD site name
                -Domain <string>: Target domain for search
                -LDAPFilter <string>: Custom LDAP query filter
                -Properties <string[]>: Specific attributes to retrieve
                -SearchBase <string>: LDAP search root path
                -Server <string>: Domain controller to query
                -SearchScope <scope>: Search depth (default: Subtree)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -Tombstone: Include deleted objects
                -FindOne: Return only first result
                -Credential <domain\\user>: Alternate credentials
                -Raw: Return unprocessed results
        """
        return await self._execute("Get-DomainSubnet", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_dns_record(self, args: str = "") -> str:
        """
        Get DNS records from Active Directory.

        Args:
            args: Optional arguments string. Available options:
                -ZoneName <string>: DNS zone name to query
                -Domain <string>: Target domain for DNS record lookup
                -Server <string>: Domain controller to query
                -Properties <string[]>: Attributes to retrieve (defaults: name,
                    distinguishedname, dnsrecord, whencreated, whenchanged)
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -FindOne: Return only first matching record
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("Get-DomainDNSRecord", args)

    @tool_method(catch=True, variants=["all"])
    async def get_domain_dns_zone(self, args: str = "") -> str:
        """
        Get DNS zones from Active Directory.

        Args:
            args: Optional arguments string. Available options:
                -Domain <string>: Target domain for DNS zone queries
                -Server <string>: Domain controller to query
                -Properties <string[]>: Specific attributes to retrieve
                -ResultPageSize <int>: Results per page (1-10000, default: 200)
                -ServerTimeLimit <int>: Query timeout in seconds
                -FindOne: Return only first matching result
                -Credential <domain\\user>: Alternate credentials
        """
        return await self._execute("Get-DomainDNSZone", args)
