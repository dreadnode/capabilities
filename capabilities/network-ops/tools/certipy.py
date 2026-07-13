import shutil
import types
from typing import override

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger


def _detect_certipy_command() -> str:
    """Detect whether certipy is available as 'certipy' (pip) or 'certipy-ad' (Kali)."""
    if shutil.which("certipy"):
        return "certipy"
    if shutil.which("certipy-ad"):
        return "certipy-ad"
    # Default to pip-installed name, will fail with clear error if not installed
    return "certipy"


class Certipy(Toolset):
    """
    Toolset for using Certipy to interact with Active Directory Certificate Services (AD CS).
    """

    variant: str | None = Config(default="generic")
    """Expose generic protocol functions or specialized methods wrapping common use cases (or both)."""
    timeout: int = Config(default=20)
    """Default timeout for commands in seconds."""
    certipy_cmd: str = Config(default_factory=_detect_certipy_command)
    """Command to execute certipy (auto-detected: 'certipy' for pip, 'certipy-ad' for Kali)."""

    @override
    async def __aenter__(self):
        """Initialize Certipy toolset and verify certipy is installed."""
        if not shutil.which(self.certipy_cmd):
            logger.warning(
                f"certipy command '{self.certipy_cmd}' not found in PATH. "
                "Install with: pip install certipy-ad"
            )
        else:
            logger.info(
                f"Certipy toolset initialized, using command: {self.certipy_cmd}"
            )
        return self

    @override
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ):
        """Clean up Certipy toolset resources."""
        return

    @tool_method(catch=True, variants=["all"])
    async def certipy(
        self,
        action: str,
        args: list[str],
        target: str,
        username: str | None = None,
        domain: str | None = None,
        password: str | None = None,
        nt_hash: str | None = None,
        input: str | None = None,
    ) -> str:
        """
        Execute certipy-ad to interact with active directory certificate services (AD CS).

        Args:
            action: The certipy-ad action. Can be one of:
                account - Manage user and machine accounts
                auth - Authenticate using certificates
                ca - Manage CA and certificates
                cert - Manage certificates and private keys
                find - Enumerate AD CS
                parse - Offline enumerate AD CS based on registry data
                forge - Create Golden Certificates or self-signed certificates
                relay - NTLM Relay to AD CS HTTP Endpoints
                req -  Request certificates
                shadow -  Abuse Shadow Credentials for account takeover
                template - Manage certificate templates
            args: A list of arguments specific to the subcommand.
            target: The IP address of the Domain Controller.
            username: The username for authentication.
            domain: The domain name.
            password: The password for authentication.
            nt_hash: The NTLM hash for authentication.
            input: Optional input string to send to the command's standard input.
        """
        cmd = [self.certipy_cmd, action]

        if username:
            if domain and "@" not in username:
                cmd.extend(["-u", f"{username}@{domain}"])
            else:
                cmd.extend(["-u", username])

        if password:
            cmd.extend(["-p", password])
        elif nt_hash:
            cmd.extend(["-hashes", f":{nt_hash}"])

        cmd.extend(["-dc-ip", target])
        cmd.extend(args)

        logger.info(
            f"Running '{self.certipy_cmd} {action}' with args: {' '.join(args)}"
        )
        return await execute(cmd, timeout=self.timeout, input=input)

    # Specialized methods

    @tool_method(catch=True, variants=["specialized", "all"])
    async def certipy_find_vulnerable_templates(
        self,
        target: str,
        username: str,
        domain: str,
        password: str | None = None,
        nt_hash: str | None = None,
    ) -> str:
        """
        Finds vulnerable AD CS certificate templates using the certipy-ad runner.

        Args:
            target: The IP address of the Domain Controller.
            username: The username for authentication.
            domain: The domain name.
            password: The password for authentication.
            nt_hash: The NTLM hash for authentication.
        """
        logger.info(f"Finding vulnerable certificate templates on {target}")
        return await self.certipy(
            action="find",
            args=["-vulnerable", "-stdout"],
            target=target,
            username=username,
            domain=domain,
            password=password,
            nt_hash=nt_hash,
        )

    @tool_method(catch=True, variants=["specialized", "all"])
    async def certipy_request_certificate(
        self,
        target: str,
        ca_server: str,
        ca_name: str,
        template: str,
        username: str,
        domain: str,
        password: str | None = None,
        nt_hash: str | None = None,
        on_behalf_of: str | None = None,
    ) -> str:
        """
        Requests a certificate using a specified template via the certipy-ad runner.

        Args:
            target: IP address of the Domain Controller.
            ca_server: Hostname or IP of the Certificate Authority server.
            ca_name: Name of the Certificate Authority (e.g., "corp-CA").
            template: Name of the certificate template to use.
            username: Username for authentication.
            domain: Domain name.
            password: Password for authentication.
            nt_hash: NTLM hash for authentication.
            on_behalf_of: User to impersonate for the certificate request (for ESC4).
        """
        args = [
            "-target",
            ca_server,
            "-ca",
            ca_name,
            "-template",
            template,
        ]
        if on_behalf_of:
            args.extend(["-on-behalf-of", on_behalf_of])

        return await self.certipy(
            action="req",
            args=args,
            target=target,
            username=username,
            domain=domain,
            password=password,
            nt_hash=nt_hash,
            input="y",
        )

    @tool_method(catch=True, variants=["specialized", "all"])
    async def certipy_certificate_auth(
        self,
        pfx_file: str,
        target: str,
        *,
        username: str = "",
        domain: str = "",
    ) -> str:
        """
        Authenticates using a certificate to get an NT hash or TGT.

        Args:
            pfx_file: Path to the PFX certificate file.
            target: IP address of the Domain Controller.
            username: The username for authentication.
            domain: The domain name.
        """
        return await self.certipy(
            action="auth",
            args=["-pfx", pfx_file],
            username=username,
            domain=domain,
            target=target,
            input="y",
        )

    # General methods

    @tool_method(catch=True, variants=["generic", "all"])
    async def certipy_account(self, args: list[str], input: str | None = None) -> str:
        """
        Execute a certipy-ad account command.

        <documentation>
        Create, read, update, and delete Active Directory user and computer accounts. This command allows manipulating account properties including DNS names, service principal names (SPNs), and
        passwords.

        positional arguments:
        {create,read,update,delete}
                                Action to perform: create (new account), read (view account properties), update (modify existing account), delete (remove account)

        options:
        -h, --help            show this help message and exit

        target options:
        -user SAM Account Name
                                Logon name for the account to target
        -group CN=Computers,DC=test,DC=local
                                Group to which the account will be added. If omitted, CN=Computers,<default path> will be used

        attribute options:
        -dns hostname         Set the DNS hostname for the account (e.g., computer.domain.local)
        -upn principal name   Set the User Principal Name for the account (e.g., user@domain.local)
        -sam account name     Set the SAM Account Name for the account (e.g., computer$ or username)
        -spns service names   Set the Service Principal Names for the account (comma-separated)
        -pass password        Set the password for the account

        connection options:
        -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
        -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the domain part (FQDN) specified in the account parameter
                                will be used
        -target-ip ip address
                                IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
        -target dns/ip address
                                DNS name or IP address of the target machine. Required for Kerberos authentication
        -ns ip address        Nameserver for DNS resolution
        -dns-tcp              Use TCP instead of UDP for DNS queries
        -timeout seconds      Timeout for connections in seconds (default: 10)

        authentication options:
        -u, -username username@domain
                                Username to authenticate with
        -p, -password password
                                Password for authentication
        -hashes [lmhash:]nthash
                                NTLM hash
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones
                                specified in the command line
        -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
        -no-pass              Don't ask for password (useful for -k)

        ldap options:
        -ldap-scheme ldap scheme
                                LDAP connection scheme to use (default: ldaps)
        -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
        -no-ldap-channel-binding
                                Don't use LDAP channel binding for LDAP communication (LDAPS only)
        -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
        -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
        -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
        </documentation>

        Args:
            args: List of arguments for the command.
            input: Optional input string to pass to the command's stdin.
        """
        return await execute(
            [self.certipy_cmd, "account", *args], timeout=self.timeout, input=input
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def certipy_auth(self, args: list[str], input: str | None = "y") -> str:
        """
        Execute a certipy-ad auth command.

        <documentation>
        Authenticate to Active Directory services using certificates. This command enables certificate-based authentication to obtain Kerberos tickets, NT hashes, or establish LDAP connections.

        options:
        -h, --help            show this help message and exit

        certificate options:
        -pfx pfx/p12 file name
                                Path to certificate and private key (PFX/P12 format)
        -password password    Password for the PFX/P12 file

        output options:
        -no-save              Don't save Kerberos TGT to file
        -no-hash              Don't request NT hash from Kerberos
        -print                Print Kerberos TGT in Kirbi format to console
        -kirbi                Save Kerberos TGT in Kirbi format (default is ccache)

        connection options:
        -dc-ip ip address     IP Address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
        -ns nameserver        Nameserver for DNS resolution
        -dns-tcp              Use TCP instead of UDP for DNS queries
        -timeout seconds      Timeout for connections in seconds

        authentication options:
        -username username    Username to authenticate as (extracted from certificate if omitted)
        -domain domain        Domain name to authenticate to (extracted from certificate if omitted)
        -ldap-shell           Authenticate with the certificate via Schannel against LDAP

        ldap options:
        -ldap-scheme ldap scheme
                                LDAP connection scheme to use (default: ldaps)
        -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
        -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
        </documentation>

        Args:
            args: List of arguments for the command.
            input: Optional input string to pass to the command's stdin.
        """
        return await execute(
            [self.certipy_cmd, "auth", *args], timeout=self.timeout, input=input
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def certipy_ca(self, args: list[str], input: str | None = None) -> str:
        r"""
        Execute a certipy-ad ca command.

        <documentation>
        Manage Certificate Authority configurations, templates, and permissions. This command allows enabling/disabling templates, processing certificate requests, managing role assignments, and backing
        up CA certificates.

        options:
        -h, --help            show this help message and exit
        -ca certificate authority name
                                Name of the Certificate Authority to manage

        certificate template options:
        -enable-template template name
                                Enable a certificate template on the CA
        -disable-template template name
                                Disable a certificate template on the CA
        -list-templates       List all enabled certificate templates on the CA

        certificate request options:
        -issue-request request ID
                                Issue a pending or failed certificate request
        -deny-request request ID
                                Deny a pending certificate request

        officer options:
        -add-officer officer  Add a new officer (Certificate Manager) to the CA
        -remove-officer officer
                                Remove an existing officer (Certificate Manager) from the CA

        manager options:
        -add-manager manager  Add a new manager (CA Manager) to the CA
        -remove-manager manager
                                Remove an existing manager (CA Manager) from the CA

        backup options:
        -backup               Backup CA certificate and private key
        -config Machine\CA    CA configuration string in format Machine\CAName

        connection options:
        -dynamic-endpoint     Prefer dynamic TCP endpoint over named pipe
        -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
        -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the domain part (FQDN) specified in the account parameter
                                will be used
        -target-ip ip address
                                IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
        -target dns/ip address
                                DNS name or IP address of the target machine. Required for Kerberos authentication
        -ns ip address        Nameserver for DNS resolution
        -dns-tcp              Use TCP instead of UDP for DNS queries
        -timeout seconds      Timeout for connections in seconds (default: 10)

        authentication options:
        -u, -username username@domain
                                Username to authenticate with
        -p, -password password
                                Password for authentication
        -hashes [lmhash:]nthash
                                NTLM hash
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones
                                specified in the command line
        -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
        -no-pass              Don't ask for password (useful for -k)

        ldap options:
        -ldap-scheme ldap scheme
                                LDAP connection scheme to use (default: ldaps)
        -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
        -no-ldap-channel-binding
                                Don't use LDAP channel binding for LDAP communication (LDAPS only)
        -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
        -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
        -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
        </documentation>

        Args:
            args: List of arguments for the command.
            input: Optional input string to pass to the command's stdin.
        """
        return await execute(
            [self.certipy_cmd, "ca", *args], timeout=self.timeout, input=input
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def certipy_cert(self, args: list[str], input: str | None = "y") -> str:
        r"""
        Execute a certipy-ad cert command.

        <documentation>
        Import, export, and manipulate certificates and private keys locally. This command supports various operations like converting between formats, extracting components, and creating PFX files.

        options:
        -h, --help            show this help message and exit

        input options:
        -pfx infile           Load certificate and private key from PFX/P12 file
        -password password    Password for the input PFX/P12 file
        -key infile           Load private key from PEM or DER file
        -cert infile          Load certificate from PEM or DER file

        output options:
        -export               Export to PFX/P12 file (default format)
        -out outfile          Output filename for the exported certificate/key
        -nocert               Don't include certificate in output (key only)
        -nokey                Don't include private key in output (certificate only)
        -export-password password
                                Password to protect the output PFX/P12 file
        </documentation>

        Args:
            args: List of arguments for the command.
            input: Optional input string to pass to the command's stdin.
        """
        return await execute(
            [self.certipy_cmd, "cert", *args], timeout=self.timeout, input=input
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def certipy_find(
        self,
        target: str,
        args: list[str] | None = None,
        username: str | None = None,
        domain: str | None = None,
        password: str | None = None,
        nt_hash: str | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute a certipy-ad find command.

        <documentation>
        Discover and analyze Active Directory Certificate Services (AD CS) components. This command identifies vulnerable certificate templates, security misconfigurations, and potential certificate-
        based privilege escalation paths.

        output options:
        -text                 Output result as formatted text file
        -stdout               Output result as text directly to console
        -json                 Output result as JSON
        -csv                  Output result as CSV
        -output prefix        Filename prefix for writing results to

        find options:
        -enabled              Show only enabled certificate templates
        -dc-only              Collects data only from the domain controller. Will not try to retrieve CA security/configuration or check for Web Enrollment
        -vulnerable           Show only vulnerable certificate templates based on nested group memberships
        -hide-admins          Don't show administrator permissions for -text, -stdout, -json, and -csv

        connection options:
        -target-ip ip address
                                IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
        -target dns/ip address
                                DNS name or IP address of the target machine. Required for Kerberos authentication
        -ns ip address        Nameserver for DNS resolution
        -dns-tcp              Use TCP instead of UDP for DNS queries
        -timeout seconds      Timeout for connections in seconds (default: 10)

        ldap options:
        -ldap-scheme ldap scheme
                                LDAP connection scheme to use (default: ldaps)
        -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
        -no-ldap-channel-binding
                                Don't use LDAP channel binding for LDAP communication (LDAPS only)
        -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
        </documentation>

        Args:
            target: The IP address of the Domain Controller.
            args: Additional arguments for the find command (e.g., ["-vulnerable", "-stdout"]).
            username: The username for authentication.
            domain: The domain name (combined with username as user@domain).
            password: The password for authentication.
            nt_hash: The NTLM hash for authentication.
            input: Optional input string to pass to the command.
        """
        return await self.certipy(
            action="find",
            args=args or [],
            target=target,
            username=username,
            domain=domain,
            password=password,
            nt_hash=nt_hash,
            input=input,
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def certipy_req(self, args: list[str], input: str | None = "y") -> str:
        r"""
        Execute a certipy-ad req command.

        <documentation>
        Request and retrieve certificates from Active Directory Certificate Services (AD CS). This command supports multiple enrollment protocols and certificate template types.

        options:
        -h, --help            show this help message and exit
        -ca certificate authority name
                                Name of the Certificate Authority to request certificates from. Required for RPC and DCOM methods

        certificate request options:
        -template template name
                                Certificate template to request (default: User)
        -upn alternative UPN  User Principal Name to include in the Subject Alternative Name
        -dns alternative DNS  DNS name to include in the Subject Alternative Name
        -sid alternative Object SID
                                Object SID to include in the Subject Alternative Name
        -subject subject      Subject to include in certificate, e.g. CN=Administrator,CN=Users,DC=CORP,DC=LOCAL
        -retrieve request ID  Retrieve an issued certificate specified by a request ID instead of requesting a new certificate
        -on-behalf-of domain\account
                                Use a Certificate Request Agent certificate to request on behalf of another user
        -pfx pfx/p12 file name
                                Path to PFX for -on-behalf-of or -renew
        -pfx-password PFX file password
                                Password for the PFX file
        -key-size RSA key length
                                Length of RSA key (default: 2048)
        -archive-key          Send private key for Key Archival
        -cax-cert             Retrieve CAX Cert for relay with enabled Key Archival
        -renew                Create renewal request
        -application-policies Application Policy [Application Policy ...]
                                Specify application policies for the certificate request using OIDs (e.g., '1.3.6.1.4.1.311.10.3.4' or 'Client Authentication')
        -smime encryption algorithm
                                Specify SMIME Extension that gets added to CSR (e.g., des, rc4, 3des, aes128, aes192, aes256)

        output options:
        -out output file name
                                Path to save the certificate and private key (PFX format)

        connection options:
        -web                  Use Web Enrollment instead of RPC
        -dcom                 Use DCOM Enrollment instead of RPC
        -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
        -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the domain part (FQDN) specified in the account parameter
                                will be used
        -target-ip ip address
                                IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
        -target dns/ip address
                                DNS name or IP address of the target machine. Required for Kerberos authentication
        -ns ip address        Nameserver for DNS resolution
        -dns-tcp              Use TCP instead of UDP for DNS queries
        -timeout seconds      Timeout for connections in seconds (default: 10)

        rpc connection options:
        -dynamic-endpoint     Prefer dynamic TCP endpoint over named pipe

        http connection options:
        -http-scheme http scheme
                                HTTP scheme to use for Web Enrollment (default: http)
        -http-port port number
                                Web Enrollment port (default: 80 for http, 443 for https)
        -no-channel-binding   Disable channel binding for HTTP connections

        authentication options:
        -u, -username username@domain
                                Username to authenticate with
        -p, -password password
                                Password for authentication
        -hashes [lmhash:]nthash
                                NTLM hash
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones
                                specified in the command line
        -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
        -no-pass              Don't ask for password (useful for -k)

        ldap options:
        -ldap-scheme ldap scheme
                                LDAP connection scheme to use (default: ldaps)
        -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
        -no-ldap-channel-binding
                                Don't use LDAP channel binding for LDAP communication (LDAPS only)
        -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
        -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
        -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
        </documentation>

        Args:
            args: List of arguments for the command.
        """
        return await execute(
            [self.certipy_cmd, "req", *args], timeout=self.timeout, input=input
        )

    @tool_method(catch=True, variants=["generic", "all"])
    async def certipy_template(self, args: list[str], input: str | None = None) -> str:
        r"""
        Execute a certipy-ad template command.

        <documentation>
        Manipulate certificate templates in Active Directory. This command allows viewing and modifying template configurations for privilege escalation
        testing or remediation.

        options:
        -h, --help            show this help message and exit
        -template template name
                                Name of the certificate template to operate on (case-sensitive)

        configuration options:
        -write-configuration configuration file
                                Apply configuration from a JSON file to the certificate template. Use this option to restore a previous configuration or
                                apply custom settings. The file should contain the template configuration in valid JSON format.
        -write-default-configuration
                                Apply the default Certipy ESC1 configuration to the certificate template. This configures the template to be vulnerable
                                to ESC1 attack.
        -save-configuration configuration file
                                Save the current template configuration to a JSON file. This creates a backup before making changes or documents the
                                current settings. If not specified when using -write-configuration or -write-default-configuration, a backup will still
                                be created.
        -no-save              Skip saving the current template configuration before applying changes. Use this option to apply modifications without
                                creating a backup file.
        -force                Don't prompt for confirmation before applying changes. Use this option to apply modifications without user interaction.

        connection options:
        -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
        -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the
                                domain part (FQDN) specified in the account parameter will be used
        -target-ip ip address
                                IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the
                                NetBIOS name and cannot be resolved
        -target dns/ip address
                                DNS name or IP address of the target machine. Required for Kerberos authentication
        -ns ip address        Nameserver for DNS resolution
        -dns-tcp              Use TCP instead of UDP for DNS queries
        -timeout seconds      Timeout for connections in seconds (default: 10)

        authentication options:
        -u, -username username@domain
                                Username to authenticate with
        -p, -password password
                                Password for authentication
        -hashes [lmhash:]nthash
                                NTLM hash
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid
                                credentials cannot be found, it will use the ones specified in the command line
        -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
        -no-pass              Don't ask for password (useful for -k)

        ldap options:
        -ldap-scheme ldap scheme
                                LDAP connection scheme to use (default: ldaps)
        -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
        -no-ldap-channel-binding
                                Don't use LDAP channel binding for LDAP communication (LDAPS only)
        -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
        -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
        -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
        </documentation>

        Args:
            args: List of arguments for the command.
            input: Optional input string to pass to the command's stdin.
        """
        return await execute(
            [self.certipy_cmd, "template", *args], timeout=self.timeout, input=input
        )
