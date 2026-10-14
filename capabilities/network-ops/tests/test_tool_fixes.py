"""Tests for network-ops tool fixes: nmap port quoting, certipy domain
handling, ntlmrelayx arg building, coercion command building, and
relay orchestration helpers."""

from __future__ import annotations

import importlib.util
import inspect
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: stub dreadnode + loguru so we can import the tool modules
# ---------------------------------------------------------------------------

_STUBS_INSTALLED = False


def _install_stubs():
    global _STUBS_INSTALLED
    if _STUBS_INSTALLED:
        return
    _STUBS_INSTALLED = True

    # dreadnode stubs — only create and populate modules that don't exist yet
    # to avoid clobbering a real dreadnode installation in the test env.
    _stub_modules: list[str] = []
    for mod_name in [
        "dreadnode",
        "dreadnode.agents",
        "dreadnode.agents.tools",
        "dreadnode.tools",
        "dreadnode.tools.execute",
        "dreadnode.app",
        "dreadnode.app.env",
    ]:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)
            _stub_modules.append(mod_name)

    # Config stub
    class Config:
        def __init__(self, **kwargs):
            self.default = kwargs.get("default")
            self.default_factory = kwargs.get("default_factory")

    if "dreadnode" in _stub_modules:
        sys.modules["dreadnode"].Config = Config  # type: ignore[attr-defined]

    # Toolset stub
    class Toolset:
        pass

    def tool_method(**kwargs):
        def decorator(func):
            return func

        return decorator

    if "dreadnode.agents.tools" in _stub_modules:
        sys.modules["dreadnode.agents.tools"].Toolset = Toolset  # type: ignore[attr-defined]
        sys.modules["dreadnode.agents.tools"].tool_method = tool_method  # type: ignore[attr-defined]

    # execute stub
    async def execute(cmd, **kwargs):
        return f"executed: {' '.join(cmd)}"

    if "dreadnode.tools.execute" in _stub_modules:
        sys.modules["dreadnode.tools.execute"].execute = execute  # type: ignore[attr-defined]

    # loguru stub
    if "loguru" not in sys.modules:
        try:
            import loguru as _real  # noqa: F401
        except ImportError:
            _loguru = types.ModuleType("loguru")

            class _StubLogger:
                def __getattr__(self, name):
                    return lambda *a, **kw: None

            _loguru.logger = _StubLogger()
            sys.modules["loguru"] = _loguru


_install_stubs()

# Now we can import the tool modules
TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"


def _load_module(name: str, filename: str):
    path = TOOLS_DIR / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nmap_mod = _load_module("nmap_tools", "nmap.py")
certipy_mod = _load_module("certipy_tools", "certipy.py")
impacket_mod = _load_module("impacket_tools", "impacket.py")
cracking_mod = _load_module("cracking_tools", "cracking.py")
bloodyad_mod = _load_module("bloodyad_tools", "bloodyad.py")


# ===================================================================
# Nmap: port quoting
# ===================================================================


class TestNmapPortQuoting:
    """nmap_service_scan should strip wrapping quotes from ports."""

    @pytest.mark.asyncio
    async def test_strips_double_quotes(self):
        """Agent sent ports='"80,1433"' — nmap choked on literal quotes."""
        nmap = nmap_mod.Nmap()
        nmap.timeout = 10

        with patch.object(nmap, "nmap", new_callable=AsyncMock) as mock_nmap:
            mock_nmap.return_value = "scan output"
            await nmap.nmap_service_scan(["10.0.0.1"], ports='"80,1433"')

            args = mock_nmap.call_args[0]  # (targets, args_list)
            # The -p flag value should NOT contain quotes
            arg_list = args[1]
            p_idx = arg_list.index("-p")
            assert arg_list[p_idx + 1] == "80,1433"

    @pytest.mark.asyncio
    async def test_strips_single_quotes(self):
        nmap = nmap_mod.Nmap()
        nmap.timeout = 10

        with patch.object(nmap, "nmap", new_callable=AsyncMock) as mock_nmap:
            mock_nmap.return_value = "scan output"
            await nmap.nmap_service_scan(["10.0.0.1"], ports="'22,80'")

            arg_list = mock_nmap.call_args[0][1]
            p_idx = arg_list.index("-p")
            assert arg_list[p_idx + 1] == "22,80"

    @pytest.mark.asyncio
    async def test_clean_ports_unchanged(self):
        nmap = nmap_mod.Nmap()
        nmap.timeout = 10

        with patch.object(nmap, "nmap", new_callable=AsyncMock) as mock_nmap:
            mock_nmap.return_value = "scan output"
            await nmap.nmap_service_scan(["10.0.0.1"], ports="80,443,8080")

            arg_list = mock_nmap.call_args[0][1]
            p_idx = arg_list.index("-p")
            assert arg_list[p_idx + 1] == "80,443,8080"


# ===================================================================
# Certipy: domain handling in base certipy() method
# ===================================================================


class TestCertipyDomainHandling:
    """certipy() should correctly build -u user@domain."""

    def _make_certipy(self):
        c = certipy_mod.Certipy()
        c.certipy_cmd = "certipy"
        c.timeout = 10
        return c

    @pytest.mark.asyncio
    async def test_username_and_domain_combined(self):
        """username='Admin', domain='corp.local' → -u Admin@corp.local"""
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy(
                action="find",
                args=["-vulnerable"],
                target="10.0.0.1",
                username="Admin",
                domain="corp.local",
            )
            cmd = mock_exec.call_args[0][0]
            assert "-u" in cmd
            u_idx = cmd.index("-u")
            assert cmd[u_idx + 1] == "Admin@corp.local"

    @pytest.mark.asyncio
    async def test_username_with_at_sign_no_double_domain(self):
        """username='Admin@corp.local', domain=None → -u Admin@corp.local (no doubling)"""
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy(
                action="find",
                args=[],
                target="10.0.0.1",
                username="Admin@corp.local",
            )
            cmd = mock_exec.call_args[0][0]
            u_idx = cmd.index("-u")
            assert cmd[u_idx + 1] == "Admin@corp.local"

    @pytest.mark.asyncio
    async def test_username_with_at_and_domain_no_double(self):
        """username='Admin@corp.local', domain='corp.local' → -u Admin@corp.local (not doubled)"""
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy(
                action="find",
                args=[],
                target="10.0.0.1",
                username="Admin@corp.local",
                domain="corp.local",
            )
            cmd = mock_exec.call_args[0][0]
            u_idx = cmd.index("-u")
            assert cmd[u_idx + 1] == "Admin@corp.local"

    @pytest.mark.asyncio
    async def test_no_username_no_u_flag(self):
        """No username → no -u flag at all."""
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy(action="find", args=[], target="10.0.0.1")
            cmd = mock_exec.call_args[0][0]
            assert "-u" not in cmd


# ===================================================================
# Certipy: certipy_find routes through certipy()
# ===================================================================


class TestCertipyFind:
    """certipy_find should use structured params, not raw args for auth."""

    def _make_certipy(self):
        c = certipy_mod.Certipy()
        c.certipy_cmd = "certipy"
        c.timeout = 10
        return c

    @pytest.mark.asyncio
    async def test_certipy_find_builds_auth_correctly(self):
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy_find(
                target="10.0.0.1",
                username="Administrator",
                domain="deltasystems.local",
                nt_hash="c56b4bc88c94f5b0db14acaaac702fc4",
                args=["-vulnerable", "-stdout"],
            )
            cmd = mock_exec.call_args[0][0]
            assert cmd[0] == "certipy"
            assert cmd[1] == "find"
            assert "-u" in cmd
            u_idx = cmd.index("-u")
            assert cmd[u_idx + 1] == "Administrator@deltasystems.local"
            assert "-hashes" in cmd
            assert "-dc-ip" in cmd
            dc_idx = cmd.index("-dc-ip")
            assert cmd[dc_idx + 1] == "10.0.0.1"
            assert "-vulnerable" in cmd
            assert "-stdout" in cmd
            # No -domain flag (the bug we're fixing)
            assert "-domain" not in cmd


# ===================================================================
# Impacket: _build_ntlmrelayx_args
# ===================================================================


class TestBuildNtlmrelayxArgs:
    """_build_ntlmrelayx_args should produce correct flag lists."""

    def _make_impacket(self):
        imp = impacket_mod.Impacket()
        imp.timeout = 30
        imp.script_path = Path("/fake/scripts")
        return imp

    def test_basic_adcs_relay(self):
        imp = self._make_impacket()
        args = imp._build_ntlmrelayx_args(
            target="http://ca/certsrv/certfnsh.asp",
            smb2support=True,
            interface_ip="10.0.0.1",
            adcs=True,
            template="DomainController",
        )
        assert ["-t", "http://ca/certsrv/certfnsh.asp"] == args[:2]
        assert "-smb2support" in args
        assert "-ip" in args
        assert "--adcs" in args
        assert "--template" in args
        t_idx = args.index("--template")
        assert args[t_idx + 1] == "DomainController"

    def test_ldap_relay_with_escalation(self):
        imp = self._make_impacket()
        args = imp._build_ntlmrelayx_args(
            target="ldap://dc01",
            smb2support=True,
            escalate_user="attacker",
            delegate_access=True,
        )
        assert "--escalate-user" in args
        assert "--delegate-access" in args

    def test_server_toggles(self):
        imp = self._make_impacket()
        args = imp._build_ntlmrelayx_args(
            target="smb://10.0.0.1",
            no_smb_server=True,
            no_http_server=True,
            no_wcf_server=True,
            no_raw_server=True,
        )
        assert "--no-smb-server" in args
        assert "--no-http-server" in args
        assert "--no-wcf-server" in args
        assert "--no-raw-server" in args

    def test_shadow_credentials(self):
        imp = self._make_impacket()
        args = imp._build_ntlmrelayx_args(
            target="ldap://dc01",
            shadow_credentials=True,
            shadow_target="victim$",
        )
        assert "--shadow-credentials" in args
        assert "--shadow-target" in args


# ===================================================================
# Impacket: _build_coercion_command
# ===================================================================


class TestBuildCoercionCommand:
    """_build_coercion_command should produce correct coercion commands."""

    def _make_impacket(self):
        imp = impacket_mod.Impacket()
        imp.timeout = 30
        imp.script_path = Path("/fake/scripts")
        return imp

    def test_unknown_method_raises(self):
        imp = self._make_impacket()
        with pytest.raises(ValueError, match="Unknown coercion method"):
            imp._build_coercion_command("bogus", "10.0.0.1", "10.0.0.2")

    def test_missing_script_raises(self):
        imp = self._make_impacket()
        with pytest.raises(FileNotFoundError, match="not found"):
            imp._build_coercion_command("petitpotam", "10.0.0.1", "10.0.0.2")

    def test_petitpotam_with_pipe(self, tmp_path):
        # Create fake script
        script = tmp_path / "PetitPotam.py"
        script.write_text("# fake")

        imp = self._make_impacket()
        with patch.dict(
            impacket_mod._COERCION_SCRIPTS,
            {
                "petitpotam": (
                    tmp_path,
                    "PetitPotam.py",
                    "https://github.com/topotam/PetitPotam",
                )
            },
        ):
            cmd = imp._build_coercion_command(
                "petitpotam",
                "10.0.0.1",
                "10.0.0.2",
                username="admin",
                domain="corp.local",
                hashes=":abc123",
                pipe="efsr",
            )

        assert cmd[0] == sys.executable
        assert str(script) in cmd[1]
        assert "-u" in cmd
        assert "-d" in cmd
        assert "-hashes" in cmd
        assert "-pipe" in cmd
        # Positional args at end
        assert cmd[-2] == "10.0.0.1"
        assert cmd[-1] == "10.0.0.2"

    def test_shadowcoerce_no_kerberos_no_dc_ip(self, tmp_path):
        script = tmp_path / "shadowcoerce.py"
        script.write_text("# fake")

        imp = self._make_impacket()
        with patch.dict(
            impacket_mod._COERCION_SCRIPTS,
            {
                "shadowcoerce": (
                    tmp_path,
                    "shadowcoerce.py",
                    "https://github.com/ShutdownRepo/ShadowCoerce",
                )
            },
        ):
            cmd = imp._build_coercion_command(
                "shadowcoerce",
                "10.0.0.1",
                "10.0.0.2",
                kerberos=True,  # should be ignored
                dc_ip="10.0.0.3",  # should be ignored
            )

        assert "-k" not in cmd
        assert "-dc-ip" not in cmd

    def test_auto_no_pass_when_no_creds(self, tmp_path):
        script = tmp_path / "PetitPotam.py"
        script.write_text("# fake")

        imp = self._make_impacket()
        with patch.dict(
            impacket_mod._COERCION_SCRIPTS,
            {
                "petitpotam": (
                    tmp_path,
                    "PetitPotam.py",
                    "https://github.com/topotam/PetitPotam",
                )
            },
        ):
            cmd = imp._build_coercion_command("petitpotam", "10.0.0.1", "10.0.0.2")

        assert "-no-pass" in cmd


# ===================================================================
# Relay helpers: _wait_for_relay_ready, _wait_for_relay_result
# ===================================================================


def _make_mock_process(lines: list[bytes], returncode: int | None = None):
    """Create a mock asyncio subprocess with predefined stdout lines."""
    line_iter = iter(lines)

    async def readline():
        try:
            return next(line_iter)
        except StopIteration:
            return b""

    proc = MagicMock()
    proc.stdout = MagicMock()
    proc.stdout.readline = readline
    proc.returncode = returncode
    proc.pid = 12345

    async def wait():
        proc.returncode = 0

    proc.wait = wait
    return proc


class TestWaitForRelayReady:
    @pytest.mark.asyncio
    async def test_detects_servers_started(self):
        proc = _make_mock_process(
            [
                b"Impacket v0.13.1\n",
                b"[*] Setting up SMB Server\n",
                b"[*] Servers started, waiting for connections\n",
            ]
        )
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_ready(proc, output, timeout=5)
        assert result is True
        assert len(output) == 3

    @pytest.mark.asyncio
    async def test_returns_false_on_early_exit(self):
        proc = _make_mock_process(
            [
                b"Error: something went wrong\n",
                b"",  # EOF
            ]
        )
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_ready(proc, output, timeout=5)
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_bind_error(self):
        proc = _make_mock_process(
            [
                b"Impacket v0.13.1\n",
                b"Error: Address already in use (bind failed)\n",
            ]
        )
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_ready(proc, output, timeout=5)
        assert result is False


class TestWaitForRelayResult:
    @pytest.mark.asyncio
    async def test_detects_certificate_success(self):
        proc = _make_mock_process(
            [
                b"[*] SMBD-Thread-4: Received connection from 10.0.0.5\n",
                b"[*] Authenticating against http://ca/certsrv\n",
                b"[*] Got certificate!\n",
                b"[*] Certificate: MIIFxz...\n",
            ]
        )
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_result(proc, output, timeout=5)
        assert result is True
        assert any("certificate" in line.lower() for line in output)

    @pytest.mark.asyncio
    async def test_returns_false_on_timeout(self):
        # No success patterns, just connection noise
        proc = _make_mock_process(
            [
                b"[*] SMBD-Thread-4: Connection from 10.0.0.5\n",
                b"",  # EOF
            ]
        )
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_result(proc, output, timeout=2)
        assert result is False


# ===================================================================
# Relay: _kill_relay
# ===================================================================


class TestKillRelay:
    @pytest.mark.asyncio
    async def test_noop_if_already_exited(self):
        proc = MagicMock()
        proc.returncode = 0
        # Should not raise
        await impacket_mod._kill_relay(proc)

    @pytest.mark.asyncio
    async def test_sends_sigterm_to_process_group(self):
        proc = MagicMock()
        proc.returncode = None
        proc.pid = 99999

        async def mock_wait():
            proc.returncode = -15

        proc.wait = mock_wait

        with (
            patch("os.getpgid", return_value=99999) as mock_getpgid,
            patch("os.killpg") as mock_killpg,
        ):
            await impacket_mod._kill_relay(proc)
            mock_getpgid.assert_called_once_with(99999)
            mock_killpg.assert_called()


# ===================================================================
# Cracking: hashcat no-backend detection
# ===================================================================


class TestHashcatNoBackendDetection:
    """hashcat should raise an actionable error when no GPU backend is available."""

    @pytest.mark.asyncio
    async def test_backend_error_suggests_john_with_known_mode(self, tmp_path):
        """CL_PLATFORM_NOT_FOUND_KHR should suggest john_the_ripper with mapped format."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("aad3b435b51404eeaad3b435b51404ee")
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("password\n")

        cracker = cracking_mod.Cracking()

        async def fake_execute(cmd, **kwargs):
            raise RuntimeError(
                "Command failed (255): clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR"
            )

        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            with pytest.raises(
                RuntimeError, match=r"Use john_the_ripper.*hash_format='nt'"
            ):
                await cracker.hashcat(
                    hashcat_mode=1000,
                    hash_file=str(hash_file),
                    wordlist_path=str(wordlist),
                )

    @pytest.mark.asyncio
    async def test_backend_error_chains_original_exception(self, tmp_path):
        """The original hashcat error should be preserved as __cause__."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("aad3b435b51404eeaad3b435b51404ee")
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("password\n")

        cracker = cracking_mod.Cracking()
        original = RuntimeError(
            "Command failed (255): clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR"
        )

        async def fake_execute(cmd, **kwargs):
            raise original

        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            with pytest.raises(RuntimeError) as exc_info:
                await cracker.hashcat(
                    hashcat_mode=1000,
                    hash_file=str(hash_file),
                    wordlist_path=str(wordlist),
                )
            assert exc_info.value.__cause__ is original

    @pytest.mark.asyncio
    async def test_non_backend_error_propagates_unchanged(self, tmp_path):
        """Errors unrelated to missing backends should propagate as-is."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("badhash")
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("password\n")

        cracker = cracking_mod.Cracking()

        async def fake_execute(cmd, **kwargs):
            raise RuntimeError("Command failed (1): Hash format mismatch")

        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            with pytest.raises(RuntimeError, match=r"Hash format mismatch"):
                await cracker.hashcat(
                    hashcat_mode=1000,
                    hash_file=str(hash_file),
                    wordlist_path=str(wordlist),
                )


# ===================================================================
# BloodyAD: _build_connection_options (pass-the-hash auth)
# ===================================================================


class TestBuildConnectionOptions:
    """A hash is supplied to bloodyAD through the password field (-p)."""

    def _make_bloodyad(self):
        return bloodyad_mod.BloodyAD()

    def _base_kwargs(self):
        return {"domain": "domain.local", "username": "alice", "host": "dc01"}

    def test_bare_nt_hash_uses_leading_colon_password(self):
        bad = self._make_bloodyad()
        cmd = bad._build_connection_options(
            **self._base_kwargs(),
            hashes="aad3b435b51404eeaad3b435b51404ee",
        )
        assert "--hashes" not in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == ":aad3b435b51404eeaad3b435b51404ee"

    def test_full_lm_nt_hash_passed_through_unchanged(self):
        bad = self._make_bloodyad()
        full = "aad3b435b51404eeaad3b435b51404ee:" "31d6cfe0d16ae931b73c59d7e0c089c0"
        cmd = bad._build_connection_options(**self._base_kwargs(), hashes=full)
        assert "--hashes" not in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == full

    def test_password_takes_precedence_over_hashes(self):
        bad = self._make_bloodyad()
        cmd = bad._build_connection_options(
            **self._base_kwargs(),
            password="Summer2026!",
            hashes="deadbeef",
        )
        assert "--hashes" not in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == "Summer2026!"
        # The hash must not also leak into the argv.
        assert "deadbeef" not in cmd
        assert ":deadbeef" not in cmd

    def test_no_hashes_flag_ever_emitted(self):
        bad = self._make_bloodyad()
        cmd = bad._build_connection_options(**self._base_kwargs(), hashes="deadbeef")
        assert "--hashes" not in cmd


# Every public bloodyad_* tool method must forward its `hashes` argument into
# the shared connection-options helper. Testing the helper alone would not
# catch a method that dropped `hashes=hashes` on its own call, so this walks
# the real tool surface.
_BLOODYAD_TOOL_METHODS = sorted(
    name
    for name, member in inspect.getmembers(
        bloodyad_mod.BloodyAD, inspect.iscoroutinefunction
    )
    if name.startswith("bloodyad_")
)

_CONNECTION_PARAMS = {"domain", "username", "host"}
_NT_HASH = "aad3b435b51404eeaad3b435b51404ee"


def _call_kwargs_for(method) -> dict:
    """Minimal kwargs to invoke a tool method on the hash-auth path: every
    required parameter gets a placeholder, and `hashes` carries a bare NT hash
    while `password` is left unset so the hash branch is taken."""
    kwargs: dict = {}
    for name, param in inspect.signature(method).parameters.items():
        if name == "self":
            continue
        if name == "hashes":
            kwargs[name] = _NT_HASH
        elif name in _CONNECTION_PARAMS:
            kwargs[name] = f"test-{name}"
        elif param.default is inspect.Parameter.empty:
            kwargs[name] = "test-value"
    return kwargs


class TestPublicMethodsForwardHashes:
    """The ticket's failure was a tool authenticating without its hash. Guard
    every public tool method, not just the shared helper."""

    def test_at_least_one_tool_method_discovered(self):
        # A rename/refactor that empties this list must fail loudly rather than
        # silently parametrizing over nothing and passing.
        assert len(_BLOODYAD_TOOL_METHODS) >= 20

    @pytest.mark.parametrize("method_name", _BLOODYAD_TOOL_METHODS)
    @pytest.mark.asyncio
    async def test_hash_reaches_argv(self, method_name):
        bad = bloodyad_mod.BloodyAD()
        bad.timeout = 30
        method = getattr(bad, method_name)

        captured = AsyncMock(return_value="ok")
        with patch.object(bloodyad_mod, "execute", captured):
            await method(**_call_kwargs_for(method))

        cmd = captured.call_args.args[0]
        assert "--hashes" not in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == f":{_NT_HASH}"


# ===================================================================
# Cracking: results survive hashcat's non-zero / time-boxed exits
# ===================================================================


def _split_execute(crack_error: BaseException, show_output: str):
    """Build an execute() side effect: the --show call returns `show_output`,
    every other (crack) call raises `crack_error`. Records the commands seen."""
    calls: list[list[str]] = []

    async def fake_execute(cmd, **kwargs):
        calls.append(cmd)
        if "--show" in cmd:
            return show_output
        raise crack_error

    return fake_execute, calls


class TestHashcatResultsSurviveNonZeroExit:
    """A time-boxed crack that exits non-zero must still return potfile results."""

    def _write_inputs(self, tmp_path):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("aad3b435b51404eeaad3b435b51404ee\n")
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("Password1\n")
        return hash_file, wordlist

    @pytest.mark.asyncio
    async def test_exhausted_exit_1_returns_recovered(self, tmp_path):
        """Exit 1 (exhausted keyspace) with a partial recovery returns the creds."""
        hash_file, wordlist = self._write_inputs(tmp_path)
        fake_execute, calls = _split_execute(
            RuntimeError("Command failed (1):\nStatus: Exhausted\nRecovered: 1/2"),
            "svc_sql:Password1",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            result = await cracking_mod.Cracking().hashcat(
                hashcat_mode=1000,
                hash_file=str(hash_file),
                wordlist_path=str(wordlist),
            )
        assert result == "svc_sql:Password1"
        assert any("--show" in cmd for cmd in calls)

    @pytest.mark.asyncio
    async def test_runtime_exit_4_returns_recovered(self, tmp_path):
        """Exit 4 (halted by --runtime, the real code on current hashcat) returns creds."""
        hash_file, wordlist = self._write_inputs(tmp_path)
        fake_execute, _ = _split_execute(
            RuntimeError("Command failed (4):\nStatus: Aborted (Runtime)"),
            "svc_sql:Password1",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            result = await cracking_mod.Cracking().hashcat(
                hashcat_mode=1000,
                hash_file=str(hash_file),
                wordlist_path=str(wordlist),
            )
        assert result == "svc_sql:Password1"

    @pytest.mark.asyncio
    async def test_aborted_exit_2_returns_recovered(self, tmp_path):
        """Exit 2 (aborted) still returns the creds."""
        hash_file, wordlist = self._write_inputs(tmp_path)
        fake_execute, _ = _split_execute(
            RuntimeError("Command failed (2):\nStatus: Aborted"),
            "svc_sql:Password1",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            result = await cracking_mod.Cracking().hashcat(
                hashcat_mode=1000,
                hash_file=str(hash_file),
                wordlist_path=str(wordlist),
            )
        assert result == "svc_sql:Password1"

    @pytest.mark.asyncio
    async def test_genuine_failure_surfaces_instead_of_empty(self, tmp_path):
        """A non-backend fatal exit (255) must surface as an error, not an empty
        '--show' result that reads as 'nothing cracked'."""
        hash_file, wordlist = self._write_inputs(tmp_path)
        # Crack fails for a real reason; --show would exit 0 with nothing to report.
        fake_execute, calls = _split_execute(
            RuntimeError("Command failed (255):\nCUDA API call failed (cuInit)"),
            "",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            with pytest.raises(RuntimeError, match=r"cuInit"):
                await cracking_mod.Cracking().hashcat(
                    hashcat_mode=1000,
                    hash_file=str(hash_file),
                    wordlist_path=str(wordlist),
                )
        assert not any("--show" in cmd for cmd in calls)

    @pytest.mark.asyncio
    async def test_error_without_parseable_code_surfaces(self, tmp_path):
        """An error whose text carries no exit code is treated as genuine and surfaced."""
        hash_file, wordlist = self._write_inputs(tmp_path)
        fake_execute, calls = _split_execute(
            RuntimeError("hashcat process died unexpectedly"),
            "",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            with pytest.raises(RuntimeError, match=r"died unexpectedly"):
                await cracking_mod.Cracking().hashcat(
                    hashcat_mode=1000,
                    hash_file=str(hash_file),
                    wordlist_path=str(wordlist),
                )
        assert not any("--show" in cmd for cmd in calls)

    @pytest.mark.asyncio
    async def test_timeout_kill_returns_recovered(self, tmp_path):
        """A timeout that kills hashcat still collects potfile results via --show."""
        hash_file, wordlist = self._write_inputs(tmp_path)
        fake_execute, _ = _split_execute(
            TimeoutError("Command 'hashcat ...' timed out after 150 seconds."),
            "svc_sql:Password1",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            result = await cracking_mod.Cracking().hashcat(
                hashcat_mode=1000,
                hash_file=str(hash_file),
                wordlist_path=str(wordlist),
            )
        assert result == "svc_sql:Password1"

    @pytest.mark.asyncio
    async def test_no_backend_short_circuits_before_show(self, tmp_path):
        """A missing GPU backend raises the john hint and never reaches --show."""
        hash_file, wordlist = self._write_inputs(tmp_path)
        fake_execute, calls = _split_execute(
            RuntimeError(
                "Command failed (255): clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR"
            ),
            "svc_sql:Password1",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            with pytest.raises(RuntimeError, match=r"Use john_the_ripper"):
                await cracking_mod.Cracking().hashcat(
                    hashcat_mode=1000,
                    hash_file=str(hash_file),
                    wordlist_path=str(wordlist),
                )
        assert not any("--show" in cmd for cmd in calls)


class TestJohnResultsSurviveNonCleanExit:
    """John is time-boxed by a timeout kill — results must survive that — but a
    non-zero john exit is a genuine failure and must surface."""

    def _write_inputs(self, tmp_path):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("$krb5asrep$23$user@REALM:abc...\n")
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("Password1\n")
        return hash_file, wordlist

    @pytest.mark.asyncio
    async def test_timeout_kill_returns_recovered(self, tmp_path):
        hash_file, wordlist = self._write_inputs(tmp_path)
        fake_execute, calls = _split_execute(
            TimeoutError("Command 'john ...' timed out after 630 seconds."),
            "user:Password1",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            result = await cracking_mod.Cracking().john_the_ripper(
                hash_format="krb5asrep",
                hash_file=str(hash_file),
                wordlist_path=str(wordlist),
            )
        assert result == "user:Password1"
        assert any("--show" in cmd for cmd in calls)

    @pytest.mark.asyncio
    async def test_nonzero_exit_surfaces_instead_of_empty(self, tmp_path):
        """A john failure (e.g. unknown format) surfaces rather than returning an
        empty, successful-looking result."""
        hash_file, wordlist = self._write_inputs(tmp_path)
        fake_execute, calls = _split_execute(
            RuntimeError("Command failed (1):\nUnknown ciphertext format name"),
            "",
        )
        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            with pytest.raises(RuntimeError, match=r"Unknown ciphertext format"):
                await cracking_mod.Cracking().john_the_ripper(
                    hash_format="krb5asrep",
                    hash_file=str(hash_file),
                    wordlist_path=str(wordlist),
                )
        assert not any("--show" in cmd for cmd in calls)
