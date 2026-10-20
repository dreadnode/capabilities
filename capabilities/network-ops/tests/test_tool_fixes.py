"""Tests for network-ops tool fixes: nmap port quoting, certipy domain
handling, ntlmrelayx arg building, coercion command building, and
relay orchestration helpers."""

from __future__ import annotations

import asyncio
import importlib.machinery
import importlib.util
import inspect
import signal
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

# Register a synthetic package rooted at the tools dir so the tool modules'
# intra-package imports (e.g. ``from ._relay import ...``) resolve the same way
# they do when the capability loader imports them as a package at runtime.
_PKG = "netops_tools"
if _PKG not in sys.modules:
    _spec = importlib.machinery.ModuleSpec(_PKG, loader=None, is_package=True)
    _spec.submodule_search_locations = [str(TOOLS_DIR)]
    sys.modules[_PKG] = importlib.util.module_from_spec(_spec)


def _load_module(name: str, filename: str):
    mod_name = f"{_PKG}.{name}"
    path = TOOLS_DIR / filename
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


nmap_mod = _load_module("nmap", "nmap.py")
certipy_mod = _load_module("certipy", "certipy.py")
impacket_mod = _load_module("impacket", "impacket.py")
cracking_mod = _load_module("cracking", "cracking.py")
bloodyad_mod = _load_module("bloodyad", "bloodyad.py")
krbrelayx_mod = _load_module("krbrelayx", "krbrelayx.py")
netexec_mod = _load_module("netexec", "netexec.py")
coercion_mod = _load_module("coercion", "coercion.py")
smbclient_mod = _load_module("smbclient", "smbclient.py")
# The tool modules above import ``._relay`` relatively, so it is already loaded
# under the package; reuse that instance rather than loading a second copy.
relay_mod = sys.modules.get(f"{_PKG}._relay") or _load_module("_relay", "_relay.py")


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
                dc_ip="10.0.0.1",
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
                dc_ip="10.0.0.1",
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
                dc_ip="10.0.0.1",
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
            await c.certipy(action="find", args=[], dc_ip="10.0.0.1")
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
                dc_ip="10.0.0.1",
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
# Certipy: uniform, hang-safe stdin confirmation across the toolset
# ===================================================================


class TestCertipyConfirmInput:
    """Every certipy_* tool should auto-confirm interactive prompts by default
    and close stdin, so no sibling tool can hang on a prompt until timeout, and
    an explicit `input` always overrides."""

    # Assert the literal "y" the subprocess must receive, not Certipy._CONFIRM_INPUT:
    # comparing to the module constant would stay green if someone set it to "" or
    # None, which (via execute()'s `if proc.stdin and input:` guard) would stop
    # closing stdin and reintroduce the very prompt-hang these tests guard against.
    CONFIRM = "y"

    def _make_certipy(self):
        c = certipy_mod.Certipy()
        c.certipy_cmd = "certipy"
        c.timeout = 10
        return c

    def _input_kwarg(self, mock_exec):
        """Extract the `input` passed to execute, positional or keyword."""
        assert mock_exec.await_count == 1
        return mock_exec.call_args.kwargs["input"]

    @pytest.mark.asyncio
    async def test_direct_generic_tools_default_to_confirm(self):
        """account/auth/ca/cert/req/template send the confirm default to stdin
        when no input is given (none inherit the parent's stdin)."""
        for method in [
            "certipy_account",
            "certipy_auth",
            "certipy_ca",
            "certipy_cert",
            "certipy_req",
            "certipy_template",
        ]:
            c = self._make_certipy()
            with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
                mock_exec.return_value = "output"
                await getattr(c, method)(args=[])
                assert self._input_kwarg(mock_exec) == self.CONFIRM, f"{method} should auto-confirm by default"

    @pytest.mark.asyncio
    async def test_passthrough_and_find_default_to_confirm(self):
        """The generic passthrough and certipy_find route through certipy() and
        inherit the same confirm default."""
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy(action="find", args=[], dc_ip="10.0.0.1")
            assert self._input_kwarg(mock_exec) == self.CONFIRM

        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy_find(dc_ip="10.0.0.1")
            assert self._input_kwarg(mock_exec) == self.CONFIRM

    @pytest.mark.asyncio
    async def test_relay_does_not_receive_confirm_stdin(self):
        """The relay action is a streaming listener that never reads stdin; the
        confirm default must not leak into it (it bypasses execute())."""
        c = self._make_certipy()
        with (
            patch.object(certipy_mod, "stream_listener", new_callable=AsyncMock) as mock_relay,
            patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec,
        ):
            mock_relay.return_value = "output"
            await c.certipy(action="relay", args=["-target", "http://ca"], dc_ip="1.2.3.4")
            mock_exec.assert_not_awaited()
            mock_relay.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_high_level_tools_default_to_confirm(self):
        """The high-level helpers no longer hardcode stdin; they inherit the
        uniform confirm default via certipy()."""
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy_request_certificate(
                dc_ip="10.0.0.1",
                ca_server="ca.corp.local",
                ca_name="corp-CA",
                template="User",
                username="Admin",
                domain="corp.local",
            )
            assert self._input_kwarg(mock_exec) == self.CONFIRM

        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy_certificate_auth(pfx_file="admin.pfx", dc_ip="10.0.0.1")
            assert self._input_kwarg(mock_exec) == self.CONFIRM

    @pytest.mark.asyncio
    async def test_explicit_input_overrides_default(self):
        """A caller-supplied non-empty input is passed through unchanged."""
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy_cert(args=["-export"], input="n")
            assert self._input_kwarg(mock_exec) == "n"

    @pytest.mark.asyncio
    async def test_empty_input_still_confirms(self):
        """An empty string falls back to the confirm default rather than being
        forwarded as-is. This is deliberate: execute() only closes stdin when the
        input is truthy, so forwarding "" would leave stdin open and reintroduce
        the prompt-hang. Callers decline by sending an explicit answer (e.g. "n"),
        not an empty string."""
        c = self._make_certipy()
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy_cert(args=["-export"], input="")
            assert self._input_kwarg(mock_exec) == self.CONFIRM


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
                nt_hash=":abc123",
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


def _make_mock_process(lines: list[bytes], returncode: int | None = None, exit_code: int = 0):
    """Create a mock asyncio subprocess with predefined stdout lines.

    ``returncode`` is the process's state before it is awaited; ``exit_code`` is
    what ``wait()`` resolves it to, letting a test model a clean (0) or failing
    (non-zero) exit after stdout closes.
    """
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
        proc.returncode = exit_code

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
        result = await impacket_mod._wait_for_relay_result(
            proc, output, impacket_mod.NTLMRELAYX_SUCCESS_PATTERNS, timeout=5
        )
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
        result = await impacket_mod._wait_for_relay_result(
            proc, output, impacket_mod.NTLMRELAYX_SUCCESS_PATTERNS, timeout=2
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_krbrelayx_failed_auth_is_not_success(self):
        # krbrelayx logs "Authenticating against ... SUCCEED" and "... FAILED".
        # The patterns must fire on the real capture lines, not on FAILED.
        failed = _make_mock_process(
            [
                b"[*] SMBD: Received connection from 10.0.0.5\n",
                b"[-] Authenticating against smb://dc as CORP\\u FAILED\n",
                b"",
            ]
        )
        out1: list[str] = []
        assert (
            await relay_mod.wait_for_relay_result(failed, out1, krbrelayx_mod._KRBRELAYX_SUCCESS_PATTERNS, timeout=2)
            is False
        )

        caught = _make_mock_process(
            [
                b"[*] SMBD: Received connection from 10.0.0.5\n",
                b"[*] Got ticket for admin@CORP.LOCAL [2]\n",
                b"",
            ]
        )
        out2: list[str] = []
        assert (
            await relay_mod.wait_for_relay_result(caught, out2, krbrelayx_mod._KRBRELAYX_SUCCESS_PATTERNS, timeout=2)
            is True
        )


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

    @pytest.mark.asyncio
    async def test_escalates_to_sigkill_when_sigterm_ignored(self):
        # A relay that ignores SIGTERM (ntlmrelayx with live connections does)
        # must be escalated to SIGKILL, not leaked holding ports 445/80.
        proc = MagicMock()
        proc.returncode = None
        proc.pid = 99999
        calls = {"n": 0}

        async def mock_wait():
            calls["n"] += 1
            if calls["n"] == 1:
                await asyncio.sleep(1)  # outlast the (patched) SIGKILL timeout
            proc.returncode = -9

        proc.wait = mock_wait

        with (
            patch.object(relay_mod, "_SIGKILL_TIMEOUT", 0.05),
            patch("os.getpgid", return_value=99999),
            patch("os.killpg") as mock_killpg,
        ):
            await impacket_mod._kill_relay(proc)
            # SIGTERM first, then SIGKILL after the wait timed out.
            assert mock_killpg.call_count == 2
            assert mock_killpg.call_args_list[-1].args[1] == signal.SIGKILL


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
            raise RuntimeError("Command failed (255): clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR")

        with patch.object(cracking_mod, "execute", side_effect=fake_execute):
            with pytest.raises(RuntimeError, match=r"Use john_the_ripper.*hash_format='nt'"):
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
        original = RuntimeError("Command failed (255): clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR")

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
        return {"domain": "domain.local", "username": "alice", "dc_ip": "dc01"}

    def test_bare_nt_hash_uses_leading_colon_password(self):
        bad = self._make_bloodyad()
        cmd = bad._build_connection_options(
            **self._base_kwargs(),
            nt_hash="aad3b435b51404eeaad3b435b51404ee",
        )
        assert "--hashes" not in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == ":aad3b435b51404eeaad3b435b51404ee"

    def test_full_lm_nt_hash_passed_through_unchanged(self):
        bad = self._make_bloodyad()
        full = "aad3b435b51404eeaad3b435b51404ee:" "31d6cfe0d16ae931b73c59d7e0c089c0"
        cmd = bad._build_connection_options(**self._base_kwargs(), nt_hash=full)
        assert "--hashes" not in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == full

    def test_password_takes_precedence_over_hashes(self):
        bad = self._make_bloodyad()
        cmd = bad._build_connection_options(
            **self._base_kwargs(),
            password="Summer2026!",
            nt_hash="deadbeef",
        )
        assert "--hashes" not in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == "Summer2026!"
        # The hash must not also leak into the argv.
        assert "deadbeef" not in cmd
        assert ":deadbeef" not in cmd

    def test_no_hashes_flag_ever_emitted(self):
        bad = self._make_bloodyad()
        cmd = bad._build_connection_options(**self._base_kwargs(), nt_hash="deadbeef")
        assert "--hashes" not in cmd


# Every public bloodyad_* tool method must forward its `hashes` argument into
# the shared connection-options helper. Testing the helper alone would not
# catch a method that dropped `hashes=hashes` on its own call, so this walks
# the real tool surface.
_BLOODYAD_TOOL_METHODS = sorted(
    name
    for name, member in inspect.getmembers(bloodyad_mod.BloodyAD, inspect.iscoroutinefunction)
    if name.startswith("bloodyad_")
)

_CONNECTION_PARAMS = {"domain", "username", "dc_ip"}
_NT_HASH = "aad3b435b51404eeaad3b435b51404ee"


def _call_kwargs_for(method) -> dict:
    """Minimal kwargs to invoke a tool method on the hash-auth path: every
    required parameter gets a placeholder, and `hashes` carries a bare NT hash
    while `password` is left unset so the hash branch is taken."""
    kwargs: dict = {}
    for name, param in inspect.signature(method).parameters.items():
        if name == "self":
            continue
        if name == "nt_hash":
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
            RuntimeError("Command failed (255): clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR"),
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


# ===================================================================
# Netexec: null-session / empty-credential argv construction
# ===================================================================


class TestNetexecNullSession:
    """The base netexec() builder must distinguish None (omit the flag) from
    "" (emit the explicit `-u ''` / `-p ''` null-session form)."""

    def _make_netexec(self):
        nx = netexec_mod.Netexec()
        nx.timeout = 60
        nx.variant = "all"
        return nx

    @pytest.mark.asyncio
    async def test_empty_strings_emit_null_session(self):
        """username="" and password="" → `-u '' -p ''`, the anonymous null session."""
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], args=["--shares"], username="", password="")
            cmd = mock_exec.call_args[0][0]
            assert "-u" in cmd and "-p" in cmd
            assert cmd[cmd.index("-u") + 1] == ""
            assert cmd[cmd.index("-p") + 1] == ""

    @pytest.mark.asyncio
    async def test_none_omits_flags(self):
        """username=None / password=None → no auth flags at all."""
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], args=["--shares"])
            cmd = mock_exec.call_args[0][0]
            assert "-u" not in cmd
            assert "-p" not in cmd

    @pytest.mark.asyncio
    async def test_populated_credentials_unchanged(self):
        """Non-empty credentials still build `-u user -p pass` (regression)."""
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], args=[], username="admin", password="Passw0rd")
            cmd = mock_exec.call_args[0][0]
            assert cmd[cmd.index("-u") + 1] == "admin"
            assert cmd[cmd.index("-p") + 1] == "Passw0rd"

    @pytest.mark.asyncio
    async def test_username_with_empty_password(self):
        """AS-REP-roast style: a real username with password="" → `-u svc -p ''`."""
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("ldap", ["dc.corp.local"], args=[], username="svc", password="")
            cmd = mock_exec.call_args[0][0]
            assert cmd[cmd.index("-u") + 1] == "svc"
            assert cmd[cmd.index("-p") + 1] == ""

    @pytest.mark.asyncio
    async def test_multi_value_lists_expand(self):
        """A list of usernames/passwords expands to repeated values after each flag."""
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec(
                "smb",
                ["10.0.0.1"],
                args=[],
                username=["u1", "u2"],
                password=["p1", "p2"],
            )
            cmd = mock_exec.call_args[0][0]
            u_idx = cmd.index("-u")
            assert cmd[u_idx + 1 : u_idx + 3] == ["u1", "u2"]
            p_idx = cmd.index("-p")
            assert cmd[p_idx + 1 : p_idx + 3] == ["p1", "p2"]

    @pytest.mark.asyncio
    async def test_empty_list_omits_flag(self):
        """An empty list is "no value supplied", not a null session — no dangling `-u`."""
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], args=["--shares"], username=[])
            cmd = mock_exec.call_args[0][0]
            assert "-u" not in cmd

    @pytest.mark.asyncio
    async def test_enum_shares_wrapper_passes_null_session(self):
        """The specialized wrapper threads "" through to the null-session form."""
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec_smb_enum_shares(["10.0.0.1"], username="", password="")
            cmd = mock_exec.call_args[0][0]
            assert cmd[cmd.index("-u") + 1] == ""
            assert cmd[cmd.index("-p") + 1] == ""
            assert "--shares" in cmd


# ===================================================================
# Shared relay listener: stream_listener
#
# Relay/coercion tools are listeners, not one-shot commands. stream_listener
# must stream their output, return early on a success line, and — crucially —
# return the captured output rather than raising when it reaches the timeout
# without catching an auth. A listener that caught nothing produced no result;
# that is a normal outcome, not a failed tool call.
# ===================================================================


class TestStreamListener:
    @pytest.mark.asyncio
    async def test_returns_output_on_success(self):
        proc = _make_mock_process(
            [
                b"[*] Servers started, waiting for connections\n",
                b"[*] Got certificate!\n",
                b"",
            ]
        )
        with (
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("os.getpgid", return_value=12345),
            patch("os.killpg"),
        ):
            out = await relay_mod.stream_listener(
                ["ntlmrelayx.py"],
                success_patterns=["got certificate"],
                timeout=5,
            )
        assert "Got certificate" in out
        assert "No success indicator" not in out

    @pytest.mark.asyncio
    async def test_success_drain_captures_followup_loot(self):
        # The certificate / hashes land on the line *after* the success marker;
        # the drain must capture that loot, not just the marker line.
        proc = _make_mock_process(
            [
                b"[*] Got certificate!\n",
                b"[*] Certificate: MIIFxyz-LOOT-VALUE\n",
                b"",
            ]
        )
        with (
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("os.getpgid", return_value=12345),
            patch("os.killpg"),
        ):
            out = await relay_mod.stream_listener(["ntlmrelayx.py"], success_patterns=["got certificate"], timeout=5)
        assert "MIIFxyz-LOOT-VALUE" in out

    @pytest.mark.asyncio
    async def test_clean_early_exit_returns_note_without_raising(self):
        # Process exits 0 without catching anything: a result, not an error.
        proc = _make_mock_process([b"[*] Servers started, waiting for connections\n", b""], exit_code=0)
        with (
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("os.getpgid", return_value=12345),
            patch("os.killpg"),
        ):
            out = await relay_mod.stream_listener(["ntlmrelayx.py"], success_patterns=["got certificate"], timeout=5)
        assert "Servers started" in out
        assert "exited without capturing" in out

    @pytest.mark.asyncio
    async def test_nonzero_early_exit_raises(self):
        # A crash / misconfiguration (non-zero exit before the deadline) must
        # surface as a tool-call error, not a success-shaped "nothing caught".
        proc = _make_mock_process([b"[-] Address already in use\n", b""], exit_code=1)
        with (
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("os.getpgid", return_value=12345),
            patch("os.killpg"),
        ):
            with pytest.raises(RuntimeError, match=r"exited with code 1"):
                await relay_mod.stream_listener(["ntlmrelayx.py"], success_patterns=["got certificate"], timeout=5)

    @pytest.mark.asyncio
    async def test_real_timeout_returns_note_and_terminates(self):
        # End-to-end against a real subprocess that prints a line then blocks
        # past the timeout: verifies the actual timeout + process-group kill
        # path (not just mocked EOF), and that it returns rather than raises.
        script = "import time, sys; print('listener up', flush=True); time.sleep(30)"
        out = await relay_mod.stream_listener(
            [sys.executable, "-c", script],
            success_patterns=["NEVER-MATCHES"],
            timeout=1,
        )
        assert "listener up" in out
        assert "No authentication captured within 1s" in out


class TestCertipyRelayRouting:
    """certipy(action='relay') is a listener; every other action is one-shot."""

    def _make_certipy(self):
        inst = certipy_mod.Certipy()
        inst.certipy_cmd = "certipy"
        inst.timeout = 20
        inst.relay_timeout = 7
        return inst

    @pytest.mark.asyncio
    async def test_relay_action_streams_with_relay_timeout(self):
        inst = self._make_certipy()
        captured: dict = {}

        async def fake_stream(cmd, **kwargs):
            captured["cmd"] = cmd
            captured.update(kwargs)
            return "relayed"

        async def fake_execute(*args, **kwargs):
            raise AssertionError("execute must not be called for the relay action")

        with (
            patch.object(certipy_mod, "stream_listener", side_effect=fake_stream),
            patch.object(certipy_mod, "execute", side_effect=fake_execute),
        ):
            out = await inst.certipy(action="relay", args=["-target", "http://ca"], dc_ip="1.2.3.4")

        assert out == "relayed"
        assert captured["timeout"] == 7
        assert captured["success_patterns"] is certipy_mod._CERTIPY_RELAY_SUCCESS_PATTERNS

    @pytest.mark.asyncio
    async def test_non_relay_action_uses_execute(self):
        inst = self._make_certipy()

        async def fake_execute(cmd, **kwargs):
            return "executed"

        async def fake_stream(*args, **kwargs):
            raise AssertionError("stream_listener must not be called for non-relay")

        with (
            patch.object(certipy_mod, "execute", side_effect=fake_execute),
            patch.object(certipy_mod, "stream_listener", side_effect=fake_stream),
        ):
            out = await inst.certipy(action="find", args=["-enabled"], dc_ip="1.2.3.4")

        assert out == "executed"


class TestKrbrelayxRelayRouting:
    """krbrelayx_relay is a listener and must stream with its relay_timeout."""

    @pytest.mark.asyncio
    async def test_relay_streams_with_relay_timeout(self):
        inst = krbrelayx_mod.Krbrelayx()
        inst.script_path = Path("/opt/krbrelayx")
        inst.timeout = 30
        captured: dict = {}

        async def fake_stream(cmd, **kwargs):
            captured["cmd"] = cmd
            captured.update(kwargs)
            return "ok"

        with patch.object(krbrelayx_mod, "stream_listener", side_effect=fake_stream):
            out = await inst.krbrelayx_relay(target="host/victim.corp.local", clsid="abc", relay_timeout=42)

        assert out == "ok"
        assert captured["timeout"] == 42
        assert captured["success_patterns"] is krbrelayx_mod._KRBRELAYX_SUCCESS_PATTERNS
        assert str(Path("/opt/krbrelayx") / "krbrelayx.py") in captured["cmd"]


class TestImpacketNtlmrelayxRouting:
    """The standalone impacket_ntlmrelayx listener must stream, not block-execute."""

    @pytest.mark.asyncio
    async def test_standalone_relay_streams_with_relay_timeout(self):
        inst = impacket_mod.Impacket()
        captured: dict = {}

        async def fake_stream(cmd, **kwargs):
            captured["cmd"] = cmd
            captured.update(kwargs)
            return "ok"

        with (
            patch.object(inst, "_build_ntlmrelayx_args", return_value=["-t", "smb://x"]),
            patch.object(
                inst,
                "_build_script_command",
                return_value=["python", "ntlmrelayx.py", "-t", "smb://x"],
            ),
            patch.object(impacket_mod, "stream_listener", side_effect=fake_stream),
        ):
            out = await inst.impacket_ntlmrelayx(target="smb://x", relay_timeout=55)

        assert out == "ok"
        assert captured["timeout"] == 55
        assert captured["success_patterns"] is impacket_mod.NTLMRELAYX_SUCCESS_PATTERNS


class TestRelayRedactionAndCap:
    def test_redact_cmd_masks_credentials(self):
        cmd = [
            "certipy",
            "relay",
            "-u",
            "bob",
            "-p",
            "S3cret!",
            "-hashes",
            ":abcd",
            "--aeskey",
            "AESKEY",
            "-dc-ip",
            "1.2.3.4",
        ]
        red = relay_mod._redact_cmd(cmd)
        joined = " ".join(red)
        assert "S3cret!" not in joined
        assert ":abcd" not in joined
        assert "AESKEY" not in joined
        assert red.count("***") == 3
        # Non-secret args are preserved.
        assert "bob" in red
        assert "1.2.3.4" in red

    @pytest.mark.asyncio
    async def test_output_is_capped(self):
        lines = [b"X" * 500 + b"\n"] * 10 + [b""]  # ~5 KB of output
        proc = _make_mock_process(lines, exit_code=0)
        with (
            patch.object(relay_mod, "_MAX_OUTPUT_BYTES", 1000),
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("os.getpgid", return_value=12345),
            patch("os.killpg"),
        ):
            out = await relay_mod.stream_listener(["x"], success_patterns=["nomatch"], timeout=5)
        assert "Output truncated at 1000 bytes" in out
        # Retained output stays bounded near the cap, not the full ~5 KB.
        assert len(out) < 2000


# ===================================================================
# Netexec: explicit Kerberos params (no AES-key-vs-ccache length guess)
# ===================================================================


class TestNetexecKerberos:
    """netexec routes Kerberos auth by explicit parameter.

    aes_key maps to --aesKey; ccache maps to --use-kcache with KRB5CCNAME; the
    two are mutually exclusive; kerberos alone adds -k. Routing is by parameter,
    independent of the value's length.
    """

    def _make_netexec(self):
        nx = netexec_mod.Netexec()
        nx.timeout = 60
        nx.variant = "all"
        return nx

    @pytest.mark.asyncio
    async def test_64_char_ccache_path_uses_kcache_not_aeskey(self):
        nx = self._make_netexec()
        # A 64-character ccache path must route by its parameter, not its length.
        ccache_path = "/tmp/" + "a" * 59
        assert len(ccache_path) == 64
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], [], ccache=ccache_path)
        cmd = mock_exec.call_args[0][0]
        env = mock_exec.call_args[1].get("env")
        assert "-k" in cmd
        assert "--use-kcache" in cmd
        assert "--aesKey" not in cmd
        assert env == {"KRB5CCNAME": ccache_path}

    @pytest.mark.asyncio
    async def test_aes_key_uses_aeskey_flag(self):
        nx = self._make_netexec()
        aes_key = "a" * 64
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], [], aes_key=aes_key)
        cmd = mock_exec.call_args[0][0]
        env = mock_exec.call_args[1].get("env")
        assert "-k" in cmd
        assert cmd[cmd.index("--aesKey") + 1] == aes_key
        assert "--use-kcache" not in cmd
        assert env is None

    @pytest.mark.asyncio
    async def test_non_standard_length_aes_key_still_aeskey(self):
        """An AES key of any length routes to --aesKey by its parameter."""
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], [], aes_key="deadbeef")
        cmd = mock_exec.call_args[0][0]
        assert "--aesKey" in cmd
        assert "--use-kcache" not in cmd

    @pytest.mark.asyncio
    async def test_kerberos_bool_only(self):
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], [], kerberos=True)
        cmd = mock_exec.call_args[0][0]
        env = mock_exec.call_args[1].get("env")
        assert "-k" in cmd
        assert "--aesKey" not in cmd
        assert "--use-kcache" not in cmd
        assert env is None

    @pytest.mark.asyncio
    async def test_aes_key_and_ccache_conflict_raises(self):
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock):
            with pytest.raises(ValueError, match="only one of aes_key or ccache"):
                await nx.netexec("smb", ["10.0.0.1"], [], aes_key="a" * 32, ccache="/tmp/ccache")

    @pytest.mark.asyncio
    async def test_nt_hash_routes_to_H_flag(self):
        nx = self._make_netexec()
        nt_hash = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await nx.netexec("smb", ["10.0.0.1"], [], nt_hash=nt_hash)
        cmd = mock_exec.call_args[0][0]
        assert cmd[cmd.index("-H") + 1] == nt_hash


# Every kerberos-bearing netexec wrapper re-forwards aes_key/ccache by hand; a
# copy-paste that dropped one would silently discard the credential.
_NETEXEC_WRAPPERS = [
    lambda n, **kw: n.netexec_smb_enum(["10.0.0.1"], **kw),
    lambda n, **kw: n.netexec_smb_auth(["10.0.0.1"], "admin", **kw),
    lambda n, **kw: n.netexec_smb_enum_group_members(["10.0.0.1"], ["Domain Admins"], **kw),
    lambda n, **kw: n.netexec_smb_enum_shares(["10.0.0.1"], **kw),
    lambda n, **kw: n.netexec_ldap_enum(["10.0.0.1"], **kw),
    lambda n, **kw: n.netexec_ldap_auth(["10.0.0.1"], **kw),
    lambda n, **kw: n.netexec_ldap_enum_group_members(["10.0.0.1"], ["Domain Admins"], **kw),
    lambda n, **kw: n.netexec_smb(["10.0.0.1"], **kw),
    lambda n, **kw: n.netexec_ldap(["10.0.0.1"], **kw),
    lambda n, **kw: n.netexec_mssql(["10.0.0.1"], **kw),
    lambda n, **kw: n.netexec_wmi(["10.0.0.1"], **kw),
]


class TestNetexecWrapperForwarding:
    def _make_netexec(self):
        nx = netexec_mod.Netexec()
        nx.timeout = 60
        nx.variant = "all"
        return nx

    @pytest.mark.parametrize("call", _NETEXEC_WRAPPERS)
    @pytest.mark.asyncio
    async def test_wrapper_forwards_aes_key(self, call):
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await call(nx, aes_key="a" * 32)
        assert "--aesKey" in mock_exec.call_args[0][0]

    @pytest.mark.parametrize("call", _NETEXEC_WRAPPERS)
    @pytest.mark.asyncio
    async def test_wrapper_forwards_ccache(self, call):
        nx = self._make_netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await call(nx, ccache="/tmp/krb5cc")
        assert "--use-kcache" in mock_exec.call_args[0][0]


# ===================================================================
# Certipy: nt_hash accepts the family-wide LMHASH:NTHASH format
# ===================================================================


class TestCertipyHashFormat:
    def _make_certipy(self):
        c = certipy_mod.Certipy()
        c.certipy_cmd = "certipy"
        c.timeout = 10
        return c

    @pytest.mark.asyncio
    async def test_full_lmhash_nthash_passed_verbatim(self):
        c = self._make_certipy()
        full = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy_find(dc_ip="10.0.0.1", username="u", domain="d", nt_hash=full)
        cmd = mock_exec.call_args[0][0]
        assert cmd[cmd.index("-hashes") + 1] == full

    @pytest.mark.asyncio
    async def test_bare_nt_hash_gets_empty_lm_half(self):
        c = self._make_certipy()
        nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "output"
            await c.certipy_find(dc_ip="10.0.0.1", username="u", domain="d", nt_hash=nt)
        cmd = mock_exec.call_args[0][0]
        assert cmd[cmd.index("-hashes") + 1] == f":{nt}"


# ===================================================================
# Auth parameter naming consistency across the tool family
# ===================================================================


class TestAuthParamNaming:
    """Sibling tools share one auth vocabulary: nt_hash + kerberos, never
    hash / hashes / use_kerberos / host."""

    _AUTH_TOOLSETS = [
        (netexec_mod, "Netexec"),
        (impacket_mod, "Impacket"),
        (bloodyad_mod, "BloodyAD"),
        (krbrelayx_mod, "Krbrelayx"),
        (coercion_mod, "Coercion"),
        (certipy_mod, "Certipy"),
    ]
    _BANNED = ("hash", "hashes", "use_kerberos", "host")

    def test_no_legacy_auth_param_names_in_any_method(self):
        offenders: list[str] = []
        for mod, cls_name in self._AUTH_TOOLSETS:
            cls = getattr(mod, cls_name)
            for name in dir(cls):
                if name.startswith("_"):
                    continue
                attr = getattr(cls, name)
                if not callable(attr):
                    continue
                try:
                    params = inspect.signature(attr).parameters
                except (TypeError, ValueError):
                    continue
                offenders.extend(f"{cls_name}.{name}({banned})" for banned in self._BANNED if banned in params)
        assert not offenders, f"legacy auth param names remain: {offenders}"

    def test_netexec_kerberos_is_bool_with_aes_key_and_ccache(self):
        params = inspect.signature(netexec_mod.Netexec.netexec).parameters
        assert params["kerberos"].default is False
        assert "aes_key" in params
        assert "ccache" in params

    def test_certipy_uses_dc_ip_not_target(self):
        params = inspect.signature(certipy_mod.Certipy.certipy).parameters
        assert "dc_ip" in params
        assert "target" not in params


# ===================================================================
# Credential redaction: secrets= threaded into execute()
# ===================================================================


def _secrets_of(mock_exec):
    """The secrets= list passed to a patched execute()."""
    return mock_exec.call_args.kwargs.get("secrets")


class TestCredentialRedaction:
    """Spot-checks that each threading style carries the credential into
    execute(secrets=...): named auth params, a list-valued param, an opaque
    arg list (flag recovery), and embedded operation secrets."""

    @pytest.mark.asyncio
    async def test_bloodyad_password_and_nt_hash_threaded(self):
        bad = bloodyad_mod.BloodyAD()
        with patch.object(bloodyad_mod, "execute", new_callable=AsyncMock) as mock_exec:
            await bad.bloodyad_get_object(
                "CN=alice", domain="corp.local", username="alice", dc_ip="dc01", password="hunter2"
            )
            assert "hunter2" in _secrets_of(mock_exec)
        with patch.object(bloodyad_mod, "execute", new_callable=AsyncMock) as mock_exec:
            await bad.bloodyad_get_object(
                "CN=alice", domain="corp.local", username="alice", dc_ip="dc01", nt_hash="aad3b:5f4"
            )
            assert "aad3b:5f4" in _secrets_of(mock_exec)

    @pytest.mark.asyncio
    async def test_netexec_named_and_args_embedded_secrets(self):
        nxc = netexec_mod.Netexec()
        with patch.object(netexec_mod, "execute", new_callable=AsyncMock) as mock_exec:
            await nxc.netexec(
                protocol="smb",
                targets=["10.0.0.1"],
                args=["-M", "spider", "-p", "argpw"],
                username="alice",
                password="hunter2",
            )
            secrets = _secrets_of(mock_exec)
            assert "hunter2" in secrets
            assert "argpw" in secrets

    @pytest.mark.asyncio
    async def test_certipy_named_and_opaque_args_secrets(self):
        c = certipy_mod.Certipy()
        c.certipy_cmd = "certipy"
        c.timeout = 10
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            await c.certipy(action="find", args=[], dc_ip="10.0.0.1", username="alice", password="hunter2")
            assert "hunter2" in _secrets_of(mock_exec)
        with patch.object(certipy_mod, "execute", new_callable=AsyncMock) as mock_exec:
            await c.certipy_auth(args=["-aes", "deadbeefkey", "-pfx-password", "pfxpw"])
            secrets = _secrets_of(mock_exec)
            assert "deadbeefkey" in secrets
            assert "pfxpw" in secrets

    @pytest.mark.asyncio
    async def test_impacket_secretsdump_threads_password_and_aes_key(self):
        imp = impacket_mod.Impacket()
        imp.timeout = 120
        with (
            patch.object(impacket_mod, "execute", new_callable=AsyncMock) as mock_exec,
            patch.object(imp, "_build_script_command", return_value=["secretsdump.py"]),
        ):
            await imp.impacket_secretsdump(target="10.0.0.1", username="alice", password="hunter2", aes_key="deadbeef")
            secrets = _secrets_of(mock_exec)
            assert "hunter2" in secrets
            assert "deadbeef" in secrets

    @pytest.mark.asyncio
    async def test_smbclient_password_threaded(self):
        smb = smbclient_mod.SmbClient()
        with (
            patch.object(smbclient_mod, "execute", new_callable=AsyncMock) as mock_exec,
            patch.object(smbclient_mod, "_require_smbclient", return_value="smbclient"),
        ):
            await smb.smb_download_file(
                target="10.0.0.1",
                share_name="C$",
                remote_path="f.txt",
                username="alice",
                password="hunter2",
            )
            assert "hunter2" in _secrets_of(mock_exec)
