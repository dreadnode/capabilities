"""Tests for network-ops tool fixes: nmap port quoting, certipy domain
handling, ntlmrelayx arg building, coercion command building, and
relay orchestration helpers."""

from __future__ import annotations

import asyncio
import importlib.util
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

    # dreadnode stubs
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

    # Config stub
    class Config:
        def __init__(self, **kwargs):
            self.default = kwargs.get("default")
            self.default_factory = kwargs.get("default_factory")

    sys.modules["dreadnode"].Config = Config

    # Toolset stub
    class Toolset:
        pass

    def tool_method(**kwargs):
        def decorator(func):
            return func
        return decorator

    sys.modules["dreadnode.agents.tools"].Toolset = Toolset
    sys.modules["dreadnode.agents.tools"].tool_method = tool_method

    # execute stub
    async def execute(cmd, **kwargs):
        return f"executed: {' '.join(cmd)}"

    sys.modules["dreadnode.tools.execute"].execute = execute

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
            await c.certipy(
                action="find", args=[], target="10.0.0.1"
            )
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
            {"petitpotam": (tmp_path, "PetitPotam.py", "https://github.com/topotam/PetitPotam")},
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
            {"shadowcoerce": (tmp_path, "shadowcoerce.py", "https://github.com/ShutdownRepo/ShadowCoerce")},
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
            {"petitpotam": (tmp_path, "PetitPotam.py", "https://github.com/topotam/PetitPotam")},
        ):
            cmd = imp._build_coercion_command(
                "petitpotam", "10.0.0.1", "10.0.0.2"
            )

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
        proc = _make_mock_process([
            b"Impacket v0.13.1\n",
            b"[*] Setting up SMB Server\n",
            b"[*] Servers started, waiting for connections\n",
        ])
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_ready(proc, output, timeout=5)
        assert result is True
        assert len(output) == 3

    @pytest.mark.asyncio
    async def test_returns_false_on_early_exit(self):
        proc = _make_mock_process([
            b"Error: something went wrong\n",
            b"",  # EOF
        ])
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_ready(proc, output, timeout=5)
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_bind_error(self):
        proc = _make_mock_process([
            b"Impacket v0.13.1\n",
            b"Error: Address already in use (bind failed)\n",
        ])
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_ready(proc, output, timeout=5)
        assert result is False


class TestWaitForRelayResult:

    @pytest.mark.asyncio
    async def test_detects_certificate_success(self):
        proc = _make_mock_process([
            b"[*] SMBD-Thread-4: Received connection from 10.0.0.5\n",
            b"[*] Authenticating against http://ca/certsrv\n",
            b"[*] Got certificate!\n",
            b"[*] Certificate: MIIFxz...\n",
        ])
        output: list[str] = []
        result = await impacket_mod._wait_for_relay_result(proc, output, timeout=5)
        assert result is True
        assert any("certificate" in line.lower() for line in output)

    @pytest.mark.asyncio
    async def test_returns_false_on_timeout(self):
        # No success patterns, just connection noise
        proc = _make_mock_process([
            b"[*] SMBD-Thread-4: Connection from 10.0.0.5\n",
            b"",  # EOF
        ])
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

        with patch("os.getpgid", return_value=99999) as mock_getpgid, \
             patch("os.killpg") as mock_killpg:
            await impacket_mod._kill_relay(proc)
            mock_getpgid.assert_called_once_with(99999)
            mock_killpg.assert_called()
