"""Tests for CallbackClient — OOB callback URL toolset.

Covers webhook.site, interactsh API, and interactsh CLI providers with
mocked HTTP responses.  No real network calls are made.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup & stub installation (must happen before importing the module)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve()
while _REPO_ROOT != _REPO_ROOT.parent:
    if (_REPO_ROOT / "capabilities" / "web-security" / "tools").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent
sys.path.insert(0, str(_REPO_ROOT / "capabilities" / "web-security" / "tools"))

# Install the dreadnode stub if not already present
import conftest  # noqa: F401 — triggers _install_dreadnode_tools_stub()

from callback import (
    CallbackClient,
    _InteractshSession,
    _build_interactsh_url,
    _build_registration_payload,
    _decrypt_interactsh_message,
    _encode_public_key,
    _generate_correlation_id,
    _generate_rsa_keypair,
    _generate_secret_key,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> CallbackClient:
    """Fresh CallbackClient instance with no registered provider.

    Manually initialise Pydantic PrivateAttr defaults because the test-stub
    Toolset base class does not run Pydantic's ``__init__``.
    """
    c = CallbackClient()
    c._callback_url = None
    c._provider = None
    c._token_id = None
    c._seen_ids = set()
    c._interactsh_session = None
    return c


@pytest.fixture
def rsa_keypair() -> tuple[bytes, bytes]:
    """Pre-generated RSA keypair (private_der, public_pem)."""
    return _generate_rsa_keypair()


# ---------------------------------------------------------------------------
# Pure helper tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_generate_correlation_id_default_length(self) -> None:
        cid = _generate_correlation_id()
        assert len(cid) == 20
        assert cid.isalnum()
        assert cid == cid.lower()

    def test_generate_correlation_id_custom_length(self) -> None:
        cid = _generate_correlation_id(10)
        assert len(cid) == 10

    def test_generate_secret_key_is_uuid(self) -> None:
        import uuid

        sk = _generate_secret_key()
        uuid.UUID(sk)  # raises ValueError if not a valid UUID

    def test_generate_rsa_keypair(self, rsa_keypair: tuple[bytes, bytes]) -> None:
        private_der, public_pem = rsa_keypair
        assert isinstance(private_der, bytes)
        assert isinstance(public_pem, bytes)
        assert b"BEGIN PUBLIC KEY" in public_pem

    def test_encode_public_key(self, rsa_keypair: tuple[bytes, bytes]) -> None:
        _, public_pem = rsa_keypair
        encoded = _encode_public_key(public_pem)
        # Should be valid base64
        decoded = base64.b64decode(encoded)
        assert b"BEGIN PUBLIC KEY" in decoded

    def test_build_registration_payload(self, rsa_keypair: tuple[bytes, bytes]) -> None:
        _, public_pem = rsa_keypair
        payload = _build_registration_payload(public_pem, "secret-123", "corr-id-abc")
        assert payload["public-key"] == _encode_public_key(public_pem)
        assert payload["secret-key"] == "secret-123"
        assert payload["correlation-id"] == "corr-id-abc"

    def test_build_interactsh_url(self) -> None:
        url = _build_interactsh_url("abcdefghijklmnopqrst", "oast.fun")
        assert url.startswith("abcdefghijklmnopqrst")
        assert url.endswith(".oast.fun")
        # correlation_id (20) + nonce (13) + "." + "oast.fun"
        parts = url.split(".")
        assert len(parts[0]) == 33  # 20 + 13

    def test_interactsh_ts_before_cutoff(self) -> None:
        import time

        now = time.time()
        old = "2020-01-01T00:00:00Z"
        assert CallbackClient._interactsh_ts_before_cutoff(old, now - 1) is True

        future = "2099-01-01T00:00:00Z"
        assert CallbackClient._interactsh_ts_before_cutoff(future, now) is False

    def test_interactsh_ts_invalid_returns_false(self) -> None:
        assert CallbackClient._interactsh_ts_before_cutoff("not-a-date", 0.0) is False

    def test_parse_interactsh_interaction(self) -> None:
        data = {
            "protocol": "http",
            "timestamp": "2024-01-01T00:00:00Z",
            "unique-id": "abc123",
            "full-id": "abc123.oast.fun",
            "remote-address": "1.2.3.4",
            "raw-request": "GET / HTTP/1.1\r\nHost: abc123.oast.fun",
            "raw-response": "HTTP/1.1 200 OK",
            "q-type": "",
            "smtp-from": "",
        }
        result = CallbackClient._parse_interactsh_interaction(data)
        assert result is not None
        assert result["protocol"] == "http"
        assert result["remote_address"] == "1.2.3.4"
        assert result["unique_id"] == "abc123"

    def test_parse_interactsh_interaction_empty_protocol(self) -> None:
        assert CallbackClient._parse_interactsh_interaction({}) is None
        assert CallbackClient._parse_interactsh_interaction({"protocol": ""}) is None


# ---------------------------------------------------------------------------
# Crypto round-trip test
# ---------------------------------------------------------------------------


class TestInteractshCrypto:
    def test_encrypt_decrypt_round_trip(self, rsa_keypair: tuple[bytes, bytes]) -> None:
        """Verify that _decrypt_interactsh_message correctly reverses the
        server-side encryption (RSA-OAEP + AES-256-CTR)."""
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        private_der, public_pem = rsa_keypair

        # Simulate server-side encryption
        plaintext = json.dumps(
            {
                "protocol": "http",
                "unique-id": "testid",
                "full-id": "testid.oast.fun",
                "raw-request": "GET / HTTP/1.1",
                "raw-response": "HTTP/1.1 200 OK",
                "remote-address": "10.0.0.1",
                "timestamp": "2024-06-01T12:00:00Z",
            }
        ).encode()

        # Generate random AES-256 key and IV
        aes_key = os.urandom(32)
        iv = os.urandom(16)

        # AES-256-CTR encrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
        ciphertext_b64 = base64.b64encode(ciphertext).decode()

        # RSA-OAEP encrypt the AES key
        public_key = load_pem_public_key(public_pem)
        encrypted_aes_key = public_key.encrypt(  # type: ignore[union-attr]
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None,
            ),
        )
        aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()

        # Decrypt using our function
        result = _decrypt_interactsh_message(private_der, aes_key_b64, ciphertext_b64)
        decoded = json.loads(result)
        assert decoded["protocol"] == "http"
        assert decoded["unique-id"] == "testid"
        assert decoded["remote-address"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# webhook.site provider tests
# ---------------------------------------------------------------------------


def _mock_response(status_code: int, json_data: Any = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


class TestWebhookSiteProvider:
    @pytest.mark.asyncio
    async def test_register_success(self, client: CallbackClient) -> None:
        mock_resp = _mock_response(201, {"uuid": "test-uuid-1234"})
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._register_webhook_site()

        assert result is True
        assert client._provider == "webhook_site"
        assert client._token_id == "test-uuid-1234"
        assert client._callback_url == "https://webhook.site/test-uuid-1234"

    @pytest.mark.asyncio
    async def test_register_failure_non_201(self, client: CallbackClient) -> None:
        mock_resp = _mock_response(500)
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._register_webhook_site()

        assert result is False

    @pytest.mark.asyncio
    async def test_register_failure_no_uuid(self, client: CallbackClient) -> None:
        mock_resp = _mock_response(201, {})
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._register_webhook_site()

        assert result is False

    @pytest.mark.asyncio
    async def test_register_failure_exception(self, client: CallbackClient) -> None:
        with patch(
            "callback.httpx.AsyncClient", side_effect=Exception("network error")
        ):
            result = await client._register_webhook_site()

        assert result is False

    @pytest.mark.asyncio
    async def test_poll_webhook_site_no_interactions(
        self, client: CallbackClient
    ) -> None:
        client._token_id = "test-token"
        client._provider = "webhook_site"

        mock_resp = _mock_response(200, {"data": []})
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._poll_webhook_site(300)

        assert "No callback interactions received yet" in result

    @pytest.mark.asyncio
    async def test_poll_webhook_site_with_interactions(
        self, client: CallbackClient
    ) -> None:
        client._token_id = "test-token"
        client._provider = "webhook_site"

        mock_resp = _mock_response(
            200,
            {
                "data": [
                    {
                        "uuid": "req-1",
                        "method": "GET",
                        "url": "https://webhook.site/test-token?test=1",
                        "ip": "10.0.0.1",
                        "created_at": "2099-01-01T00:00:00Z",
                        "content": "",
                        "headers": {"Host": "webhook.site"},
                    }
                ]
            },
        )
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._poll_webhook_site(300)

        assert "1 callback interactions" in result
        assert "10.0.0.1" in result

    @pytest.mark.asyncio
    async def test_poll_webhook_site_deduplicates(self, client: CallbackClient) -> None:
        client._token_id = "test-token"
        client._provider = "webhook_site"

        interaction = {
            "uuid": "req-1",
            "method": "GET",
            "url": "https://webhook.site/test-token",
            "ip": "10.0.0.1",
            "created_at": "2099-01-01T00:00:00Z",
            "content": "",
            "headers": {},
        }

        mock_resp = _mock_response(200, {"data": [interaction]})
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result1 = await client._poll_webhook_site(300)
            result2 = await client._poll_webhook_site(300)

        assert "1 callback interactions" in result1
        assert "No new callback interactions" in result2

    @pytest.mark.asyncio
    async def test_poll_webhook_site_no_token(self, client: CallbackClient) -> None:
        result = await client._poll_webhook_site(300)
        assert "Error" in result


# ---------------------------------------------------------------------------
# interactsh API provider tests
# ---------------------------------------------------------------------------


class TestInteractshApiProvider:
    @pytest.mark.asyncio
    async def test_register_success(self, client: CallbackClient) -> None:
        mock_resp = _mock_response(200, {"message": "registration successful"})
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._register_interactsh_api()

        assert result is True
        assert client._provider == "interactsh_api"
        assert client._interactsh_session is not None
        assert client._callback_url is not None
        assert ".oast.pro" in client._callback_url

    @pytest.mark.asyncio
    async def test_register_success_custom_server(self, client: CallbackClient) -> None:
        mock_resp = _mock_response(200, {"message": "registration successful"})
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("callback.httpx.AsyncClient", return_value=mock_client),
            patch.dict(os.environ, {"INTERACTSH_SERVER": "my.custom.server"}),
        ):
            result = await client._register_interactsh_api()

        assert result is True
        assert client._interactsh_session is not None
        assert client._interactsh_session.server_host == "my.custom.server"

    @pytest.mark.asyncio
    async def test_register_failure_all_servers(self, client: CallbackClient) -> None:
        mock_resp = _mock_response(500)
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._register_interactsh_api()

        assert result is False

    @pytest.mark.asyncio
    async def test_register_failure_wrong_message(self, client: CallbackClient) -> None:
        mock_resp = _mock_response(200, {"message": "something else"})
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._register_interactsh_api()

        assert result is False

    @pytest.mark.asyncio
    async def test_register_failure_no_cryptography(
        self, client: CallbackClient
    ) -> None:
        """Gracefully return False when cryptography is not importable."""
        with patch.dict(
            sys.modules, {"cryptography.hazmat.primitives.asymmetric.rsa": None}
        ):
            # Force an ImportError by patching the import
            original_import = (
                __builtins__.__import__
                if hasattr(__builtins__, "__import__")
                else __import__
            )  # type: ignore[union-attr]

            def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
                if "cryptography" in name:
                    raise ImportError("no cryptography")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                result = await client._register_interactsh_api()

            assert result is False

    @pytest.mark.asyncio
    async def test_poll_no_session(self, client: CallbackClient) -> None:
        result = await client._poll_interactsh_api(300)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_poll_empty_response(self, client: CallbackClient) -> None:
        session = _InteractshSession(
            server_url="https://oast.fun",
            server_host="oast.fun",
            correlation_id="testcorrelationid01",
            secret_key="secret",
            private_key_der=b"unused",
        )
        client._interactsh_session = session

        mock_resp = _mock_response(200, {"data": [], "aes_key": "", "extra": []})
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._poll_interactsh_api(300)

        assert "No new callback interactions" in result

    @pytest.mark.asyncio
    async def test_poll_with_extra_unencrypted(self, client: CallbackClient) -> None:
        """Test polling with unencrypted 'extra' data (no crypto needed)."""
        session = _InteractshSession(
            server_url="https://oast.fun",
            server_host="oast.fun",
            correlation_id="testcorrelationid01",
            secret_key="secret",
            private_key_der=b"unused",
        )
        client._interactsh_session = session

        extra_interaction = json.dumps(
            {
                "protocol": "dns",
                "unique-id": "testcorrelationid01abc",
                "full-id": "testcorrelationid01abc.oast.fun",
                "remote-address": "8.8.8.8",
                "timestamp": "2099-01-01T12:00:00Z",
                "raw-request": "DNS A query",
                "raw-response": "",
                "q-type": "A",
            }
        )

        mock_resp = _mock_response(
            200,
            {"data": [], "aes_key": "", "extra": [extra_interaction]},
        )
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._poll_interactsh_api(300)

        assert "1 callback interactions" in result
        assert "DNS" in result
        assert "8.8.8.8" in result

    @pytest.mark.asyncio
    async def test_poll_with_encrypted_data(self, client: CallbackClient) -> None:
        """Full crypto round-trip: simulate server encrypting, client decrypting."""
        private_der, public_pem = _generate_rsa_keypair()

        session = _InteractshSession(
            server_url="https://oast.pro",
            server_host="oast.pro",
            correlation_id="testcorrelationid01",
            secret_key="secret-key",
            private_key_der=private_der,
        )
        client._interactsh_session = session

        # Server-side encryption
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        interaction_json = json.dumps(
            {
                "protocol": "http",
                "unique-id": "testcorrelationid01nonce",
                "full-id": "testcorrelationid01nonce.oast.pro",
                "remote-address": "192.168.1.1",
                "timestamp": "2099-06-01T12:00:00Z",
                "raw-request": "GET /ssrf?target=internal HTTP/1.1\r\nHost: testcorrelationid01nonce.oast.pro",
                "raw-response": "HTTP/1.1 200 OK",
                "q-type": "",
                "smtp-from": "",
            }
        ).encode()

        aes_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(interaction_json) + encryptor.finalize()
        ciphertext_b64 = base64.b64encode(ciphertext).decode()

        public_key = load_pem_public_key(public_pem)
        encrypted_aes_key = public_key.encrypt(  # type: ignore[union-attr]
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None,
            ),
        )
        aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()

        mock_resp = _mock_response(
            200,
            {"data": [ciphertext_b64], "aes_key": aes_key_b64, "extra": []},
        )
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client._poll_interactsh_api(300)

        assert "1 callback interactions" in result
        assert "HTTP" in result
        assert "192.168.1.1" in result

    @pytest.mark.asyncio
    async def test_poll_deduplicates(self, client: CallbackClient) -> None:
        session = _InteractshSession(
            server_url="https://oast.fun",
            server_host="oast.fun",
            correlation_id="testcorrelationid01",
            secret_key="secret",
            private_key_der=b"unused",
        )
        client._interactsh_session = session

        extra = json.dumps(
            {
                "protocol": "dns",
                "unique-id": "x",
                "full-id": "x.oast.fun",
                "remote-address": "1.1.1.1",
                "timestamp": "2099-01-01T12:00:00Z",
                "raw-request": "",
                "raw-response": "",
            }
        )

        mock_resp = _mock_response(200, {"data": [], "aes_key": "", "extra": [extra]})
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result1 = await client._poll_interactsh_api(300)
            result2 = await client._poll_interactsh_api(300)

        assert "1 callback interactions" in result1
        assert "No new callback interactions" in result2

    @pytest.mark.asyncio
    async def test_deregister_best_effort(self, client: CallbackClient) -> None:
        session = _InteractshSession(
            server_url="https://oast.fun",
            server_host="oast.fun",
            correlation_id="test",
            secret_key="secret",
            private_key_der=b"",
        )
        client._interactsh_session = session

        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(200, {})
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            await client._deregister_interactsh_api()

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert "/deregister" in call_kwargs.args[0]

    @pytest.mark.asyncio
    async def test_deregister_no_session(self, client: CallbackClient) -> None:
        """Deregister with no active session should be a no-op."""
        await client._deregister_interactsh_api()  # Should not raise

    @pytest.mark.asyncio
    async def test_deregister_handles_exception(self, client: CallbackClient) -> None:
        session = _InteractshSession(
            server_url="https://oast.fun",
            server_host="oast.fun",
            correlation_id="test",
            secret_key="secret",
            private_key_der=b"",
        )
        client._interactsh_session = session

        with patch("callback.httpx.AsyncClient", side_effect=Exception("network")):
            await client._deregister_interactsh_api()  # Should not raise


# ---------------------------------------------------------------------------
# interactsh CLI provider tests
# ---------------------------------------------------------------------------


class TestInteractshCliProvider:
    def test_register_cli_json_url(self, client: CallbackClient) -> None:
        mock_result = MagicMock()
        mock_result.stdout = '{"url": "https://abc.oast.fun"}\n'
        mock_result.returncode = 0

        with patch("callback.subprocess.run", return_value=mock_result):
            result = client._register_interactsh_cli()

        assert result is True
        assert client._provider == "interactsh_cli"
        assert client._callback_url == "https://abc.oast.fun"

    def test_register_cli_plain_text(self, client: CallbackClient) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "abc123.oast.fun\n"
        mock_result.returncode = 0

        with patch("callback.subprocess.run", return_value=mock_result):
            result = client._register_interactsh_cli()

        assert result is True
        assert client._provider == "interactsh_cli"
        assert client._callback_url == "https://abc123.oast.fun"

    def test_register_cli_interact_domain(self, client: CallbackClient) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "xyz.interact.sh\n"
        mock_result.returncode = 0

        with patch("callback.subprocess.run", return_value=mock_result):
            result = client._register_interactsh_cli()

        assert result is True
        assert client._callback_url == "https://xyz.interact.sh"

    def test_register_cli_not_installed(self, client: CallbackClient) -> None:
        with patch("callback.subprocess.run", side_effect=FileNotFoundError):
            result = client._register_interactsh_cli()

        assert result is False

    def test_register_cli_timeout(self, client: CallbackClient) -> None:
        with patch(
            "callback.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 15)
        ):
            result = client._register_interactsh_cli()

        assert result is False

    def test_register_cli_no_url(self, client: CallbackClient) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "some random output\n"
        mock_result.returncode = 0

        with patch("callback.subprocess.run", return_value=mock_result):
            result = client._register_interactsh_cli()

        assert result is False


# ---------------------------------------------------------------------------
# Registration orchestrator tests
# ---------------------------------------------------------------------------


class TestEnsureRegistered:
    @pytest.mark.asyncio
    async def test_already_registered(self, client: CallbackClient) -> None:
        client._callback_url = "https://already.registered"
        result = await client._ensure_registered()
        assert result is True

    @pytest.mark.asyncio
    async def test_webhook_site_first(self, client: CallbackClient) -> None:
        with patch.object(
            client, "_register_webhook_site", return_value=True
        ) as mock_ws:
            result = await client._ensure_registered()

        assert result is True
        mock_ws.assert_called_once()

    @pytest.mark.asyncio
    async def test_falls_through_to_interactsh_api(
        self, client: CallbackClient
    ) -> None:
        with (
            patch.object(client, "_register_webhook_site", return_value=False),
            patch.object(
                client, "_register_interactsh_api", return_value=True
            ) as mock_api,
        ):
            result = await client._ensure_registered()

        assert result is True
        mock_api.assert_called_once()

    @pytest.mark.asyncio
    async def test_falls_through_to_cli(self, client: CallbackClient) -> None:
        with (
            patch.object(client, "_register_webhook_site", return_value=False),
            patch.object(client, "_register_interactsh_api", return_value=False),
            patch.object(
                client, "_register_interactsh_cli", return_value=True
            ) as mock_cli,
        ):
            result = await client._ensure_registered()

        assert result is True
        mock_cli.assert_called_once()

    @pytest.mark.asyncio
    async def test_all_fail(self, client: CallbackClient) -> None:
        with (
            patch.object(client, "_register_webhook_site", return_value=False),
            patch.object(client, "_register_interactsh_api", return_value=False),
            patch.object(client, "_register_interactsh_cli", return_value=False),
        ):
            result = await client._ensure_registered()

        assert result is False


# ---------------------------------------------------------------------------
# Tool method tests (get_callback_url, check_callbacks, reset_callback)
# ---------------------------------------------------------------------------


class TestToolMethods:
    @pytest.mark.asyncio
    async def test_get_callback_url_http(self, client: CallbackClient) -> None:
        client._callback_url = "https://webhook.site/uuid"
        client._provider = "webhook_site"

        result = await client.get_callback_url("http")
        assert "https://webhook.site/uuid" in result
        assert "webhook_site" in result

    @pytest.mark.asyncio
    async def test_get_callback_url_https(self, client: CallbackClient) -> None:
        client._callback_url = "http://example.com/cb"
        client._provider = "test"

        result = await client.get_callback_url("https")
        assert "https://example.com/cb" in result

    @pytest.mark.asyncio
    async def test_get_callback_url_dns(self, client: CallbackClient) -> None:
        client._callback_url = "https://abc.oast.fun"
        client._provider = "interactsh_api"

        result = await client.get_callback_url("dns")
        assert "abc.oast.fun" in result
        assert "https://" not in result.split("\n")[0]

    @pytest.mark.asyncio
    async def test_get_callback_url_no_provider(self, client: CallbackClient) -> None:
        with (
            patch.object(client, "_register_webhook_site", return_value=False),
            patch.object(client, "_register_interactsh_api", return_value=False),
            patch.object(client, "_register_interactsh_cli", return_value=False),
        ):
            result = await client.get_callback_url()

        assert "Error" in result

    @pytest.mark.asyncio
    async def test_check_callbacks_no_url(self, client: CallbackClient) -> None:
        result = await client.check_callbacks()
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_check_callbacks_webhook_site(self, client: CallbackClient) -> None:
        client._callback_url = "https://webhook.site/uuid"
        client._provider = "webhook_site"
        client._token_id = "uuid"

        mock_resp = _mock_response(200, {"data": []})
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client.check_callbacks()

        assert "No callback interactions" in result

    @pytest.mark.asyncio
    async def test_check_callbacks_interactsh_api(self, client: CallbackClient) -> None:
        client._callback_url = "https://abc.oast.fun"
        client._provider = "interactsh_api"
        client._interactsh_session = _InteractshSession(
            server_url="https://oast.fun",
            server_host="oast.fun",
            correlation_id="test",
            secret_key="secret",
            private_key_der=b"",
        )

        mock_resp = _mock_response(200, {"data": [], "aes_key": "", "extra": []})
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("callback.httpx.AsyncClient", return_value=mock_client):
            result = await client.check_callbacks()

        assert "No new callback interactions" in result

    @pytest.mark.asyncio
    async def test_check_callbacks_interactsh_cli(self, client: CallbackClient) -> None:
        client._callback_url = "https://abc.oast.fun"
        client._provider = "interactsh_cli"

        result = await client.check_callbacks()
        assert "interactsh" in result.lower()
        assert "bash" in result.lower()

    @pytest.mark.asyncio
    async def test_check_callbacks_unknown_provider(
        self, client: CallbackClient
    ) -> None:
        client._callback_url = "https://example.com"
        client._provider = "unknown_provider"

        result = await client.check_callbacks()
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_reset_callback(self, client: CallbackClient) -> None:
        client._callback_url = "https://abc.oast.fun"
        client._provider = "interactsh_api"
        client._interactsh_session = _InteractshSession(
            server_url="https://oast.fun",
            server_host="oast.fun",
            correlation_id="test",
            secret_key="secret",
            private_key_der=b"",
        )
        client._seen_ids.add("seen-1")

        with patch.object(client, "_deregister_interactsh_api", new_callable=AsyncMock):
            result = await client.reset_callback()

        assert "reset" in result.lower()
        assert client._callback_url is None
        assert client._provider is None
        assert client._interactsh_session is None
        assert len(client._seen_ids) == 0

    @pytest.mark.asyncio
    async def test_reset_callback_webhook_site(self, client: CallbackClient) -> None:
        """Reset with webhook_site provider should not call deregister."""
        client._callback_url = "https://webhook.site/uuid"
        client._provider = "webhook_site"
        client._token_id = "uuid"

        result = await client.reset_callback()
        assert "reset" in result.lower()
        assert client._callback_url is None
        assert client._token_id is None
