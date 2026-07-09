"""Callback client for out-of-band vulnerability testing.

Registers callback URLs via webhook.site (primary), interactsh API (secondary),
or interactsh-client CLI (fallback) for detecting SSRF, XXE, SSTI, and blind
injection vulnerabilities.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import string
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

# ---------------------------------------------------------------------------
# Interactsh protocol helpers (pure functions, no side effects)
# ---------------------------------------------------------------------------

# Public interactsh servers in priority order.
_INTERACTSH_SERVERS: list[str] = [
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
]

# Default lengths matching the upstream Go client.
_CORRELATION_ID_LENGTH = 20
_NONCE_LENGTH = 13
_RSA_KEY_SIZE = 2048


def _generate_correlation_id(length: int = _CORRELATION_ID_LENGTH) -> str:
    """Generate a random lowercase alphanumeric correlation ID."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _generate_secret_key() -> str:
    """Generate a UUID-style secret key."""
    import uuid

    return str(uuid.uuid4())


def _generate_rsa_keypair() -> tuple[bytes, bytes]:
    """Generate an RSA keypair and return (private_key_der, public_key_pem).

    Returns the private key in PKCS1/DER form (kept in memory only) and the
    public key as a PEM-encoded ``RSA PUBLIC KEY`` block.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=_RSA_KEY_SIZE
    )
    private_der = private_key.private_bytes(
        Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return private_der, public_pem


def _encode_public_key(public_pem: bytes) -> str:
    """Base64-encode a PEM public key for the registration payload."""
    return base64.b64encode(public_pem).decode()


def _build_registration_payload(
    public_pem: bytes,
    secret_key: str,
    correlation_id: str,
) -> dict[str, str]:
    """Build the JSON registration payload for POST /register."""
    return {
        "public-key": _encode_public_key(public_pem),
        "secret-key": secret_key,
        "correlation-id": correlation_id,
    }


def _build_interactsh_url(correlation_id: str, server_host: str) -> str:
    """Build a unique interactsh callback URL."""
    nonce = _generate_correlation_id(_NONCE_LENGTH)
    return f"{correlation_id}{nonce}.{server_host}"


def _decrypt_interactsh_message(
    private_key_der: bytes,
    aes_key_b64: str,
    ciphertext_b64: str,
) -> bytes:
    """Decrypt an AES-encrypted interaction record.

    The server returns:
    - ``aes_key``: RSA-OAEP(SHA-256) encrypted AES-256 key, base64-encoded.
    - ``data[]``: AES-256-CTR encrypted interaction JSON, base64-encoded.
      The first 16 bytes of the ciphertext are the IV.
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    private_key = load_der_private_key(private_key_der, password=None)

    # Decrypt the AES key with RSA-OAEP + SHA-256
    encrypted_aes_key = base64.b64decode(aes_key_b64)
    aes_key = private_key.decrypt(  # type: ignore[union-attr]
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None,
        ),
    )

    # Decrypt the message with AES-256-CTR
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.rstrip(b" \t\r\n")


# ---------------------------------------------------------------------------
# Interactsh session state
# ---------------------------------------------------------------------------


class _InteractshSession:
    """Holds cryptographic and server state for an active interactsh session."""

    __slots__ = (
        "server_url",
        "server_host",
        "correlation_id",
        "secret_key",
        "private_key_der",
    )

    def __init__(
        self,
        server_url: str,
        server_host: str,
        correlation_id: str,
        secret_key: str,
        private_key_der: bytes,
    ) -> None:
        self.server_url = server_url
        self.server_host = server_host
        self.correlation_id = correlation_id
        self.secret_key = secret_key
        self.private_key_der = private_key_der


# ---------------------------------------------------------------------------
# CallbackClient toolset
# ---------------------------------------------------------------------------


class CallbackClient(Toolset):
    """OOB vulnerability testing via callback URLs.

    Registers with webhook.site (primary), interactsh API (secondary), or
    interactsh-client CLI (fallback) to provide callback URLs for SSRF, XXE,
    SSTI, and blind injection testing.
    """

    _callback_url: str | None = PrivateAttr(default=None)
    _provider: str | None = PrivateAttr(default=None)
    _token_id: str | None = PrivateAttr(default=None)
    _seen_ids: set[str] = PrivateAttr(default_factory=set)
    _interactsh_session: _InteractshSession | None = PrivateAttr(default=None)

    # ------------------------------------------------------------------
    # Provider: webhook.site
    # ------------------------------------------------------------------

    async def _register_webhook_site(self) -> bool:
        """Register with webhook.site and return True on success."""
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.post(
                    "https://webhook.site/token",
                    json={
                        "default_content": "OK",
                        "default_status": 200,
                        "default_content_type": "text/plain",
                    },
                )
                if response.status_code != 201:
                    return False
                data = response.json()
                token_id = data.get("uuid")
                if not token_id:
                    return False
                self._token_id = token_id
                self._callback_url = f"https://webhook.site/{token_id}"
                self._provider = "webhook_site"
                return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Provider: interactsh API (native Python, no CLI binary required)
    # ------------------------------------------------------------------

    async def _register_interactsh_api(self) -> bool:
        """Register with an interactsh server via the HTTP API.

        Tries each public interactsh server in order until one succeeds.
        Returns True on success, False if all servers fail.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa  # noqa: F401
        except ImportError:
            # cryptography not installed — skip this provider
            return False

        private_der, public_pem = _generate_rsa_keypair()
        correlation_id = _generate_correlation_id()
        secret_key = _generate_secret_key()
        payload = _build_registration_payload(public_pem, secret_key, correlation_id)

        # Allow overriding the server list via environment variable.
        env_servers = os.environ.get("INTERACTSH_SERVER", "")
        if env_servers:
            servers = [s.strip() for s in env_servers.split(",") if s.strip()]
        else:
            servers = list(_INTERACTSH_SERVERS)

        for server_host in servers:
            for scheme in ("https", "http"):
                server_url = f"{scheme}://{server_host}"
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.post(
                            f"{server_url}/register",
                            json=payload,
                        )
                        if resp.status_code != 200:
                            continue
                        body = resp.json()
                        if body.get("message") != "registration successful":
                            continue

                    # Registration succeeded
                    session = _InteractshSession(
                        server_url=server_url,
                        server_host=server_host,
                        correlation_id=correlation_id,
                        secret_key=secret_key,
                        private_key_der=private_der,
                    )
                    self._interactsh_session = session
                    url = _build_interactsh_url(correlation_id, server_host)
                    self._callback_url = f"https://{url}"
                    self._provider = "interactsh_api"
                    return True
                except Exception:
                    continue
        return False

    async def _deregister_interactsh_api(self) -> None:
        """Deregister from the interactsh server (best-effort cleanup)."""
        session = self._interactsh_session
        if session is None:
            return
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{session.server_url}/deregister",
                    json={
                        "correlation-id": session.correlation_id,
                        "secret-key": session.secret_key,
                    },
                )
        except Exception:
            pass

    async def _poll_interactsh_api(self, since_seconds: int) -> str:
        """Poll the interactsh server for interactions and decrypt them."""
        session = self._interactsh_session
        if session is None:
            return "Error: No active interactsh session."

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{session.server_url}/poll",
                    params={
                        "id": session.correlation_id,
                        "secret": session.secret_key,
                    },
                )
                if resp.status_code != 200:
                    return f"Error: Interactsh poll failed: HTTP {resp.status_code}"

                body = resp.json()
                encrypted_data: list[str] = body.get("data", [])
                aes_key: str = body.get("aes_key", "")
                extra: list[str] = body.get("extra", [])

                cutoff = time.time() - since_seconds
                interactions: list[dict[str, str]] = []

                # Decrypt encrypted interactions
                if aes_key and encrypted_data:
                    for entry in encrypted_data:
                        try:
                            plaintext = _decrypt_interactsh_message(
                                session.private_key_der, aes_key, entry
                            )
                            interaction = json.loads(plaintext)
                            ix = self._parse_interactsh_interaction(interaction)
                            if ix is None:
                                continue
                            # Check timestamp filter
                            ts_str = interaction.get("timestamp", "")
                            if ts_str and self._interactsh_ts_before_cutoff(
                                ts_str, cutoff
                            ):
                                continue
                            # Deduplicate
                            ix_id = (
                                f"{ix['protocol']}:{ix['time']}:{ix['remote_address']}"
                            )
                            if ix_id in self._seen_ids:
                                continue
                            self._seen_ids.add(ix_id)
                            interactions.append(ix)
                        except Exception:
                            continue

                # Process unencrypted extra/tlddata interactions
                for plaintext_str in extra + body.get("tlddata", []):
                    if not plaintext_str:
                        continue
                    try:
                        interaction = json.loads(plaintext_str)
                        ix = self._parse_interactsh_interaction(interaction)
                        if ix is None:
                            continue
                        ts_str = interaction.get("timestamp", "")
                        if ts_str and self._interactsh_ts_before_cutoff(ts_str, cutoff):
                            continue
                        ix_id = f"{ix['protocol']}:{ix['time']}:{ix['remote_address']}"
                        if ix_id in self._seen_ids:
                            continue
                        self._seen_ids.add(ix_id)
                        interactions.append(ix)
                    except Exception:
                        continue

                if not interactions:
                    return "No new callback interactions since last check."

                lines = [f"Received {len(interactions)} callback interactions:"]
                for i, ix in enumerate(interactions[:10], 1):
                    lines.append(
                        f"  {i}. [{ix['time']}] {ix['protocol'].upper()} from {ix['remote_address']}"
                    )

                if interactions:
                    last = interactions[-1]
                    raw = last.get("raw_request", "")
                    if raw:
                        lines.append(f"\nMost recent request:\n{raw[:1000]}")

                return "\n".join(lines)

        except Exception as e:
            return f"Error: Interactsh poll error: {e}"

    @staticmethod
    def _parse_interactsh_interaction(data: dict[str, object]) -> dict[str, str] | None:
        """Parse a decrypted interactsh interaction dict into a normalised form."""
        protocol = str(data.get("protocol", ""))
        if not protocol:
            return None
        return {
            "protocol": protocol,
            "time": str(data.get("timestamp", "")),
            "unique_id": str(data.get("unique-id", "")),
            "full_id": str(data.get("full-id", "")),
            "remote_address": str(data.get("remote-address", "")),
            "raw_request": str(data.get("raw-request", ""))[:1000],
            "raw_response": str(data.get("raw-response", ""))[:500],
            "q_type": str(data.get("q-type", "")),
            "smtp_from": str(data.get("smtp-from", "")),
        }

    @staticmethod
    def _interactsh_ts_before_cutoff(ts_str: str, cutoff: float) -> bool:
        """Return True if the timestamp is before the cutoff."""
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return ts.timestamp() < cutoff
        except (ValueError, AttributeError):
            return False

    # ------------------------------------------------------------------
    # Provider: interactsh CLI (legacy fallback)
    # ------------------------------------------------------------------

    def _register_interactsh_cli(self) -> bool:
        """Register with interactsh-client CLI as fallback."""
        try:
            proc = subprocess.run(
                ["interactsh-client", "-json", "-n", "1"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in proc.stdout.splitlines():
                try:
                    data = json.loads(line)
                    if "url" in data:
                        self._callback_url = data["url"]
                        self._provider = "interactsh_cli"
                        return True
                except json.JSONDecodeError:
                    if ".oast." in line or ".interact." in line:
                        url = line.strip()
                        if not url.startswith("http"):
                            url = f"https://{url}"
                        self._callback_url = url
                        self._provider = "interactsh_cli"
                        return True
            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Registration orchestrator
    # ------------------------------------------------------------------

    async def _ensure_registered(self) -> bool:
        """Ensure a callback URL is registered, trying providers in order."""
        if self._callback_url:
            return True
        if await self._register_webhook_site():
            return True
        if await self._register_interactsh_api():
            return True
        return self._register_interactsh_cli()

    # ------------------------------------------------------------------
    # Tool methods (public API)
    # ------------------------------------------------------------------

    @tool_method(name="get_callback_url", catch=True)
    async def get_callback_url(self, protocol: str = "http") -> str:
        """Get a callback URL for out-of-band testing.

        Inject this URL in SSRF, XXE, SSTI, and blind injection payloads,
        then use check_callbacks to detect if the target contacted it.

        Args:
            protocol: Preferred protocol — 'http', 'https', or 'dns'
        """
        if not await self._ensure_registered():
            return "Error: Could not register with any callback provider."

        url = self._callback_url
        assert url is not None  # guarded by _ensure_registered

        if protocol == "https" and url.startswith("http://"):
            url = url.replace("http://", "https://", 1)
        elif protocol == "dns":
            url = url.replace("http://", "").replace("https://", "")

        return (
            f"{url}\n\n"
            f"Provider: {self._provider}. "
            f"Inject this URL in payloads, then use check_callbacks to see if the target contacted it."
        )

    @tool_method(name="check_callbacks", catch=True)
    async def check_callbacks(self, since_seconds: int = 300) -> str:
        """Check for callback interactions received from the target application.

        Call after injecting callback URLs to see if the target made requests.

        Args:
            since_seconds: Only show interactions from last N seconds (default: 300)
        """
        if not self._callback_url:
            return "Error: No callback URL registered. Use get_callback_url first."

        if self._provider == "webhook_site":
            return await self._poll_webhook_site(since_seconds)
        if self._provider == "interactsh_api":
            return await self._poll_interactsh_api(since_seconds)
        if self._provider == "interactsh_cli":
            return (
                "For interactsh CLI, run in bash: interactsh-client -json | head -20\n\n"
                "The CLI will show any interactions with your callback domain."
            )
        return f"Error: Unknown provider: {self._provider}"

    async def _poll_webhook_site(self, since_seconds: int) -> str:
        """Poll webhook.site for new interactions."""
        if not self._token_id:
            return "Error: No webhook.site token."

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"https://webhook.site/token/{self._token_id}/requests",
                    params={"sorting": "newest"},
                )
                if response.status_code != 200:
                    return f"Error: Poll failed: HTTP {response.status_code}"

                data = response.json()
                requests_data = data.get("data", [])
                if not requests_data:
                    return "No callback interactions received yet."

                cutoff = time.time() - since_seconds
                interactions = []

                for item in requests_data:
                    req_id = item.get("uuid", "")
                    if req_id in self._seen_ids:
                        continue

                    created_at = item.get("created_at", "")
                    try:
                        ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        if ts.timestamp() < cutoff:
                            continue
                    except (ValueError, AttributeError):
                        pass

                    self._seen_ids.add(req_id)
                    method = item.get("method", "GET")
                    url = item.get("url", "")
                    ip = item.get("ip", "unknown")
                    content = item.get("content", "")
                    headers = item.get("headers", {})

                    path = "/"
                    try:
                        parsed = urlparse(url)
                        path = parsed.path or "/"
                        if parsed.query:
                            path += f"?{parsed.query}"
                    except Exception:
                        pass

                    raw = f"{method} {path} HTTP/1.1\n"
                    if headers:
                        for k, v in headers.items():
                            if isinstance(v, list):
                                v = ", ".join(str(x) for x in v)
                            raw += f"{k}: {v}\n"
                    if content:
                        raw += f"\n{content}"

                    interactions.append(
                        {
                            "time": created_at,
                            "method": method,
                            "path": path,
                            "ip": ip,
                            "raw_request": raw[:1000],
                        }
                    )

                if not interactions:
                    return "No new callback interactions since last check."

                lines = [f"Received {len(interactions)} callback interactions:"]
                for i, ix in enumerate(interactions[:10], 1):
                    lines.append(
                        f"  {i}. [{ix['time']}] {ix['method']} {ix['path']} from {ix['ip']}"
                    )

                if interactions:
                    lines.append(
                        f"\nMost recent request:\n{interactions[-1]['raw_request']}"
                    )

                return "\n".join(lines)

        except Exception as e:
            return f"Error: Poll error: {e}"

    @tool_method(name="reset_callback", catch=True)
    async def reset_callback(self) -> str:
        """Reset callback state. Next get_callback_url will register a new URL."""
        # Best-effort deregistration from interactsh
        if self._provider == "interactsh_api":
            await self._deregister_interactsh_api()

        self._callback_url = None
        self._provider = None
        self._token_id = None
        self._seen_ids.clear()
        self._interactsh_session = None
        return "Callback state reset. Next get_callback_url will register a new URL."
