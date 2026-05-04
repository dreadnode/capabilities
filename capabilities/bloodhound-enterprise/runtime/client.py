"""BloodHound Enterprise REST API client.

The capability supports two authentication modes:

- **HMAC-signed requests** (recommended for long-lived integrations).
  Implements the published three-stage chain:

      OperationKey = HMAC-SHA-256(token_key, METHOD + URI)
      DateKey      = HMAC-SHA-256(OperationKey, RFC3339_datetime[:13])
      Signature    = HMAC-SHA-256(DateKey, body_bytes)

  Where ``RFC3339_datetime[:13]`` is the truncated-to-hour part
  (``2020-12-01T23``) used to bound replay windows.

- **JWT bearer**. Convenient for short interactive sessions; expires
  with the user's login. Exchanged via ``/api/v2/login`` and stored
  on the client.

The client wraps an :class:`httpx.AsyncClient` for connection
pooling, exposes typed verbs (``get`` / ``post`` / ``put`` /
``delete``), and surfaces errors as :class:`BHEAPIError` with the
status code + decoded body so tools can surface them to the agent.

Configuration is read from environment on first use:

- ``BLOODHOUND_URL``      — base URL, e.g. ``https://bhe.example.com``
- ``BHE_TOKEN_ID``        — HMAC token id (signed mode)
- ``BHE_TOKEN_KEY``       — HMAC token key (signed mode)
- ``BHE_JWT``             — pre-obtained JWT (jwt mode)
- ``BHE_USERNAME``        — login email (jwt mode, used by ``connect``)
- ``BHE_PASSWORD``        — login password (jwt mode)
- ``BHE_VERIFY_SSL``      — ``"false"`` to disable TLS verification
- ``BHE_TIMEOUT``         — default per-request timeout (seconds)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import typing as t
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from loguru import logger


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class BHEError(Exception):
    """Base class for client errors."""


class BHEConfigError(BHEError):
    """Configuration is missing or contradictory."""


class BHEAuthError(BHEError):
    """Login failed or token is missing/invalid."""


class BHEAPIError(BHEError):
    """The API returned a non-2xx response.

    Carries the status code and the (decoded best-effort) body so
    tools can surface a useful failure message.
    """

    def __init__(self, status_code: int, message: str, body: t.Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BHEConfig:
    """Resolved BHE client configuration.

    ``token_id`` + ``token_key`` enable HMAC mode. ``jwt`` enables JWT
    mode. ``username`` + ``password`` enable on-demand login.
    """

    base_url: str
    token_id: str | None = None
    token_key: str | None = None
    jwt: str | None = None
    username: str | None = None
    password: str | None = None
    verify_ssl: bool = True
    timeout: float = 30.0
    user_agent: str = "dreadnode-bloodhound-enterprise/0.1"

    @classmethod
    def from_env(cls) -> "BHEConfig":
        base_url = os.environ.get("BLOODHOUND_URL", "").strip().rstrip("/")
        if not base_url:
            raise BHEConfigError("BLOODHOUND_URL is not set")
        verify_ssl = os.environ.get("BHE_VERIFY_SSL", "true").strip().lower() != "false"
        try:
            timeout = float(os.environ.get("BHE_TIMEOUT", "30").strip() or "30")
        except ValueError:
            timeout = 30.0
        return cls(
            base_url=base_url,
            token_id=os.environ.get("BHE_TOKEN_ID", "").strip() or None,
            token_key=os.environ.get("BHE_TOKEN_KEY", "").strip() or None,
            jwt=os.environ.get("BHE_JWT", "").strip() or None,
            username=os.environ.get("BHE_USERNAME", "").strip() or None,
            password=os.environ.get("BHE_PASSWORD", "").strip() or None,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    @property
    def auth_mode(self) -> t.Literal["hmac", "jwt", "unconfigured"]:
        if self.token_id and self.token_key:
            return "hmac"
        if self.jwt:
            return "jwt"
        return "unconfigured"


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _format_request_date(now: datetime | None = None) -> str:
    """Produce the RFC3339 datetime BHE expects in ``RequestDate``.

    The published example uses microsecond precision with a trailing
    ``Z`` and three extra zeroes to match the Go reference impl
    (``YYYY-MM-DDTHH:MM:SS.SSSSSS000Z``). Keep the format identical
    — drift here causes silent signature failures.
    """
    instant = now or datetime.now(timezone.utc)
    return instant.strftime("%Y-%m-%dT%H:%M:%S.%f000Z")


def sign_request(
    *,
    token_key: str,
    method: str,
    request_uri: str,
    request_date: str,
    body: bytes = b"",
) -> str:
    """Compute the HMAC-SHA-256 signature for a single request.

    See module docstring for the full chain. Returns the base64-
    encoded final digest, which goes straight into the
    ``Signature`` header.

    The token_key is treated as raw bytes — BHE token keys are
    plain strings (not base64). The ``request_uri`` must be the
    path + query, not the absolute URL (e.g. ``/api/v2/users``).
    """
    if not method:
        raise ValueError("method must not be empty")
    if not request_uri.startswith("/"):
        raise ValueError(f"request_uri must start with '/'; got {request_uri!r}")
    if not request_date or len(request_date) < 13:
        raise ValueError("request_date must be RFC3339 with at least YYYY-MM-DDTHH")

    key = token_key.encode("utf-8")
    op_msg = f"{method.upper()}{request_uri}".encode("utf-8")
    op_digester = hmac.new(key, op_msg, hashlib.sha256)
    operation_key = op_digester.digest()

    date_msg = request_date[:13].encode("utf-8")
    date_digester = hmac.new(operation_key, date_msg, hashlib.sha256)
    date_key = date_digester.digest()

    body_digester = hmac.new(date_key, body or b"", hashlib.sha256)
    return base64.b64encode(body_digester.digest()).decode("ascii")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class BHEClient:
    """Async HTTP client for the BloodHound Enterprise REST API.

    Use as an async context manager — ``__aexit__`` closes the
    underlying httpx client. Multiple tool calls reuse the same
    client instance via :func:`get_client`.
    """

    def __init__(self, config: BHEConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None

    @property
    def config(self) -> BHEConfig:
        return self._config

    @property
    def base_url(self) -> str:
        return self._config.base_url

    @property
    def auth_mode(self) -> str:
        return self._config.auth_mode

    async def __aenter__(self) -> "BHEClient":
        return self

    async def __aexit__(self, *_: t.Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._config.base_url,
                verify=self._config.verify_ssl,
                timeout=self._config.timeout,
                headers={"User-Agent": self._config.user_agent},
                follow_redirects=False,
            )
        return self._client

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    async def login(self, username: str, password: str) -> str:
        """Exchange username + password for a JWT and store it on the client.

        The JWT is mounted into the active config so subsequent
        requests can run in JWT mode without re-logging-in. Returns
        the token (caller may persist it; it expires per server
        policy).
        """
        client = self._ensure_client()
        # Login itself is unauthenticated; don't sign or attach JWT.
        response = await client.post(
            "/api/v2/login",
            json={"login_method": "secret", "username": username, "secret": password},
        )
        if response.status_code >= 400:
            raise BHEAuthError(
                f"login failed with HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise BHEAuthError(f"login response is not JSON: {response.text[:300]}") from exc
        token = (payload.get("data") or {}).get("session_token") or payload.get("session_token")
        if not isinstance(token, str) or not token:
            raise BHEAuthError(f"login response missing session_token: {payload!r}")
        self._config.jwt = token
        # Wipe HMAC creds so we don't double-auth.
        self._config.token_id = None
        self._config.token_key = None
        return token

    # ------------------------------------------------------------------
    # Verbs
    # ------------------------------------------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: t.Mapping[str, t.Any] | None = None,
        json: t.Any | None = None,
        data: bytes | None = None,
        headers: t.Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """Issue a signed (or JWT-authenticated) request.

        Exactly one of ``json`` / ``data`` may be set. The body is
        serialised before signing so the signature covers what goes
        on the wire.
        """
        if json is not None and data is not None:
            raise ValueError("pass json= or data=, not both")
        client = self._ensure_client()
        body_bytes = b""
        request_headers: dict[str, str] = dict(headers or {})
        if json is not None:
            import json as _json

            body_bytes = _json.dumps(json).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            body_bytes = data
            request_headers.setdefault("Content-Type", "application/octet-stream")

        # Build the request URI (path + query) for signing — must
        # match what httpx puts on the wire.
        request_uri = path
        if params:
            from urllib.parse import urlencode

            qs = urlencode(
                [(k, v) for k, v in params.items() if v is not None],
                doseq=True,
            )
            if qs:
                request_uri = f"{path}?{qs}"

        request_headers.update(
            self._auth_headers(method=method, request_uri=request_uri, body=body_bytes)
        )

        response = await client.request(
            method.upper(),
            path,
            params=params,
            content=body_bytes if body_bytes else None,
            headers=request_headers,
            timeout=timeout if timeout is not None else self._config.timeout,
        )
        return response

    async def get(self, path: str, **kw: t.Any) -> httpx.Response:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw: t.Any) -> httpx.Response:
        return await self.request("POST", path, **kw)

    async def put(self, path: str, **kw: t.Any) -> httpx.Response:
        return await self.request("PUT", path, **kw)

    async def delete(self, path: str, **kw: t.Any) -> httpx.Response:
        return await self.request("DELETE", path, **kw)

    async def get_json(self, path: str, **kw: t.Any) -> t.Any:
        response = await self.get(path, **kw)
        return _json_or_raise(response)

    async def post_json(self, path: str, **kw: t.Any) -> t.Any:
        response = await self.post(path, **kw)
        return _json_or_raise(response)

    async def put_json(self, path: str, **kw: t.Any) -> t.Any:
        response = await self.put(path, **kw)
        return _json_or_raise(response)

    async def delete_json(self, path: str, **kw: t.Any) -> t.Any:
        response = await self.delete(path, **kw)
        return _json_or_raise(response)

    # ------------------------------------------------------------------
    # Auth header construction
    # ------------------------------------------------------------------

    def _auth_headers(
        self,
        *,
        method: str,
        request_uri: str,
        body: bytes,
    ) -> dict[str, str]:
        mode = self._config.auth_mode
        if mode == "hmac":
            request_date = _format_request_date()
            signature = sign_request(
                token_key=self._config.token_key or "",
                method=method,
                request_uri=request_uri,
                request_date=request_date,
                body=body,
            )
            return {
                "Authorization": f"bhesignature {self._config.token_id}",
                "RequestDate": request_date,
                "Signature": signature,
            }
        if mode == "jwt":
            return {"Authorization": f"Bearer {self._config.jwt}"}
        # Unconfigured — let the request go out unauth'd; the API
        # will reject and the resulting BHEAPIError carries enough
        # context for the agent to recover.
        logger.warning("BHE client has no credentials; request will be unauthenticated")
        return {}


def _json_or_raise(response: httpx.Response) -> t.Any:
    """Return parsed JSON or raise :class:`BHEAPIError`."""
    if response.status_code >= 400:
        body: t.Any
        try:
            body = response.json()
        except ValueError:
            body = response.text
        raise BHEAPIError(
            response.status_code,
            f"HTTP {response.status_code} for {response.request.method} "
            f"{response.request.url.path}: {response.text[:300]}",
            body=body,
        )
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError as exc:
        raise BHEAPIError(
            response.status_code,
            f"non-JSON response from {response.request.url.path}: {exc}",
            body=response.text,
        ) from exc


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


_CLIENT: BHEClient | None = None


def get_client(*, config: BHEConfig | None = None) -> BHEClient:
    """Return the shared session-scoped client, creating it if needed.

    Tools call this to get a connected client without each one
    re-reading env. The first call instantiates from
    :func:`BHEConfig.from_env`; later calls return the same instance.
    Pass ``config=`` to override (mostly useful in tests).
    """
    global _CLIENT
    if _CLIENT is None or config is not None:
        _CLIENT = BHEClient(config or BHEConfig.from_env())
    return _CLIENT


async def reset_client() -> None:
    """Close the shared client and forget it (next ``get_client`` re-reads env)."""
    global _CLIENT
    if _CLIENT is not None:
        await _CLIENT.close()
    _CLIENT = None


__all__ = [
    "BHEAPIError",
    "BHEAuthError",
    "BHEClient",
    "BHEConfig",
    "BHEConfigError",
    "BHEError",
    "get_client",
    "reset_client",
    "sign_request",
]
