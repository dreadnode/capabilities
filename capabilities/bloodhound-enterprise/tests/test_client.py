"""Tests for the high-level BHEClient — auth headers, error mapping, env config."""

from __future__ import annotations

import json

import httpx
import pytest

from runtime.client import (
    BHEAPIError,
    BHEClient,
    BHEConfig,
    BHEConfigError,
    _json_or_raise,
)


@pytest.fixture
def hmac_config() -> BHEConfig:
    return BHEConfig(
        base_url="https://bhe.example.com",
        token_id="abc-123",
        token_key="supersecretkey",
    )


@pytest.fixture
def jwt_config() -> BHEConfig:
    return BHEConfig(
        base_url="https://bhe.example.com",
        jwt="eyJ.fake.jwt",
    )


class TestAuthMode:
    def test_hmac_mode_when_token_pair_present(self, hmac_config: BHEConfig) -> None:
        assert hmac_config.auth_mode == "hmac"

    def test_jwt_mode_when_jwt_present(self, jwt_config: BHEConfig) -> None:
        assert jwt_config.auth_mode == "jwt"

    def test_unconfigured_when_neither(self) -> None:
        config = BHEConfig(base_url="https://bhe.example.com")
        assert config.auth_mode == "unconfigured"

    def test_hmac_takes_priority_over_jwt(self) -> None:
        config = BHEConfig(
            base_url="https://bhe.example.com",
            token_id="x",
            token_key="y",
            jwt="ignored",
        )
        assert config.auth_mode == "hmac"


class TestEnvConfig:
    def test_rejects_missing_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BLOODHOUND_URL", raising=False)
        with pytest.raises(BHEConfigError):
            BHEConfig.from_env()

    def test_strips_trailing_slash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BLOODHOUND_URL", "https://bhe.example.com/")
        config = BHEConfig.from_env()
        assert config.base_url == "https://bhe.example.com"

    def test_reads_hmac_creds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BLOODHOUND_URL", "https://bhe.example.com")
        monkeypatch.setenv("BHE_TOKEN_ID", "tid")
        monkeypatch.setenv("BHE_TOKEN_KEY", "tkey")
        config = BHEConfig.from_env()
        assert config.auth_mode == "hmac"
        assert config.token_id == "tid"

    def test_verify_ssl_toggle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BLOODHOUND_URL", "https://bhe.example.com")
        monkeypatch.setenv("BHE_VERIFY_SSL", "false")
        config = BHEConfig.from_env()
        assert config.verify_ssl is False

    def test_timeout_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BLOODHOUND_URL", "https://bhe.example.com")
        monkeypatch.setenv("BHE_TIMEOUT", "12.5")
        config = BHEConfig.from_env()
        assert config.timeout == 12.5

    def test_invalid_timeout_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BLOODHOUND_URL", "https://bhe.example.com")
        monkeypatch.setenv("BHE_TIMEOUT", "not-a-number")
        config = BHEConfig.from_env()
        assert config.timeout == 30.0


class TestAuthHeaders:
    def test_hmac_emits_signature_headers(self, hmac_config: BHEConfig) -> None:
        client = BHEClient(hmac_config)
        headers = client._auth_headers(
            method="GET",
            request_uri="/api/v2/users",
            body=b"",
        )
        assert headers["Authorization"] == "bhesignature abc-123"
        assert "RequestDate" in headers
        assert "Signature" in headers
        # Different body → different signature.
        other = client._auth_headers(
            method="GET",
            request_uri="/api/v2/users",
            body=b'{"foo":"bar"}',
        )
        assert other["Signature"] != headers["Signature"]

    def test_jwt_emits_bearer(self, jwt_config: BHEConfig) -> None:
        client = BHEClient(jwt_config)
        headers = client._auth_headers(
            method="GET",
            request_uri="/api/v2/users",
            body=b"",
        )
        assert headers["Authorization"] == "Bearer eyJ.fake.jwt"
        assert "Signature" not in headers

    def test_unconfigured_emits_nothing(self) -> None:
        config = BHEConfig(base_url="https://bhe.example.com")
        client = BHEClient(config)
        headers = client._auth_headers(
            method="GET",
            request_uri="/api/v2/users",
            body=b"",
        )
        assert "Authorization" not in headers


class TestJsonOrRaise:
    def _response(self, status: int, body: str) -> httpx.Response:
        request = httpx.Request("GET", "https://bhe.example.com/api/v2/test")
        return httpx.Response(status_code=status, text=body, request=request)

    def test_4xx_raises_bhe_error(self) -> None:
        r = self._response(403, '{"error":"forbidden"}')
        with pytest.raises(BHEAPIError) as exc_info:
            _json_or_raise(r)
        assert exc_info.value.status_code == 403
        assert exc_info.value.body == {"error": "forbidden"}

    def test_5xx_raises(self) -> None:
        r = self._response(500, "internal server error")
        with pytest.raises(BHEAPIError):
            _json_or_raise(r)

    def test_2xx_returns_decoded_json(self) -> None:
        r = self._response(200, '{"data":[1,2,3]}')
        assert _json_or_raise(r) == {"data": [1, 2, 3]}

    def test_empty_2xx_returns_none(self) -> None:
        request = httpx.Request("DELETE", "https://bhe.example.com/x")
        r = httpx.Response(status_code=204, text="", request=request)
        assert _json_or_raise(r) is None

    def test_non_json_2xx_raises(self) -> None:
        r = self._response(200, "<html></html>")
        with pytest.raises(BHEAPIError):
            _json_or_raise(r)


class TestRequestSigning:
    @pytest.mark.asyncio
    async def test_signed_request_includes_three_headers(
        self,
        hmac_config: BHEConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Confirm that an outgoing request carries Authorization,
        RequestDate, and Signature in HMAC mode. Uses a transport
        mock so we never touch a real BHE deployment."""
        captured: dict[str, dict[str, str]] = {}

        def transport(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, json={"ok": True})

        client = BHEClient(hmac_config)
        # Inject the mock transport into the underlying httpx client.
        client._client = httpx.AsyncClient(
            base_url=hmac_config.base_url,
            transport=httpx.MockTransport(transport),
            headers={"User-Agent": hmac_config.user_agent},
        )
        try:
            response = await client.get("/api/v2/users")
            assert response.status_code == 200
        finally:
            await client.close()

        h = captured["headers"]
        assert h.get("authorization", "").startswith("bhesignature ")
        assert "requestdate" in h
        assert "signature" in h

    @pytest.mark.asyncio
    async def test_jwt_request_uses_bearer(
        self,
        jwt_config: BHEConfig,
    ) -> None:
        captured: dict[str, dict[str, str]] = {}

        def transport(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, json={"ok": True})

        client = BHEClient(jwt_config)
        client._client = httpx.AsyncClient(
            base_url=jwt_config.base_url,
            transport=httpx.MockTransport(transport),
            headers={"User-Agent": jwt_config.user_agent},
        )
        try:
            await client.get("/api/v2/users")
        finally:
            await client.close()

        assert captured["headers"]["authorization"] == "Bearer eyJ.fake.jwt"
        assert "signature" not in captured["headers"]

    @pytest.mark.asyncio
    async def test_signature_covers_query_string(self, hmac_config: BHEConfig) -> None:
        """The request URI used for signing must include the query
        string the runtime sends — otherwise the server's
        recomputed signature won't match."""
        sigs: list[str] = []

        def transport(request: httpx.Request) -> httpx.Response:
            sigs.append(request.headers.get("signature", ""))
            return httpx.Response(200, json={"ok": True})

        client = BHEClient(hmac_config)
        client._client = httpx.AsyncClient(
            base_url=hmac_config.base_url,
            transport=httpx.MockTransport(transport),
            headers={"User-Agent": hmac_config.user_agent},
        )
        try:
            await client.get("/api/v2/users", params={"limit": 100})
            await client.get("/api/v2/users", params={"limit": 200})
        finally:
            await client.close()

        # Different query strings must produce different signatures.
        assert sigs[0] != sigs[1]


class TestPostBody:
    @pytest.mark.asyncio
    async def test_json_body_serialised_consistently(self, hmac_config: BHEConfig) -> None:
        """The signed body must match what httpx sends. We sign before
        the request goes out, so the runtime serialises once and
        signs the same bytes."""
        captured: dict[str, bytes] = {}

        def transport(request: httpx.Request) -> httpx.Response:
            captured["body"] = bytes(request.content)
            return httpx.Response(200, json={"ok": True})

        client = BHEClient(hmac_config)
        client._client = httpx.AsyncClient(
            base_url=hmac_config.base_url,
            transport=httpx.MockTransport(transport),
            headers={"User-Agent": hmac_config.user_agent},
        )
        try:
            await client.post("/api/v2/saved-queries", json={"name": "test"})
        finally:
            await client.close()

        assert captured["body"] == json.dumps({"name": "test"}).encode("utf-8")
