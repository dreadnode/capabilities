"""Unit tests for the HMAC signing chain.

The signature algorithm is the load-bearing piece of the BHE
client — drift here causes silent 401s on every signed request.
Tests pin the algorithm against deterministic inputs so any
refactor that changes the chain fails CI.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from runtime.client import _format_request_date, sign_request


# Reference vectors computed manually following the published
# three-stage chain. If any of these change, the on-the-wire
# signature breaks.

REFERENCE = {
    "token_key": "supersecretkey",
    "method": "GET",
    "request_uri": "/api/v2/users",
    "request_date": "2024-01-15T10:30:00.000000000Z",
    "body": b"",
}


def _expected_signature(
    *,
    token_key: str,
    method: str,
    request_uri: str,
    request_date: str,
    body: bytes,
) -> str:
    """Reference implementation, computed independently from sign_request."""
    op_msg = f"{method.upper()}{request_uri}".encode()
    op_key = hmac.new(token_key.encode(), op_msg, hashlib.sha256).digest()
    date_msg = request_date[:13].encode()
    date_key = hmac.new(op_key, date_msg, hashlib.sha256).digest()
    sig = hmac.new(date_key, body, hashlib.sha256).digest()
    return base64.b64encode(sig).decode("ascii")


class TestSigning:
    def test_matches_reference_implementation(self) -> None:
        produced = sign_request(**REFERENCE)
        expected = _expected_signature(**REFERENCE)
        assert produced == expected

    def test_signature_changes_with_method(self) -> None:
        ref = sign_request(**REFERENCE)
        post_variant = sign_request(**{**REFERENCE, "method": "POST"})
        assert ref != post_variant

    def test_signature_changes_with_uri(self) -> None:
        ref = sign_request(**REFERENCE)
        other = sign_request(**{**REFERENCE, "request_uri": "/api/v2/computers"})
        assert ref != other

    def test_signature_changes_with_token_key(self) -> None:
        ref = sign_request(**REFERENCE)
        other = sign_request(**{**REFERENCE, "token_key": "different"})
        assert ref != other

    def test_signature_changes_with_date_hour(self) -> None:
        ref = sign_request(**REFERENCE)
        other = sign_request(**{**REFERENCE, "request_date": "2024-01-15T11:30:00.000000000Z"})
        assert ref != other

    def test_signature_changes_with_body(self) -> None:
        ref = sign_request(**REFERENCE)
        other = sign_request(**{**REFERENCE, "body": b'{"x":1}'})
        assert ref != other

    def test_minute_does_not_change_signature(self) -> None:
        """Stage 2 truncates to YYYY-MM-DDTHH (13 chars). Two requests
        in the same hour on the same path/body must produce the same
        signature — load-bearing for replay-window semantics."""
        ref = sign_request(**REFERENCE)
        same_hour = sign_request(**{**REFERENCE, "request_date": "2024-01-15T10:59:59.999999999Z"})
        assert ref == same_hour

    def test_returns_base64(self) -> None:
        sig = sign_request(**REFERENCE)
        # Round-trip through b64decode without raising.
        assert len(base64.b64decode(sig)) == 32  # SHA-256 digest

    def test_rejects_empty_method(self) -> None:
        with pytest.raises(ValueError):
            sign_request(**{**REFERENCE, "method": ""})

    def test_rejects_relative_uri(self) -> None:
        with pytest.raises(ValueError):
            sign_request(**{**REFERENCE, "request_uri": "api/v2/users"})

    def test_rejects_short_date(self) -> None:
        with pytest.raises(ValueError):
            sign_request(**{**REFERENCE, "request_date": "2024-01-15"})


class TestRequestDateFormat:
    def test_includes_microseconds_and_padding(self) -> None:
        from datetime import datetime, timezone

        result = _format_request_date(datetime(2024, 1, 15, 10, 30, 0, 123456, tzinfo=timezone.utc))
        # Expected shape: 2024-01-15T10:30:00.123456000Z
        assert result == "2024-01-15T10:30:00.123456000Z"

    def test_default_uses_now_utc(self) -> None:
        result = _format_request_date()
        assert result.endswith("Z")
        assert len(result) == len("YYYY-MM-DDTHH:MM:SS.SSSSSS000Z")
        # First 13 chars are the hour key — must be parseable.
        assert result[10] == "T"
