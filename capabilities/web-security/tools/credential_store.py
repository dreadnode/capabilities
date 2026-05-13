"""Credential management for web security testing.

Provides structured storage for API keys, bearer tokens, cookies,
basic auth, and custom headers with formatting helpers for immediate
use in HTTP requests. Includes TOTP/MFA code generation via 2fa CLI.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
from typing import Any, Literal

from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

CredentialType = Literal["api_key", "bearer_token", "cookie", "basic_auth", "custom_header", "http_request"]


class CredentialStore(Toolset):
    """Manage typed credentials for web security testing with formatting helpers."""

    _store: dict[str, dict[str, Any]] = PrivateAttr(default_factory=dict)

    @tool_method(name="store_credential", catch=True)
    async def store_credential(
        self,
        name: str,
        credential_type: CredentialType,
        credential_data: dict[str, Any],
    ) -> str:
        """Store a typed credential.

        Types and expected credential_data fields:
        - api_key: {value, header_name?="X-API-Key"}
        - bearer_token: {token, refresh_token?}
        - cookie: {name, value, domain, path?="/", http_only?, secure?}
        - basic_auth: {username, password}
        - custom_header: {header_name, value}
        - http_request: {content} (raw HTTP request from Burp/Caido export)
        """
        valid_types = list(CredentialType.__args__)  # type: ignore[attr-defined]
        if credential_type not in valid_types:
            return f"Error: Unknown type '{credential_type}'. Valid: {', '.join(valid_types)}"

        self._store[name] = {"type": credential_type, "data": credential_data}

        if credential_type == "http_request":
            return (
                f"Credential '{name}' stored as {credential_type}. "
                f"Use get_credential with format='raw' to see the full request."
            )
        return (
            f"Credential '{name}' stored as {credential_type}. " f"Use get_credential with format='header' to use it."
        )

    @tool_method(name="get_credential", catch=True)
    async def get_credential(
        self,
        name: str,
        format: Literal["raw", "header", "cookie_string"] = "raw",
    ) -> str:
        """Get a stored credential formatted for use.

        Formats:
        - raw: JSON dump (or full HTTP request for http_request type)
        - header: Pre-formatted HTTP header string
        - cookie_string: Set-Cookie format string
        """
        if name not in self._store:
            available = ", ".join(self._store.keys()) if self._store else "none"
            return f"Error: Credential '{name}' not found. Available: {available}"

        cred = self._store[name]
        cred_type = cred["type"]
        data = cred["data"]

        if format == "raw":
            if cred_type == "http_request":
                return data.get("content", "")
            return json.dumps(cred, indent=2)

        if format == "header":
            if cred_type == "api_key":
                return f"{data.get('header_name', 'X-API-Key')}: {data['value']}"
            if cred_type == "bearer_token":
                return f"Authorization: Bearer {data['token']}"
            if cred_type == "basic_auth":
                b64 = base64.b64encode(f"{data['username']}:{data['password']}".encode()).decode()
                return f"Authorization: Basic {b64}"
            if cred_type == "custom_header":
                return f"{data['header_name']}: {data['value']}"
            if cred_type == "cookie":
                return f"Cookie: {data['name']}={data['value']}"
            if cred_type == "http_request":
                return "Error: http_request cannot be formatted as header. Use format='raw'."
            return f"Error: Cannot format {cred_type} as header"

        if format == "cookie_string":
            if cred_type != "cookie":
                return f"Error: Cannot format {cred_type} as cookie_string"
            parts = [f"{data['name']}={data['value']}"]
            parts.append(f"Domain={data.get('domain', '')}")
            parts.append(f"Path={data.get('path', '/')}")
            if data.get("http_only"):
                parts.append("HttpOnly")
            if data.get("secure"):
                parts.append("Secure")
            return "; ".join(parts)

        return f"Error: Unknown format '{format}'"

    @tool_method(name="list_credentials", catch=True)
    async def list_credentials(self) -> str:
        """List all stored credentials with their types."""
        if not self._store:
            return "No credentials stored."
        lines = ["Stored credentials:"]
        for name, cred in self._store.items():
            lines.append(f"  - {name} ({cred['type']})")
        return "\n".join(lines)

    @tool_method(name="delete_credential", catch=True)
    async def delete_credential(self, name: str) -> str:
        """Delete a stored credential by name."""
        if name not in self._store:
            return f"Error: Credential '{name}' not found."
        del self._store[name]
        return f"Credential '{name}' deleted."

    @tool_method(name="add_totp_credential", catch=True)
    def add_totp_credential(self, name: str, secret: str, digits: int = 6) -> str:
        """Add a TOTP MFA credential for generating time-based codes.

        Args:
            name: Credential identifier (e.g., "github-mfa", "aws-console")
            secret: Base32 secret from MFA setup (letters A-Z, digits 2-7)
            digits: Code length — 6, 7, or 8 (default: 6)
        """
        if digits not in (6, 7, 8):
            return f"Error: digits must be 6, 7, or 8 (got {digits})"

        secret = secret.upper().strip().replace(" ", "")
        padding_needed = (-len(secret)) & 7
        secret += "=" * padding_needed

        try:
            twofa_file = Path.home() / ".2fa"
            if not twofa_file.exists():
                twofa_file.touch(mode=0o600)
            else:
                twofa_file.chmod(0o600)

            with open(twofa_file, "a") as f:
                f.write(f"{name} {digits} {secret}\n")

            result = subprocess.run(["2fa", name], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return f"Added TOTP credential '{name}'. Current code: {result.stdout.strip()}"
            return f"Added credential but failed to generate initial code: {result.stderr}"

        except FileNotFoundError:
            return f"Added credential '{name}' but 2fa tool not found. Install rsc.io/2fa."
        except Exception as e:
            return f"Error adding TOTP credential: {e}"

    @tool_method(name="generate_mfa_code", catch=True)
    def generate_mfa_code(self, name: str) -> str:
        """Generate the current MFA code for a stored TOTP credential.

        Args:
            name: Credential identifier (from add_totp_credential)

        Returns:
            Current 6-8 digit MFA code (valid for ~30 seconds)
        """
        try:
            result = subprocess.run(["2fa", name], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
            error = result.stderr.strip()
            return f"Error: {error if error else 'Credential not found. Use add_totp_credential first.'}"
        except FileNotFoundError:
            return "Error: 2fa tool not found. Install rsc.io/2fa."
        except subprocess.TimeoutExpired:
            return "Error: Command timeout."
        except Exception as e:
            return f"Error generating MFA code: {e}"

    @tool_method(name="list_mfa_credentials", catch=True)
    def list_mfa_credentials(self) -> str:
        """List all stored MFA credentials with their current codes."""
        try:
            result = subprocess.run(["2fa"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return f"MFA Credentials:\n{result.stdout.strip()}"
            return "No MFA credentials stored. Use add_totp_credential to add one."
        except FileNotFoundError:
            return "Error: 2fa tool not installed."
        except Exception as e:
            return f"Error listing MFA credentials: {e}"
