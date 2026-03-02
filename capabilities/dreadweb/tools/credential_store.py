#!/usr/bin/env python3
"""Credential store tool for web security testing.

Manages typed credentials (API keys, bearer tokens, cookies, basic auth, etc.)
with formatting helpers for HTTP requests and TOTP/MFA code generation via 2fa CLI.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

# Persistent state file for credentials across tool invocations
STATE_FILE = Path(os.environ.get("CREDENTIAL_STORE_PATH", "/tmp/dreadweb_credentials.json"))


def load_store() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_store(store: dict) -> None:
    STATE_FILE.write_text(json.dumps(store, indent=2))


def store_credential(params: dict) -> dict:
    name = params["name"]
    cred_type = params["credential_type"]
    cred_data = params.get("credential_data", {})

    valid_types = ["api_key", "bearer_token", "cookie", "basic_auth", "custom_header", "http_request"]
    if cred_type not in valid_types:
        return {"error": f"Unknown credential type '{cred_type}'. Valid: {', '.join(valid_types)}"}

    store = load_store()
    store[name] = {"type": cred_type, "data": cred_data}
    save_store(store)

    if cred_type == "http_request":
        return {"result": f"Credential '{name}' stored as {cred_type}. Use get_credential with format='raw' to see the full HTTP request."}
    return {"result": f"Credential '{name}' stored as {cred_type}. Use get_credential with format='header' to use it."}


def get_credential(params: dict) -> dict:
    name = params["name"]
    fmt = params.get("format", "raw")
    store = load_store()

    if name not in store:
        available = ", ".join(store.keys()) if store else "none"
        return {"error": f"Credential '{name}' not found. Available: {available}"}

    cred = store[name]
    cred_type = cred["type"]
    data = cred["data"]

    if fmt == "raw":
        if cred_type == "http_request":
            return {"result": data.get("content", "")}
        return {"result": json.dumps(cred, indent=2)}

    elif fmt == "header":
        if cred_type == "api_key":
            header_name = data.get("header_name", "X-API-Key")
            return {"result": f"{header_name}: {data['value']}"}
        elif cred_type == "bearer_token":
            return {"result": f"Authorization: Bearer {data['token']}"}
        elif cred_type == "basic_auth":
            auth_str = f"{data['username']}:{data['password']}"
            b64 = base64.b64encode(auth_str.encode()).decode()
            return {"result": f"Authorization: Basic {b64}"}
        elif cred_type == "custom_header":
            return {"result": f"{data['header_name']}: {data['value']}"}
        elif cred_type == "cookie":
            return {"result": f"Cookie: {data['name']}={data['value']}"}
        elif cred_type == "http_request":
            return {"error": "http_request type cannot be formatted as header. Use format='raw' to see the full request."}
        return {"error": f"Cannot format {cred_type} as header"}

    elif fmt == "cookie_string":
        if cred_type == "cookie":
            parts = [f"{data['name']}={data['value']}"]
            parts.append(f"Domain={data.get('domain', '')}")
            parts.append(f"Path={data.get('path', '/')}")
            if data.get("http_only"):
                parts.append("HttpOnly")
            if data.get("secure"):
                parts.append("Secure")
            return {"result": "; ".join(parts)}
        return {"error": f"Cannot format {cred_type} as cookie_string"}

    return {"error": f"Unknown format '{fmt}'"}


def list_credentials(_params: dict) -> dict:
    store = load_store()
    if not store:
        return {"result": "No credentials stored."}

    lines = ["Stored credentials:"]
    for name, cred in store.items():
        lines.append(f"  - {name} ({cred['type']})")
    return {"result": "\n".join(lines)}


def delete_credential(params: dict) -> dict:
    name = params["name"]
    store = load_store()
    if name not in store:
        return {"error": f"Credential '{name}' not found."}
    del store[name]
    save_store(store)
    return {"result": f"Credential '{name}' deleted."}


def add_totp_credential(params: dict) -> dict:
    name = params["name"]
    secret = params["secret"].upper().strip().replace(" ", "")
    digits = params.get("digits", 6)

    if digits not in [6, 7, 8]:
        return {"error": f"digits must be 6, 7, or 8 (got {digits})"}

    # Pad to 8-byte boundary for rsc/2fa
    padding_needed = (-len(secret)) & 7
    secret += "=" * padding_needed

    twofa_file = Path.home() / ".2fa"
    if not twofa_file.exists():
        twofa_file.touch(mode=0o600)
    else:
        twofa_file.chmod(0o600)

    with open(twofa_file, "a") as f:
        f.write(f"{name} {digits} {secret}\n")

    # Generate first code to verify
    try:
        result = subprocess.run(["2fa", name], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            code = result.stdout.strip()
            return {"result": f"Added TOTP credential '{name}'. Current code: {code}"}
        return {"result": f"Added credential but failed to generate initial code: {result.stderr}"}
    except FileNotFoundError:
        return {"result": f"Added credential '{name}' but 2fa tool not found. Install rsc.io/2fa."}
    except Exception as e:
        return {"error": f"Error adding TOTP credential: {e}"}


def generate_mfa_code(params: dict) -> dict:
    name = params["name"]
    try:
        result = subprocess.run(["2fa", name], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return {"result": result.stdout.strip()}
        error = result.stderr.strip()
        return {"error": error if error else "Credential not found. Use add_totp_credential first."}
    except FileNotFoundError:
        return {"error": "2fa tool not found. Ensure rsc.io/2fa is installed."}
    except subprocess.TimeoutExpired:
        return {"error": "Command timeout."}
    except Exception as e:
        return {"error": f"Error generating MFA code: {e}"}


def list_mfa_credentials(_params: dict) -> dict:
    try:
        result = subprocess.run(["2fa"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return {"result": f"MFA Credentials:\n{result.stdout.strip()}"}
        return {"result": "No MFA credentials stored. Use add_totp_credential to add one."}
    except FileNotFoundError:
        return {"error": "2fa tool not installed."}
    except Exception as e:
        return {"error": f"Error listing MFA credentials: {e}"}


METHODS = {
    "store_credential": store_credential,
    "get_credential": get_credential,
    "list_credentials": list_credentials,
    "delete_credential": delete_credential,
    "add_totp_credential": add_totp_credential,
    "generate_mfa_code": generate_mfa_code,
    "list_mfa_credentials": list_mfa_credentials,
}


def main():
    raw = sys.stdin.read()
    request = json.loads(raw)
    method = request.get("method", request.get("name", ""))
    params = request.get("parameters", {})

    handler = METHODS.get(method)
    if not handler:
        print(json.dumps({"error": f"Unknown method: {method}"}))
        sys.exit(1)

    try:
        result = handler(params)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
