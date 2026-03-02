#!/usr/bin/env python3
"""Callback tool for out-of-band vulnerability testing.

Uses webhook.site as primary provider and interactsh-client (CLI, via pdtm)
as fallback for generating callback URLs for SSRF, XXE, SSTI, blind injection.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# httpx for webhook.site API calls
try:
    import httpx
except ImportError:
    print(json.dumps({"error": "httpx not installed. Run: pip install httpx"}))
    sys.exit(1)

# Persistent state across invocations
STATE_FILE = Path(os.environ.get("CALLBACK_STATE_PATH", "/tmp/dreadweb_callback.json"))


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def _register_webhook_site() -> dict:
    """Register with webhook.site and return state."""
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.post(
                "https://webhook.site/token",
                json={
                    "default_content": "OK",
                    "default_status": 200,
                    "default_content_type": "text/plain",
                },
            )
            if response.status_code != 201:
                return {"error": f"webhook.site registration failed: HTTP {response.status_code}"}

            data = response.json()
            token_id = data.get("uuid")
            if not token_id:
                return {"error": "webhook.site registration failed: no UUID in response"}

            return {
                "provider": "webhook_site",
                "token_id": token_id,
                "callback_url": f"https://webhook.site/{token_id}",
                "registered_at": datetime.now(timezone.utc).isoformat(),
                "seen_ids": [],
            }
    except Exception as e:
        return {"error": f"webhook.site registration error: {e}"}


def _register_interactsh() -> dict:
    """Register with interactsh-client CLI (fallback)."""
    try:
        # Start interactsh-client briefly to get a URL
        proc = subprocess.run(
            ["interactsh-client", "-json", "-n", "1"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        # Parse the URL from output
        for line in proc.stdout.splitlines():
            try:
                data = json.loads(line)
                if "url" in data:
                    return {
                        "provider": "interactsh",
                        "callback_url": data["url"],
                        "registered_at": datetime.now(timezone.utc).isoformat(),
                    }
            except json.JSONDecodeError:
                # interactsh-client prints the URL as plain text on first line
                if ".oast." in line or ".interact." in line:
                    url = line.strip()
                    if not url.startswith("http"):
                        url = f"https://{url}"
                    return {
                        "provider": "interactsh",
                        "callback_url": url,
                        "registered_at": datetime.now(timezone.utc).isoformat(),
                    }
        return {"error": "interactsh-client did not return a URL"}
    except FileNotFoundError:
        return {"error": "interactsh-client not found"}
    except subprocess.TimeoutExpired:
        return {"error": "interactsh-client timed out"}
    except Exception as e:
        return {"error": f"interactsh error: {e}"}


def get_callback_url(params: dict) -> dict:
    state = load_state()
    protocol = params.get("protocol", "http")

    # Return existing URL if already registered
    if state.get("callback_url"):
        url = state["callback_url"]
        provider = state.get("provider", "unknown")
    else:
        # Try webhook.site first, fall back to interactsh
        result = _register_webhook_site()
        if "error" in result:
            result = _register_interactsh()
        if "error" in result:
            return result

        state.update(result)
        save_state(state)
        url = state["callback_url"]
        provider = state["provider"]

    # Format based on protocol preference
    if protocol == "https" and url.startswith("http://"):
        url = url.replace("http://", "https://", 1)
    elif protocol == "dns":
        url = url.replace("http://", "").replace("https://", "")

    return {"result": f"{url}\n\nProvider: {provider}. Inject this URL in SSRF/XXE/SSTI payloads, then use check_callbacks to see if the target contacted it."}


def check_callbacks(params: dict) -> dict:
    state = load_state()
    since_seconds = params.get("since_seconds", 300)

    if not state.get("callback_url"):
        return {"error": "No callback URL registered. Use get_callback_url first."}

    provider = state.get("provider")

    if provider == "webhook_site":
        return _poll_webhook_site(state, since_seconds)
    elif provider == "interactsh":
        return {"result": "For interactsh, run in bash: interactsh-client -json | head -20\n\nThe CLI will show any interactions with your callback domain."}
    else:
        return {"error": f"Unknown provider: {provider}"}


def _poll_webhook_site(state: dict, since_seconds: int) -> dict:
    token_id = state.get("token_id")
    if not token_id:
        return {"error": "No webhook.site token_id in state."}

    seen_ids = set(state.get("seen_ids", []))

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                f"https://webhook.site/token/{token_id}/requests",
                params={"sorting": "newest"},
            )
            if response.status_code != 200:
                return {"error": f"Poll failed: HTTP {response.status_code}"}

            data = response.json()
            requests_data = data.get("data", [])

            if not requests_data:
                return {"result": "No callback interactions received yet. Target may not have contacted the callback server."}

            # Filter to new + recent
            cutoff = time.time() - since_seconds
            interactions = []

            for item in requests_data:
                req_id = item.get("uuid", "")
                if req_id in seen_ids:
                    continue

                created_at = item.get("created_at", "")
                try:
                    ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    if ts.timestamp() < cutoff:
                        continue
                except (ValueError, AttributeError):
                    pass

                seen_ids.add(req_id)

                method = item.get("method", "GET")
                url = item.get("url", "")
                ip = item.get("ip", "unknown")
                content = item.get("content", "")
                headers = item.get("headers", {})

                # Extract path
                path = "/"
                try:
                    parsed = urlparse(url)
                    path = parsed.path or "/"
                    if parsed.query:
                        path += f"?{parsed.query}"
                except Exception:
                    pass

                # Build raw request representation
                raw = f"{method} {path} HTTP/1.1\n"
                if headers:
                    for k, v in headers.items():
                        if isinstance(v, list):
                            v = ", ".join(str(x) for x in v)
                        raw += f"{k}: {v}\n"
                if content:
                    raw += f"\n{content}"

                interactions.append({
                    "time": created_at,
                    "method": method,
                    "path": path,
                    "ip": ip,
                    "raw_request": raw[:1000],
                })

            # Save seen IDs
            state["seen_ids"] = list(seen_ids)
            save_state(state)

            if not interactions:
                return {"result": "No new callback interactions since last check."}

            lines = [f"Received {len(interactions)} callback interactions:"]
            for i, ix in enumerate(interactions[:10], 1):
                lines.append(f"  {i}. [{ix['time']}] {ix['method']} {ix['path']} from {ix['ip']}")

            # Show most recent raw request
            if interactions:
                lines.append(f"\nMost recent request:\n{interactions[-1]['raw_request']}")

            return {"result": "\n".join(lines)}

    except Exception as e:
        return {"error": f"Poll error: {e}"}


def reset_callback(_params: dict) -> dict:
    if STATE_FILE.exists():
        STATE_FILE.unlink()
    return {"result": "Callback state reset. Next get_callback_url will register a new URL."}


METHODS = {
    "get_callback_url": get_callback_url,
    "check_callbacks": check_callbacks,
    "reset_callback": reset_callback,
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
