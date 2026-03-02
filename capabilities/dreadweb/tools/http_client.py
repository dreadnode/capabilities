#!/usr/bin/env python3
"""HTTP client tool with persistent session management and concurrency.

Provides execute_http with automatic cookie persistence, user-agent rotation,
response formatting, and concurrent request support.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import asyncio
import json
import os
import random
import sys
from urllib.parse import parse_qs, urlparse

# httpx must be available in the sandbox (pip install httpx)
try:
    import httpx
except ImportError:
    print(json.dumps({"error": "httpx not installed. Run: pip install httpx"}))
    sys.exit(1)

# Persistent cookie jar file across invocations
COOKIE_FILE = os.environ.get("HTTP_COOKIE_PATH", "/tmp/dreadweb_cookies.json")
DEFAULT_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "30"))
MAX_OUTPUT = int(os.environ.get("HTTP_MAX_OUTPUT", "50000"))
MAX_CONCURRENT = int(os.environ.get("HTTP_MAX_CONCURRENT", "10"))

# User-agent pool for rotation
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
]


def _load_cookies() -> dict:
    try:
        if os.path.exists(COOKIE_FILE):
            with open(COOKIE_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_cookies(cookies: dict) -> None:
    try:
        with open(COOKIE_FILE, "w") as f:
            json.dump(cookies, f, indent=2)
    except Exception:
        pass


def _cookies_to_httpx(cookies: dict) -> httpx.Cookies:
    jar = httpx.Cookies()
    for name, value in cookies.items():
        jar.set(name, value)
    return jar


def _httpx_to_cookies(jar) -> dict:
    result = {}
    for cookie in jar.jar:
        result[cookie.name] = cookie.value
    return result


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


async def _execute_single(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    timeout: int | None = None,
) -> dict:
    method = method.upper()
    headers = dict(headers) if headers else {}
    request_timeout = timeout or DEFAULT_TIMEOUT

    # Decode unicode escapes in URL
    try:
        url = url.encode("utf-8").decode("unicode_escape")
    except Exception:
        pass

    # Add random user-agent if not provided
    if "user-agent" not in {k.lower() for k in headers}:
        headers["User-Agent"] = _random_ua()

    try:
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=body.encode() if body else None,
            timeout=request_timeout,
        )

        response_text = response.text
        if len(response_text) > MAX_OUTPUT:
            total = len(response_text)
            response_text = response_text[:MAX_OUTPUT] + f"\n\n... [TRUNCATED: {total} chars total]"

        # Detect content type
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            lang = "json"
        elif "text/html" in content_type:
            lang = "html"
        elif "xml" in content_type:
            lang = "xml"
        else:
            lang = "text"

        # Parse query params for display
        parsed = urlparse(url)
        query_params = {}
        if parsed.query:
            for k, v in parse_qs(parsed.query).items():
                query_params[k] = v[0] if len(v) == 1 else v

        result = {
            "method": method,
            "url": url,
            "status_code": response.status_code,
            "content_type": lang,
            "response_headers": dict(response.headers),
        }
        if query_params:
            result["query_params"] = query_params
        if body:
            result["request_body"] = body[:5000]

        result["body"] = response_text

        return result

    except httpx.TimeoutException:
        return {"error": f"Request timed out after {request_timeout}s", "url": url}
    except httpx.ConnectError as e:
        return {"error": f"Connection failed: {e}", "url": url}
    except Exception as e:
        return {"error": f"Request failed: {e}", "url": url}


async def execute_http(params: dict) -> dict:
    cookies = _load_cookies()
    jar = _cookies_to_httpx(cookies)

    async with httpx.AsyncClient(follow_redirects=True, cookies=jar) as client:
        result = await _execute_single(
            client,
            url=params["url"],
            method=params.get("method", "GET"),
            headers=params.get("headers"),
            body=params.get("body"),
            timeout=params.get("timeout"),
        )

        # Persist cookies
        updated = _httpx_to_cookies(client.cookies)
        cookies.update(updated)
        _save_cookies(cookies)

    if "error" in result:
        return result

    return {"result": f"HTTP {result['status_code']}\n\n{result['body']}"}


async def execute_http_batch(params: dict) -> dict:
    """Execute multiple HTTP requests concurrently with shared session."""
    requests = params.get("requests", [])
    if not requests:
        return {"error": "No requests provided. Pass a 'requests' array."}

    max_concurrent = params.get("max_concurrent", MAX_CONCURRENT)
    cookies = _load_cookies()
    jar = _cookies_to_httpx(cookies)
    semaphore = asyncio.Semaphore(max_concurrent)

    async with httpx.AsyncClient(follow_redirects=True, cookies=jar) as client:
        async def bounded_request(req: dict) -> dict:
            async with semaphore:
                return await _execute_single(
                    client,
                    url=req["url"],
                    method=req.get("method", "GET"),
                    headers=req.get("headers"),
                    body=req.get("body"),
                    timeout=req.get("timeout"),
                )

        results = await asyncio.gather(*[bounded_request(r) for r in requests])

        # Persist cookies
        updated = _httpx_to_cookies(client.cookies)
        cookies.update(updated)
        _save_cookies(cookies)

    # Format summary
    summary = []
    for i, (req, res) in enumerate(zip(requests, results)):
        if "error" in res:
            summary.append(f"[{i+1}] {req.get('method', 'GET')} {req['url']} -> ERROR: {res['error']}")
        else:
            summary.append(f"[{i+1}] {req.get('method', 'GET')} {req['url']} -> {res['status_code']}")

    return {
        "result": "\n".join(summary),
        "responses": results,
    }


def reset_http_session(_params: dict) -> dict:
    cookies = _load_cookies()
    count = len(cookies)
    _save_cookies({})
    return {"result": f"HTTP session reset. Cleared {count} cookies."}


def get_http_cookies(_params: dict) -> dict:
    cookies = _load_cookies()
    if not cookies:
        return {"result": "No cookies in current HTTP session."}

    lines = [f"HTTP Session Cookies ({len(cookies)} total):", ""]
    for i, (name, value) in enumerate(cookies.items(), 1):
        display_value = value[:50] + "..." if len(value) > 50 else value
        lines.append(f"{i}. {name} = {display_value}")

    return {"result": "\n".join(lines)}


METHODS = {
    "execute_http": lambda p: asyncio.run(execute_http(p)),
    "execute_http_batch": lambda p: asyncio.run(execute_http_batch(p)),
    "reset_http_session": reset_http_session,
    "get_http_cookies": get_http_cookies,
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
