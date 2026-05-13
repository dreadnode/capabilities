"""Keep a Dreadnode runtime sandbox alive while a long analysis is in flight.

Calls ``POST /api/v1/org/<org>/ws/<workspace>/runtimes/<runtime_id>/keepalive``
on a loop until interrupted. Each call extends the sandbox by up to one hour
(server-side cap), so the loop interval is shorter than that — default 30
minutes leaves a comfortable buffer.

Stdlib-only on purpose so it works without the SDK installed. Run it next to
``analyze.py``::

    DREADNODE_API_KEY=... python scripts/keepalive.py \\
        <runtime-uuid> --platform-url https://app.dreadnode.io \\
        --org <org-slug> --workspace <workspace-slug>

Auth: this hits the *platform* API, not the sandbox URL. Use your platform
API key (the one your ``dn`` CLI is logged in with), not the sandbox token
the launcher uses.
"""

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from urllib.parse import quote

DEFAULT_EXTEND_SECONDS = 3600  # server cap
DEFAULT_INTERVAL_SECONDS = 1800  # half the extend window — always stay ahead

_stop = False


def _handle_signal(_signum: int, _frame: object) -> None:
    global _stop
    _stop = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("runtime_id", help="Runtime UUID")
    parser.add_argument(
        "--platform-url",
        default=os.environ.get("DREADNODE_PLATFORM_URL", "https://platform.dreadnode.io"),
        help="Platform base URL (default: $DREADNODE_PLATFORM_URL or platform.dreadnode.io).",
    )
    parser.add_argument(
        "--org",
        default=os.environ.get("DREADNODE_ORG"),
        help="Organization slug (default: $DREADNODE_ORG).",
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("DREADNODE_WORKSPACE"),
        help="Workspace slug (default: $DREADNODE_WORKSPACE).",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("DREADNODE_API_KEY"),
        help="Platform API key (default: $DREADNODE_API_KEY).",
    )
    parser.add_argument(
        "--extend-seconds",
        type=int,
        default=DEFAULT_EXTEND_SECONDS,
        help=f"Seconds to add per keepalive (60–3600, default {DEFAULT_EXTEND_SECONDS}).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        help=f"Seconds between keepalives (default {DEFAULT_INTERVAL_SECONDS}).",
    )
    args = parser.parse_args()
    if not args.org:
        parser.error("--org or $DREADNODE_ORG is required")
    if not args.workspace:
        parser.error("--workspace or $DREADNODE_WORKSPACE is required")
    if not args.api_key:
        parser.error("--api-key or $DREADNODE_API_KEY is required")
    if not 60 <= args.extend_seconds <= 3600:
        parser.error("--extend-seconds must be between 60 and 3600")
    if args.interval < 30:
        parser.error("--interval must be at least 30 seconds")
    return args


def keepalive_url(platform_url: str, org: str, workspace: str, runtime_id: str) -> str:
    base = platform_url.rstrip("/")
    return (
        f"{base}/api/v1/org/{quote(org, safe='')}/ws/{quote(workspace, safe='')}"
        f"/runtimes/{quote(runtime_id, safe='')}/keepalive"
    )


def keepalive_once(url: str, api_key: str, extend_seconds: int) -> dict:
    body = json.dumps({"extend_seconds": extend_seconds}).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - URL built from validated args
        url,
        data=body,
        method="POST",
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
        payload = response.read().decode("utf-8")
        return json.loads(payload) if payload else {}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def main() -> int:
    args = parse_args()
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    url = keepalive_url(args.platform_url, args.org, args.workspace, args.runtime_id)
    print(f"[{now_iso()}] Keepalive loop targeting {url}")
    print(f"[{now_iso()}] Extending by {args.extend_seconds}s every {args.interval}s. Ctrl+C to stop.")

    backoff = 5
    consecutive_failures = 0
    while not _stop:
        try:
            data = keepalive_once(url, args.api_key, args.extend_seconds)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace").strip()[:300]
            consecutive_failures += 1
            print(f"[{now_iso()}] Keepalive failed: HTTP {exc.code} {exc.reason} — {detail}")
            if exc.code in (401, 403, 404):
                print(f"[{now_iso()}] Fatal status; not retrying.")
                return 2
            if consecutive_failures >= 5:
                print(f"[{now_iso()}] Giving up after {consecutive_failures} consecutive failures.")
                return 3
            sleep_for = min(backoff, args.interval)
            backoff = min(backoff * 2, 120)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            consecutive_failures += 1
            print(f"[{now_iso()}] Keepalive transport error: {type(exc).__name__}: {exc}")
            if consecutive_failures >= 5:
                print(f"[{now_iso()}] Giving up after {consecutive_failures} consecutive failures.")
                return 3
            sleep_for = min(backoff, args.interval)
            backoff = min(backoff * 2, 120)
        else:
            expires_at = data.get("expires_at") or "(unknown)"
            print(f"[{now_iso()}] Extended ok; new expires_at={expires_at}")
            consecutive_failures = 0
            backoff = 5
            sleep_for = args.interval

        # Interruptible sleep so Ctrl+C exits promptly.
        deadline = time.monotonic() + sleep_for
        while not _stop and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))

    print(f"[{now_iso()}] Stopping on signal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
