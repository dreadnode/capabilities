---
name: caido-sdk
description: "Direct Caido interaction via the caido-sdk-client Python library, bypassing the Caido MCP server. Prefer this over the caido-proxy MCP skill for efficiency WHEN the SDK is importable in the current runtime. If the import fails, or Caido/the MCP is not loaded, fall back to the caido-proxy skill."
---

# Caido SDK (direct)

Talk to a running Caido instance directly through the `caido-sdk-client` Python
library instead of the Caido MCP server. When the library is importable, this is
more efficient than MCP: one process, no per-call tool round-trips, and full
access to the SDK's typed objects.

This does not replace the `caido-proxy` skill — it is the preferred path only
when the SDK is available. Decide with the availability check below.

## Step 0 — Availability check (do this first)

The SDK is often only installed inside the Caido MCP's isolated env, not the
agent runtime. Probe before committing:

```bash
python3 -c "import caido_sdk_client" 2>/dev/null \
  && echo "USE SDK DIRECTLY" || echo "SDK NOT IN RUNTIME"
```

Fallback order:

1. `import caido_sdk_client` succeeds → use it directly (this skill).
2. Import fails but `uv` is on PATH → run one-off scripts with
   `uv run --with caido-sdk-client script.py` (ephemeral install, matches how
   the MCP provisions itself). Needs network on first run.
3. Neither works, or Caido itself is not reachable → **load the `caido-proxy`
   skill and use the `caido_*` MCP tools instead.**

Do not assume the SDK is present just because "caido" is in the task. If Step 0
prints `SDK NOT IN RUNTIME` and `uv` is unavailable, switch to `caido-proxy`.

## Authentication

Resolution order (same as the MCP server uses):

1. `CAIDO_PAT` env var → `PATAuthOptions(pat=...)`, no `connect()` needed.
2. `~/.caido-mcp/token.json` (`accessToken` / `refreshToken`) →
   `TokenAuthOptions` + `await client.connect()`.
3. No auth → guest mode, only `health()` works.

`CAIDO_URL` overrides the default `http://localhost:8080`.

## Minimal usage

```python
import asyncio, os, json
from pathlib import Path
from caido_sdk_client import Client

async def main():
    url = os.environ.get("CAIDO_URL", "http://localhost:8080")
    pat = os.environ.get("CAIDO_PAT")
    if pat:
        from caido_sdk_client.auth import PATAuthOptions
        client = Client(url, auth=PATAuthOptions(pat=pat))
    else:
        from caido_sdk_client.auth import TokenAuthOptions, TokenPair
        data = json.loads((Path.home() / ".caido-mcp" / "token.json").read_text())
        client = Client(url, auth=TokenAuthOptions(
            token=TokenPair(access_token=data["accessToken"],
                            refresh_token=data.get("refreshToken"))))
        await client.connect()

    # health
    h = await client.health()
    print(h.name, h.version, h.ready)

    # search proxy history (HTTPQL — same filter syntax as the MCP/caido-proxy skill)
    conn = await client.request.list().first(20).filter('req.host.eq:"example.com"').execute()
    for edge in conn.edges:
        r = edge.node.request
        resp = edge.node.response
        print(r.id, r.method, resp.status_code if resp else "-", r.host + r.path)

    # get one request/response
    entry = await client.request.get("<request_id>")
    if entry and entry.response and entry.response.raw:
        print(entry.response.raw.decode(errors="replace")[:2000])

    # replay a modified raw request
    from caido_sdk_client.types.replay_session import ReplaySendOptions
    session = await client.replay.sessions.create()
    result = await client.replay.send(session.id, ReplaySendOptions(
        raw=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        host="example.com", port=443, tls=True))
    print(result.task_status)

    # document a finding
    from caido_sdk_client.types.finding import CreateFindingOptions
    await client.findings.create("<request_id>", CreateFindingOptions(
        title="IDOR in /api/users/{id}", reporter="dreadnode-agent"))

    await client.aclose()

asyncio.run(main())
```

Run inline with `python3 - <<'PY' ... PY`, or via `uv run --with caido-sdk-client`
when the library is not in the runtime env.

## HTTPQL

Filter syntax is identical to the `caido-proxy` skill (e.g.
`req.host.eq:"example.com" AND req.method.eq:"POST"`, `resp.code.gte:500`). See
that skill's quick reference — do not duplicate it here.

## Notes

- `caido-server-auth` is a separate auth-only helper package (device-flow / PAT
  approval) that `caido-sdk-client` pulls in. You normally interact only with
  `caido_sdk_client`; reach for `caido_server_auth` only when scripting an
  initial device-flow login.
- Do not modify the `caido-sdk-client` package or the capability's MCP wrappers.
  This skill only *uses* the SDK.
