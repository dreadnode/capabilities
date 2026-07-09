---
name: caido-sdk
description: "Direct Caido interaction via the caido-sdk-client Python library, bypassing the Caido MCP server. Prefer this over the caido-proxy MCP skill for efficiency WHEN the SDK is importable in the current runtime. If the import fails, or Caido/the MCP is not loaded, fall back to the caido-proxy skill."
---

# Caido SDK (direct)

Talk to a running Caido instance directly through `caido-sdk-client` — one
process, no per-call MCP round-trips. Preferred over the `caido-proxy` MCP skill
**only when the library is importable**.

## Step 0 — availability (probe first, never assume)

The SDK usually lives only inside the MCP's isolated env, not the agent runtime.

```bash
python3 -c "import caido_sdk_client" 2>/dev/null && echo "USE SDK" || echo "NO SDK"
```

1. Import works → use the SDK (below).
2. Import fails but `uv` is on PATH → `uv run --with caido-sdk-client script.py`.
3. Neither, or Caido unreachable → load the **`caido-proxy`** skill, use `caido_*` MCP tools.

## Auth (resolution order)

1. `CAIDO_PAT` env → `PATAuthOptions(pat=...)`, no `connect()`.
2. `~/.caido-mcp/token.json` → `TokenAuthOptions` + `await client.connect()`.
3. None → guest mode, only `health()` works.

`CAIDO_URL` overrides the `http://localhost:8080` default.

## Usage

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
        client = Client(url, auth=TokenAuthOptions(token=TokenPair(
            access_token=data["accessToken"], refresh_token=data.get("refreshToken"))))
        await client.connect()

    h = await client.health(); print(h.name, h.version, h.ready)

    # search history (HTTPQL — same syntax as the caido-proxy skill)
    conn = await client.request.list().first(20).filter('req.host.eq:"example.com"').execute()
    for edge in conn.edges:
        r, resp = edge.node.request, edge.node.response
        print(r.id, r.method, resp.status_code if resp else "-", r.host + r.path)

    # inspect one request/response
    entry = await client.request.get("<id>")
    if entry and entry.response and entry.response.raw:
        print(entry.response.raw.decode(errors="replace")[:2000])

    # replay
    from caido_sdk_client.types.replay_session import ReplaySendOptions
    s = await client.replay.sessions.create()
    res = await client.replay.send(s.id, ReplaySendOptions(
        raw=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", host="example.com", port=443, tls=True))
    print(res.task_status)

    # finding
    from caido_sdk_client.types.finding import CreateFindingOptions
    await client.findings.create("<id>", CreateFindingOptions(title="IDOR", reporter="dreadnode-agent"))

    await client.aclose()

asyncio.run(main())
```

## Notes

- HTTPQL filter syntax is identical to the `caido-proxy` skill; see its reference.
- `caido-server-auth` is a separate auth-only helper the SDK pulls in — only needed to script an initial device-flow login.
- Only *uses* the SDK; do not modify `caido-sdk-client` or the MCP wrappers.
