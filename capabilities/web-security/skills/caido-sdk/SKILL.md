---
name: caido-sdk
description: "Direct Caido interaction via the caido-sdk-client Python library, bypassing the Caido MCP server. Prefer this over the caido-proxy MCP skill for efficiency WHEN the SDK is importable in the current runtime. If the import fails, or Caido/the MCP is not loaded, fall back to the caido-proxy skill. For curl-through-Caido testing, match & replace rules, or replay handoffs, use caido-mode instead."
compatibility: "Requires caido-sdk-client >= 0.3.0 (importable or via uv) and a reachable Caido instance (CAIDO_URL)."
---

# Caido SDK (direct)

Talk to a running Caido instance directly through `caido-sdk-client` — one
process, no per-call MCP round-trips. Preferred over the `caido-proxy` MCP skill
**only when the library is importable**.

> **Sibling surfaces.** This capability ships four Caido surfaces against one
> instance. Use **this** skill for in-process Python read/replay. For
> curl-through-Caido testing, Match & Replace rules, or replay handoff, use
> **`caido-mode`**. For tool-call access without writing code, use
> **`caido-proxy`** (`caido` MCP for the basics, `caido-go` MCP for batch send,
> race windows, intercept, environments, WS). They share `CAIDO_URL`; only
> `caido-mode` uses a separate credential store, so none of them clobber each
> other's auth.

## Version floor (important)

Requires **`caido-sdk-client >= 0.3.0`**. Earlier releases (0.2.x) hardcode the
pre-0.57 replay schema — they select `collection`/`activeEntry` on
`ReplaySession` and omit `ReplaySessionKind` — so replay calls fail against
Caido >= 0.57 with `Unknown field collection on type ReplaySession`. 0.3.0 added
the versioned transport split (`transport/latest` vs `transport/v0_56`) and
negotiates the right schema per instance.

```bash
python3 -c "import importlib.metadata as m; print(m.version('caido-sdk-client'))"
# < 0.3.0 and talking to Caido >= 0.57? use:  uv run --with 'caido-sdk-client>=0.3.0' script.py
```

## Step 0 — availability (probe first, never assume)

The SDK usually lives only inside the MCP's isolated env, not the agent runtime.

```bash
python3 -c "import caido_sdk_client" 2>/dev/null && echo "USE SDK" || echo "NO SDK"
```

1. Import works → check the version floor above, then use the SDK (below).
2. Import fails but `uv` is on PATH → `uv run --with 'caido-sdk-client>=0.3.0' script.py`.
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

    # replay — SEED the session, and bound the send (see notes below)
    from caido_sdk_client.types.replay_session import (
        CreateReplaySessionFromRaw, CreateReplaySessionOptions, ReplaySendOptions)
    from caido_sdk_client.types.network import ConnectionInfoInput
    raw_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    conn = ConnectionInfoInput(host="example.com", port=443, is_tls=True)
    s = await client.replay.sessions.create(CreateReplaySessionOptions(
        request_source=CreateReplaySessionFromRaw(raw=raw_req, connection=conn)))
    res = await asyncio.wait_for(
        client.replay.send(s.id, ReplaySendOptions(raw=raw_req, connection=conn)), 30)
    print(getattr(res.status, "value", res.status))   # "DONE" | "CANCELLED" | "ERROR"
    if res.entry and res.entry.response:
        print(res.entry.response.status_code)

    # finding
    from caido_sdk_client.types.finding import CreateFindingOptions
    await client.findings.create("<id>", CreateFindingOptions(title="IDOR", reporter="dreadnode-agent"))

    await client.aclose()

asyncio.run(main())
```

## API shapes that bite

Three mistakes account for most runtime `TypeError`s here. The signatures below
are verified against `caido-sdk-client` 0.3.0:

| Wrong | Right |
|---|---|
| `ReplaySendOptions(raw=…, host=…, port=…, tls=…)` | `ReplaySendOptions(raw=…, connection=ConnectionInfoInput(host=…, port=…, is_tls=…))` |
| `ConnectionInfoInput(…, tls=True)` | `ConnectionInfoInput(…, is_tls=True)` |
| `result.task_status` | `result.status` — `"DONE"` / `"CANCELLED"` / `"ERROR"` |

`ReplaySendOptions` fields are exactly `raw`, `connection`, `settings`.
`ReplaySendResult` fields are exactly `entry`, `status`, `error`.

### Two more, both verified live against Caido 0.57.1

**Seed the session, or `send()` refuses.** On >= 0.57, `send()` updates the
draft of an *existing* entry and then starts a replay task. A bare
`sessions.create()` produces a session with no entries, so `send()` raises
`OtherUserError: Replay session has no entries`. Create the session with
`request_source=CreateReplaySessionFromRaw(raw=..., connection=...)`.

**Always bound `send()` with `asyncio.wait_for`.** After starting the task the
SDK waits on a task-finished *subscription*. If the target answers before that
subscription is established, the event is missed and the await never returns —
reproducible roughly 2 in 3 times against a localhost target. The request is
still sent, so on timeout recover the result instead of assuming failure:

```python
try:
    res = await asyncio.wait_for(client.replay.send(s.id, opts), 30)
    entry_id = res.entry.id
except TimeoutError:
    session = await client.replay.sessions.get(s.id)
    conn = await session.entries().last(1).execute()
    entry_id = conn.edges[-1].node.id

# Re-fetch by id — entries listed off a session carry no response body,
# and `response` hangs off the ENTRY, not off entry.request.
entry = await client.replay.entries.get(entry_id)
print(entry.response.status_code, entry.response.raw[:200])
```

`status` may arrive as a `TaskStatus` enum whose `str()` is `"TaskStatus.DONE"`
— unwrap with `getattr(status, "value", status)`.

Confirm against whatever is actually installed before writing a long script:

```bash
python3 -c "
import dataclasses as d
from caido_sdk_client.types.replay_session import ReplaySendOptions, ReplaySendResult
from caido_sdk_client.types.network import ConnectionInfoInput
for c in (ReplaySendOptions, ReplaySendResult, ConnectionInfoInput):
    print(c.__name__, [f.name for f in d.fields(c)])"
```

## Notes

- HTTPQL filter syntax is identical to the `caido-proxy` skill; see its reference.
- `caido-server-auth` is a separate auth-only helper the SDK pulls in — only needed to script an initial device-flow login.
- Only *uses* the SDK; do not modify `caido-sdk-client` or the MCP wrappers.
