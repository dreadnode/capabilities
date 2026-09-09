"""Shared error-handling helpers for AI red team tools.

Provides ``safe_tool``: a decorator that wraps a tool entrypoint so that any
unexpected exception is caught and returned as a clean, user-facing string
instead of surfacing a raw traceback. This guarantees users never see internal
tool errors when running the capability.

Usage::

    from .errors import safe_tool

    @safe_tool
    def my_tool(...) -> str:
        ...

``safe_tool`` applies ``@tool`` internally, so callers should NOT also apply
``@tool``. It preserves the wrapped function's name, docstring, signature and
type annotations (via ``functools.wraps``) so the generated tool schema is
identical to a plain ``@tool``.
"""

from __future__ import annotations

import asyncio
import functools
import sys
import time
import typing as t

from dreadnode.agents.tools import tool

__all__ = ["safe_tool", "fmt_asr"]

F = t.TypeVar("F", bound=t.Callable[..., t.Any])


def fmt_asr(value: t.Any) -> str:
    """Format an attack success rate as a percentage string, robust to inputs
    given either as a 0-1 fraction (the SDK convention) or an already-scaled
    0-100 percentage. Fixes the '1.0%' display bug where a fraction was printed
    with a bare '%'.

    Examples: 1.0 -> '100%', 0.78 -> '78%', 78 -> '78%', 100 -> '100%'.
    """
    if value is None:
        return "N/A"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    pct = v * 100.0 if v <= 1.0 else v
    return f"{pct:.0f}%" if abs(pct - round(pct)) < 1e-9 else f"{pct:.1f}%"

# Transient network faults worth retrying: the connection never completed, so a
# retry commonly succeeds and the failure does not affect anything already
# running (e.g. an attack in progress). Matched on the exception's class name and
# message so we do not need to import every client library's error types.
_TRANSIENT_MARKERS = (
    "handshake",
    "timed out",
    "timeout",
    "temporarily unavailable",
    "connection reset",
    "connection aborted",
    "connection refused",
    "connection error",
    "econnreset",
    "broken pipe",
    "ssl",
    "eof occurred",
    "remotedisconnected",
    "remoteprotocolerror",
    "readtimeout",
    "connecttimeout",
    "connecterror",
    "poolTimeout".lower(),
    "max retries exceeded",
    "name or service not known",
    "temporary failure in name resolution",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
)

_MAX_RETRIES = 2
_BACKOFF_SECONDS = (1.5, 3.0)


def _clean_msg(exc: BaseException) -> str:
    msg = str(exc).strip() or exc.__class__.__name__
    msg = " ".join(msg.split())
    return msg[:500] + "..." if len(msg) > 500 else msg


def _is_transient(exc: BaseException) -> bool:
    blob = f"{type(exc).__name__} {exc}".lower()
    return any(m in blob for m in _TRANSIENT_MARKERS)


def _format_error(tool_name: str, exc: BaseException, *, transient: bool, attempts: int) -> str:
    """Build a concise, user-facing string (no traceback).

    Transient network faults are labelled non-fatal so the agent (and the user)
    know the run was not compromised and the step can simply be retried.
    """
    msg = _clean_msg(exc)
    if transient:
        return (
            f"Note: '{tool_name}' hit a transient network issue after {attempts} "
            f"attempt(s) ({msg}). This is not a problem with your request and does "
            "not affect any attack already running or already-recorded results. "
            "Retry this step; it usually succeeds on the next try."
        )
    return (
        f"Error: '{tool_name}' could not complete: {msg}. This is an internal tool "
        "issue, not your input; retry, or adjust parameters if it persists."
    )


def safe_tool(fn: F) -> t.Any:
    """Wrap a function as a tool that never raises to the user.

    Any exception raised inside ``fn`` is caught and returned as a clean string.
    Transient network faults (TLS handshake timeout, connection reset, 5xx, etc.)
    are retried up to ``_MAX_RETRIES`` times with a short backoff before being
    surfaced as an explicitly non-fatal note. Works for sync and async tools.
    """
    tool_name = getattr(fn, "__name__", "tool")

    if _is_async(fn):

        @functools.wraps(fn)
        async def _async_wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
            last: BaseException | None = None
            for attempt in range(_MAX_RETRIES + 1):
                try:
                    return await fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001 - deliberate catch-all safety net
                    last = exc
                    _log(tool_name, exc, attempt)
                    if attempt < _MAX_RETRIES and _is_transient(exc):
                        await asyncio.sleep(_BACKOFF_SECONDS[attempt])
                        continue
                    return _format_error(
                        tool_name, exc, transient=_is_transient(exc), attempts=attempt + 1
                    )
            return _format_error(tool_name, last, transient=True, attempts=_MAX_RETRIES + 1)  # type: ignore[arg-type]

        return tool(_async_wrapper)

    @functools.wraps(fn)
    def _sync_wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
        last: BaseException | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - deliberate catch-all safety net
                last = exc
                _log(tool_name, exc, attempt)
                if attempt < _MAX_RETRIES and _is_transient(exc):
                    time.sleep(_BACKOFF_SECONDS[attempt])
                    continue
                return _format_error(
                    tool_name, exc, transient=_is_transient(exc), attempts=attempt + 1
                )
        return _format_error(tool_name, last, transient=True, attempts=_MAX_RETRIES + 1)  # type: ignore[arg-type]

    return tool(_sync_wrapper)


def _is_async(fn: t.Callable[..., t.Any]) -> bool:
    import inspect

    return inspect.iscoroutinefunction(fn)


def _log(tool_name: str, exc: BaseException, attempt: int = 0) -> None:
    """Best-effort diagnostic to stderr (never to the user-facing return)."""
    try:
        print(f"[AIRT] tool '{tool_name}' raised (attempt {attempt + 1}): {exc!r}", file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass
