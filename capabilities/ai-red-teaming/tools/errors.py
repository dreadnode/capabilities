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

import functools
import sys
import typing as t

from dreadnode.agents.tools import tool

__all__ = ["safe_tool"]

F = t.TypeVar("F", bound=t.Callable[..., t.Any])


def _format_error(tool_name: str, exc: BaseException) -> str:
    """Build a concise, user-facing error string (no traceback)."""
    # Keep it short and actionable; never leak a stack trace to the user.
    msg = str(exc).strip() or exc.__class__.__name__
    # Collapse multi-line / overly long internal messages.
    msg = " ".join(msg.split())
    if len(msg) > 500:
        msg = msg[:500] + "…"
    return (
        f"Error: '{tool_name}' could not complete: {msg}. "
        "This is an internal issue, not your input — please retry, or adjust "
        "parameters if it persists."
    )


def safe_tool(fn: F) -> t.Any:
    """Wrap a function as a tool that never raises to the user.

    Any exception raised inside ``fn`` is caught and returned as a clean
    string. Works for both sync and async tool functions. Applies ``@tool``
    after wrapping, so the decorated callable is a fully-formed tool.
    """
    tool_name = getattr(fn, "__name__", "tool")

    if _is_async(fn):

        @functools.wraps(fn)
        async def _async_wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
            try:
                return await fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 — deliberate catch-all safety net
                _log(tool_name, exc)
                return _format_error(tool_name, exc)

        return tool(_async_wrapper)

    @functools.wraps(fn)
    def _sync_wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 — deliberate catch-all safety net
            _log(tool_name, exc)
            return _format_error(tool_name, exc)

    return tool(_sync_wrapper)


def _is_async(fn: t.Callable[..., t.Any]) -> bool:
    import inspect

    return inspect.iscoroutinefunction(fn)


def _log(tool_name: str, exc: BaseException) -> None:
    """Best-effort diagnostic to stderr (never to the user-facing return)."""
    try:
        print(f"[AIRT] tool '{tool_name}' raised: {exc!r}", file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass
