"""Shared helpers for long-lived relay/listener subprocesses.

Relay tools (ntlmrelayx, krbrelayx, certipy relay) are listeners: they stay up
waiting for a coerced or relayed authentication to arrive, which can take far
longer than a one-shot command. These helpers stream such a listener's stdout,
return early when a success line appears, bound how much output is retained, and
distinguish three end states: a success, a listener still running when its
window expires (caught nothing — a normal result), and a listener that exited on
its own (a crash or misconfiguration, surfaced as an error).
"""

import asyncio
import contextlib
import os
import signal

from loguru import logger

# Stdout substrings that indicate an ntlmrelayx relay caught/relayed an auth.
# Each tool passes the list that matches its own output; callers must pass one
# explicitly (there is no shared default, so no tool can silently match against
# ntlmrelayx's strings).
NTLMRELAYX_SUCCESS_PATTERNS = [
    "certificate",
    "got certificate",
    "dumping",
    "sam hashes",
    "authenticating against",
    "relay succeeded",
    "shadow credentials",
    "msds-keycredentiallink",
    "escalating",
    "adding computer",
    "laps password",
    "gmsa password",
]

# argv flags whose following value is a credential and must not be logged.
_SECRET_FLAGS = {"-p", "--password", "-hashes", "--hashes", "-aeskey", "--aeskey", "-aesKey"}

# How long to wait after SIGTERM before escalating to SIGKILL.
_SIGKILL_TIMEOUT = 5.0

# Longest a single readline() blocks before we re-check the deadline / liveness.
_READ_POLL_INTERVAL = 5.0

# How long to keep draining follow-up lines after a success match, to capture
# data (certificate values, hashes) printed just after the success line.
_SUCCESS_DRAIN_SECONDS = 5.0

# Ceiling on retained stdout. A chatty listener (e.g. an NTDS dump) over a long
# window would otherwise grow the buffer and the returned string without bound.
_MAX_OUTPUT_BYTES = 1_000_000

# Grace period to reap a process that closed stdout, so its exit code settles
# before we decide whether it exited on its own or is still listening.
_EXIT_SETTLE_SECONDS = 0.5


def _redact_cmd(cmd: list[str]) -> list[str]:
    """Return a copy of ``cmd`` with credential values masked.

    Relay commands carry passwords, NTLM hashes and Kerberos keys in argv; the
    value following a known credential flag is replaced with ``***`` so the
    command can be logged without leaking secrets.
    """
    redacted: list[str] = []
    mask_next = False
    for arg in cmd:
        if mask_next:
            redacted.append("***")
            mask_next = False
            continue
        redacted.append(arg)
        if arg in _SECRET_FLAGS:
            mask_next = True
    return redacted


def _append_capped(buffer: list[str], total: int, text: str) -> int:
    """Append ``text`` to ``buffer`` within the byte budget; return the new total.

    Keeps retained output bounded so a long-running, chatty listener cannot blow
    up memory or the agent's context window. Success detection still scans every
    line; only what is kept is capped. A one-time marker is appended when the
    ceiling is first reached.
    """
    if total >= _MAX_OUTPUT_BYTES:
        return total
    remaining = _MAX_OUTPUT_BYTES - total
    chunk = text[:remaining]
    buffer.append(chunk)
    new_total = total + len(chunk)
    if new_total >= _MAX_OUTPUT_BYTES:
        buffer.append(f"\n[!] Output truncated at {_MAX_OUTPUT_BYTES} bytes.\n")
    return new_total


async def wait_for_relay_ready(
    proc: asyncio.subprocess.Process,
    output_buffer: list[str],
    timeout: float = 30,
    ready_marker: str = "servers started",
) -> bool:
    """Read a listener's stdout until it is ready to receive connections.

    Returns True when a line containing ``ready_marker`` appears, False on
    early exit, a port-bind error, or timeout.
    """
    assert proc.stdout is not None
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    while loop.time() < deadline:
        remaining = deadline - loop.time()
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=min(remaining, _READ_POLL_INTERVAL))
        except TimeoutError:
            if proc.returncode is not None:
                return False
            continue

        if not line:
            return False  # EOF — process exited

        decoded = line.decode(errors="replace")
        output_buffer.append(decoded)

        lower = decoded.lower()
        if ready_marker in lower:
            return True

        # Early failure: port bind error
        if "error" in lower and ("bind" in lower or "address already in use" in lower):
            return False

    return False


async def wait_for_relay_result(
    proc: asyncio.subprocess.Process,
    output_buffer: list[str],
    success_patterns: list[str],
    timeout: float = 90,
) -> bool:
    """Read a listener's stdout looking for a success indicator.

    On a match, continues reading for a few more seconds to capture follow-up
    data (certificate values, hashes, etc.) before returning True. Returns
    False if the deadline passes or the process exits without a match. Retained
    output is capped at :data:`_MAX_OUTPUT_BYTES`; detection is not.
    """
    assert proc.stdout is not None
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    total = sum(len(s) for s in output_buffer)

    while loop.time() < deadline:
        remaining = deadline - loop.time()
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=min(remaining, _READ_POLL_INTERVAL))
        except TimeoutError:
            if proc.returncode is not None:
                break
            continue

        if not line:
            break

        decoded = line.decode(errors="replace")
        total = _append_capped(output_buffer, total, decoded)

        lower = decoded.lower()
        if any(pattern in lower for pattern in success_patterns):
            # Drain follow-up output (cert data, hash values) for a few seconds
            drain_deadline = loop.time() + _SUCCESS_DRAIN_SECONDS
            try:
                while loop.time() < drain_deadline:
                    drain_remaining = drain_deadline - loop.time()
                    extra = await asyncio.wait_for(proc.stdout.readline(), timeout=drain_remaining)
                    if not extra:
                        break
                    total = _append_capped(output_buffer, total, extra.decode(errors="replace"))
            except TimeoutError:
                pass
            return True

    return False


async def kill_relay(proc: asyncio.subprocess.Process) -> None:
    """Terminate a listener subprocess and its process group.

    Sends SIGTERM to the group, waits up to :data:`_SIGKILL_TIMEOUT` seconds,
    then escalates to SIGKILL. Requires the subprocess was created with
    ``start_new_session=True`` so it leads its own group.
    """
    if proc.returncode is not None:
        return

    pid = proc.pid
    if pid is None:
        return

    try:
        pgid = os.getpgid(pid)
    except (OSError, ProcessLookupError):
        return

    with contextlib.suppress(OSError, ProcessLookupError):
        os.killpg(pgid, signal.SIGTERM)

    try:
        await asyncio.wait_for(proc.wait(), timeout=_SIGKILL_TIMEOUT)
    except TimeoutError:
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(pgid, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError):
            await proc.wait()


async def stream_listener(
    cmd: list[str],
    success_patterns: list[str],
    timeout: float,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> str:
    """Run a long-lived listener and return its captured stdout.

    Streams the subprocess's output and returns as soon as a line matching one
    of ``success_patterns`` appears (plus a short drain). If no match appears:

    * a listener still running when ``timeout`` elapses is stopped and its
      captured output returned — catching nothing is a normal result, not an
      error, so this does not raise;
    * a listener that exited on its own with a non-zero code raises
      ``RuntimeError`` (a crash or misconfiguration the caller must see);
    * a clean (code 0) early exit returns the captured output with a note.

    The process group is always torn down before returning.
    """
    process_env = os.environ.copy()
    if env:
        process_env.update(env)

    logger.info("Starting relay listener: {}", " ".join(_redact_cmd(cmd)))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
        env=process_env,
        cwd=cwd,
    )

    output: list[str] = []
    try:
        success = await wait_for_relay_result(proc, output, success_patterns=success_patterns, timeout=timeout)
        if success:
            return "".join(output)

        # No success line. Reap a process that closed its stdout so its exit
        # code settles, then tell apart "still listening at the deadline" from
        # "exited on its own".
        if proc.returncode is None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=_EXIT_SETTLE_SECONDS)

        captured = "".join(output)
        if proc.returncode is None:
            return captured + f"\n[!] No authentication captured within {timeout:g}s; the listener was stopped."
        if proc.returncode != 0:
            raise RuntimeError(
                f"Relay listener exited with code {proc.returncode} before capturing anything:\n{captured}"
            )
        return captured + "\n[!] Listener exited without capturing an authentication."
    finally:
        await kill_relay(proc)
