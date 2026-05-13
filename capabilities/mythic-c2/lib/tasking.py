"""Generic Mythic tasking tools — payload-type agnostic.

Registered onto the shared FastMCP instance only when the ``tasking``
capability flag is on. Works for any payload type Mythic knows about
(Apollo, Poseidon, Merlin, Athena, Freyja, Atlas, Apfell, Medusa, Tetanus,
etc.) because the tasking RPC (``issue_task_and_waitfor_task_output``) is
generic — the payload type only constrains which ``command`` names are
valid for a given callback.

This module is not a replacement for ``apollo.py``. ``apollo.py`` stays
as the Apollo-specific orchestration layer — multi-step workflows like
``sharphound_and_download`` and ``powershell_script`` that aren't single
Mythic commands. Use ``tasking`` for one-shot generic tasking; turn on
``apollo`` when you need Apollo-specific workflows.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP
from mythic import mythic as mythic_sdk

from .mythic_api import clean, current_config, ensure_connected, gql, truncate


async def list_callback_commands(
    callback_display_id: Annotated[int, "Callback display ID"],
) -> list[dict[str, Any]]:
    """Slim catalog of commands available for a callback's payload type.

    Mirrors the Mythic task-bar autocomplete: lookup is by payload type, so
    every Apollo callback shares one catalog and every Poseidon callback
    shares another. Returns just ``cmd``, ``description``, and the names of
    required parameters so the LLM can pick a command without reading the
    full parameter schema for 40+ commands. Once a command is picked, call
    :func:`get_command_details` for the full parameter schema before
    :func:`issue_task`.

    Args:
        callback_display_id: The number shown in Mythic's UI for the callback.

    Returns:
        Sorted list of ``{cmd, description, required_params}`` dicts.
        ``required_params`` is a list of parameter names marked required in
        Mythic. Empty list only if the callback's payload type genuinely
        exposes no commands — a nonexistent callback raises.

    Raises:
        LookupError: If no callback has that display ID.
    """
    result = await gql(
        """
        query CallbackCommands($display_id: Int!) {
            callback(where: {display_id: {_eq: $display_id}}, limit: 1) {
                payload {
                    payloadtype {
                        name
                        commands(where: {deleted: {_eq: false}}, order_by: {cmd: asc}) {
                            cmd
                            description
                            commandparameters(where: {required: {_eq: true}}) {
                                name
                            }
                        }
                    }
                }
            }
        }
        """,
        {"display_id": callback_display_id},
    )
    rows = result.get("callback") or []
    if not rows:
        raise LookupError(f"callback display_id={callback_display_id} not found")
    payload = rows[0].get("payload") or {}
    payloadtype = payload.get("payloadtype") or {}
    commands = payloadtype.get("commands") or []
    result_list: list[dict[str, Any]] = []
    for c in commands:
        # Mythic stores one commandparameter row per parameter-group presentation
        # (String, File, etc.), so the same parameter name can appear multiple
        # times across groups. Dedup while preserving encounter order.
        required = list(dict.fromkeys(p.get("name") for p in (c.get("commandparameters") or []) if p.get("name")))
        result_list.append(
            clean(
                {
                    "cmd": c.get("cmd"),
                    "description": c.get("description"),
                    "required_params": required,
                }
            )
        )
    return result_list


async def get_command_details(
    callback_display_id: Annotated[int, "Callback display ID"],
    command: Annotated[str, "Command name from list_callback_commands"],
) -> dict[str, Any]:
    """Full parameter schema for one command on a callback's payload type.

    Call this after picking a command from :func:`list_callback_commands`
    and before :func:`issue_task`. Returns every parameter with its type,
    default value, required flag, and description — the information the LLM
    needs to build a correct ``parameters`` dict.

    Args:
        callback_display_id: The number shown in Mythic's UI for the callback.
        command: Exact command name (case-sensitive) from ``list_callback_commands``.

    Returns:
        ``{cmd, description, help_cmd, parameters: [{name, cli_name, display_name,
        description, type, required, default_value}]}``.

    Raises:
        LookupError: If the callback doesn't exist, or the command name isn't
            valid for the callback's payload type.
    """
    result = await gql(
        """
        query CommandDetails($display_id: Int!, $command: String!) {
            callback(where: {display_id: {_eq: $display_id}}, limit: 1) {
                payload {
                    payloadtype {
                        commands(where: {cmd: {_eq: $command}, deleted: {_eq: false}}, limit: 1) {
                            cmd
                            description
                            help_cmd
                            commandparameters(order_by: {ui_position: asc}) {
                                name
                                cli_name
                                display_name
                                description
                                type
                                required
                                default_value
                            }
                        }
                    }
                }
            }
        }
        """,
        {"display_id": callback_display_id, "command": command},
    )
    rows = result.get("callback") or []
    if not rows:
        raise LookupError(f"callback display_id={callback_display_id} not found")
    commands = ((rows[0].get("payload") or {}).get("payloadtype") or {}).get("commands") or []
    if not commands:
        raise LookupError(
            f"command {command!r} not valid for callback " f"display_id={callback_display_id}'s payload type"
        )
    c = commands[0]
    return clean(
        {
            "cmd": c.get("cmd"),
            "description": c.get("description"),
            "help_cmd": c.get("help_cmd"),
            "parameters": [
                clean(
                    {
                        "name": p.get("name"),
                        "cli_name": p.get("cli_name"),
                        "display_name": p.get("display_name"),
                        "description": p.get("description"),
                        "type": p.get("type"),
                        "required": p.get("required"),
                        "default_value": p.get("default_value"),
                    }
                )
                for p in (c.get("commandparameters") or [])
            ],
        }
    )


async def issue_task(
    callback_display_id: Annotated[int, "Callback display ID"],
    command: Annotated[
        str,
        "Command name valid for the callback's payload type — use list_callback_commands to discover",
    ],
    parameters: Annotated[
        str | dict[str, Any],
        "Command arguments — typically a dict keyed by parameter name; some commands accept a plain string",
    ] = "",
    timeout: Annotated[int | None, "Task timeout in seconds; uses Mythic default if unset"] = None,
) -> str:
    """Issue one command against a callback and return the task output.

    Payload-type agnostic. ``command`` must be valid for the callback's
    payload type (see ``list_callback_commands``). Raises RuntimeError on
    transport / auth failure. A successful task with no output returns a
    short "no output" message rather than raising — that's a valid command
    result, not a failure.

    Args:
        callback_display_id: The number shown in Mythic's UI.
        command: Command name (payload-type specific — e.g. ``shell`` on
            Poseidon, ``powershell`` on Apollo).
        parameters: Either a dict keyed by parameter name, or a plain
            string for commands that take one positional argument.
        timeout: Override Mythic's default timeout (seconds).

    Returns:
        Decoded command output, truncated if it exceeds
        :data:`lib.mythic_api.MAX_OUTPUT_CHARS`.
    """
    client = await ensure_connected()
    cfg = current_config()
    effective_timeout = timeout if timeout is not None else cfg["timeout"]
    try:
        output_bytes = await mythic_sdk.issue_task_and_waitfor_task_output(
            mythic=client,
            command_name=command,
            parameters=parameters,
            callback_display_id=callback_display_id,
            timeout=effective_timeout,
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to task '{command}' on callback {callback_display_id}: {exc}") from exc

    if not output_bytes:
        return f"Command '{command}' returned no output."

    text = str(output_bytes.decode() if isinstance(output_bytes, bytes) else output_bytes)
    return truncate(text)


_TOOLS = [list_callback_commands, get_command_details, issue_task]


def register(mcp: FastMCP) -> None:
    """Register every generic tasking tool onto the provided FastMCP instance."""
    for fn in _TOOLS:
        mcp.tool(fn)
