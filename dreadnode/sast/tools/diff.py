"""
Snapshot-based file diffing tool.

Provides snapshot_file and diff tools for comparing file changes
in non-git repositories. For git repos, use GitTool instead.
"""

import asyncio
import difflib
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method
from loguru import logger
from pydantic import PrivateAttr

MAX_OUTPUT = 10_000


class DiffTool(Toolset):
    """Snapshot-based file diffing using difflib. For git diffs, use GitTool instead."""

    _snapshots: dict[str, str] = PrivateAttr(default_factory=dict)

    @tool_method(catch=True)
    async def snapshot_file(self, file_path: str) -> str:
        """
        Snapshot a file's current content for later diffing. Not needed in git repos (use git_diff instead).

        Args:
            file_path: Path to the file to snapshot.

        Returns:
            Confirmation that the snapshot was saved.
        """
        filepath = Path(file_path)
        if not filepath.is_absolute():
            filepath = Path.cwd() / filepath
        filepath = filepath.resolve()

        if not filepath.exists():
            return f"Error: File not found: {filepath}"
        if filepath.is_dir():
            return f"Error: Path is a directory: {filepath}"

        def do_snapshot() -> str:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            self._snapshots[str(filepath)] = content
            return f"Snapshot saved for {filepath}"

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, do_snapshot)

    @tool_method(catch=True)
    async def diff(self, path: str | None = None) -> str:
        """
        Show unified diff of changes compared to saved snapshots. For non-git repos only - use git_diff in git repos.

        Args:
            path: Optional file or directory path to scope the diff. If not provided, shows all changes.

        Returns:
            Unified diff output, or a message if no changes detected.
        """
        target = Path(path).resolve() if path else Path.cwd().resolve()
        logger.debug(f"diff: {target}")

        if not self._snapshots:
            return "No snapshots saved. Use snapshot_file to save a baseline before editing, or use git_diff in git repos."

        parts: list[str] = []
        target_str = str(target)

        for filepath_str, original in sorted(self._snapshots.items()):
            # If target is a file, only diff that file; if dir, diff all snapshots under it
            if target.is_file() and filepath_str != target_str:
                continue
            if target.is_dir() and not filepath_str.startswith(target_str):
                continue

            filepath = Path(filepath_str)
            if not filepath.exists():
                parts.append(f"--- {filepath_str}\n+++ /dev/null\n(file deleted)")
                continue

            current = filepath.read_text(encoding="utf-8", errors="replace")
            if current == original:
                continue

            diff_lines = list(
                difflib.unified_diff(
                    original.splitlines(keepends=True),
                    current.splitlines(keepends=True),
                    fromfile=f"a/{filepath.name}",
                    tofile=f"b/{filepath.name}",
                )
            )
            if diff_lines:
                parts.append("".join(diff_lines))

        if not parts:
            return "No changes detected compared to snapshots."

        output = "\n".join(parts)
        if len(output) > MAX_OUTPUT:
            return (
                output[:MAX_OUTPUT]
                + f"\n\n(Output truncated at {MAX_OUTPUT} characters)"
            )
        return output
