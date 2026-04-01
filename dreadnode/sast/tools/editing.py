"""
File editing tools with undo support.

Provides str_replace, insert_at_line, create_file, and undo_edit tools
for modifying source code during security analysis.
"""

import asyncio
import dataclasses
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method
from loguru import logger
from pydantic import PrivateAttr

MAX_HISTORY = 100


@dataclasses.dataclass
class EditRecord:
    """Snapshot of a file before an edit."""

    file_path: str  # Resolved absolute path
    original_content: str


class EditTool(Toolset):
    """File editing tools with undo support."""

    _edit_history: list[EditRecord] = PrivateAttr(default_factory=list)

    def _resolve(self, file_path: str) -> Path:
        """Resolve a file path to an absolute path."""
        p = Path(file_path)
        if not p.is_absolute():
            p = Path.cwd() / p
        return p.resolve()

    def _save_snapshot(self, filepath: Path, content: str) -> None:
        """Save a file snapshot to edit history."""
        self._edit_history.append(
            EditRecord(file_path=str(filepath), original_content=content)
        )
        # Cap history size
        if len(self._edit_history) > MAX_HISTORY:
            self._edit_history = self._edit_history[-MAX_HISTORY:]

    @tool_method(catch=True)
    async def str_replace(self, file_path: str, old_str: str, new_str: str) -> str:
        """
        Replace a unique string in a file. The old_str must appear exactly once in the file.

        Args:
            file_path: Path to the file to edit.
            old_str: The exact string to find and replace. Must be unique in the file.
            new_str: The replacement string.

        Returns:
            Confirmation with affected line numbers, or an error message.
        """
        filepath = self._resolve(file_path)
        logger.debug(f"str_replace in {filepath}")

        if not filepath.exists():
            return f"Error: File not found: {filepath}"
        if filepath.is_dir():
            return f"Error: Path is a directory: {filepath}"

        def do_replace() -> str:
            content = filepath.read_text(encoding="utf-8", errors="replace")

            count = content.count(old_str)
            if count == 0:
                return f"Error: old_str not found in {filepath}. Make sure it matches exactly (including whitespace and indentation)."
            if count > 1:
                return f"Error: old_str appears {count} times in {filepath}. It must be unique - include more surrounding context."

            # Find the line number where the replacement starts
            before = content[: content.index(old_str)]
            start_line = before.count("\n") + 1
            end_line = start_line + old_str.count("\n")

            self._save_snapshot(filepath, content)
            new_content = content.replace(old_str, new_str, 1)
            filepath.write_text(new_content, encoding="utf-8")

            new_end_line = start_line + new_str.count("\n")
            return f"Replaced text at lines {start_line}-{end_line} -> {start_line}-{new_end_line} in {filepath}"

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, do_replace)

    @tool_method(catch=True)
    async def insert_at_line(
        self, file_path: str, line_number: int, content: str
    ) -> str:
        """
        Insert content at a specific line number (1-based). Content is inserted before the specified line.

        Args:
            file_path: Path to the file to edit.
            line_number: Line number to insert before (1-based). Use line count + 1 to append.
            content: The text to insert.

        Returns:
            Confirmation with line numbers, or an error message.
        """
        filepath = self._resolve(file_path)
        logger.debug(f"insert_at_line {line_number} in {filepath}")

        if not filepath.exists():
            return f"Error: File not found: {filepath}"
        if filepath.is_dir():
            return f"Error: Path is a directory: {filepath}"

        def do_insert() -> str:
            file_content = filepath.read_text(encoding="utf-8", errors="replace")
            lines = file_content.split("\n")

            if line_number < 1 or line_number > len(lines) + 1:
                return f"Error: line_number {line_number} is out of range (file has {len(lines)} lines). Valid range: 1-{len(lines) + 1}."

            self._save_snapshot(filepath, file_content)

            insert_lines = content.split("\n")
            # Insert before the specified line (0-indexed: line_number - 1)
            idx = line_number - 1
            new_lines = lines[:idx] + insert_lines + lines[idx:]
            filepath.write_text("\n".join(new_lines), encoding="utf-8")

            inserted_count = len(insert_lines)
            return (
                f"Inserted {inserted_count} line(s) at line {line_number} in {filepath}"
            )

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, do_insert)

    @tool_method(catch=True)
    async def create_file(self, file_path: str, content: str) -> str:
        """
        Create a new file with the given content. Fails if the file already exists.

        Args:
            file_path: Path for the new file.
            content: Content to write to the file.

        Returns:
            Confirmation with line count, or an error message.
        """
        filepath = self._resolve(file_path)
        logger.debug(f"create_file: {filepath}")

        if filepath.exists():
            return f"Error: File already exists: {filepath}. Use str_replace to edit existing files."

        def do_create() -> str:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content, encoding="utf-8")
            line_count = len(content.split("\n"))
            return f"Created {filepath} ({line_count} lines)"

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, do_create)

    @tool_method(catch=True)
    async def undo_edit(self, file_path: str) -> str:
        """
        Undo the most recent edit to a file, restoring it to its previous state.

        Args:
            file_path: Path to the file to restore.

        Returns:
            Confirmation that the file was restored, or an error message.
        """
        filepath = self._resolve(file_path)
        logger.debug(f"undo_edit: {filepath}")

        resolved = str(filepath)

        # Search history in reverse for the most recent edit to this file
        for i in range(len(self._edit_history) - 1, -1, -1):
            record = self._edit_history[i]
            if record.file_path == resolved:

                def do_restore(rec: EditRecord = record) -> str:
                    Path(rec.file_path).write_text(
                        rec.original_content, encoding="utf-8"
                    )
                    return f"Restored {rec.file_path} to state before last edit"

                self._edit_history.pop(i)
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, do_restore)

        return f"Error: No edit history found for {filepath}"
