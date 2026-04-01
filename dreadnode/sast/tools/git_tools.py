"""
Git tools for repository analysis.

Provides git_diff, git_log, and git_blame tools for understanding
code history during security analysis.
"""

import asyncio
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method
from loguru import logger

MAX_OUTPUT = 10_000


class GitTool(Toolset):
    """Git history, diffs, and blame."""

    @tool_method(catch=True)
    async def git_diff(self, path: str | None = None) -> str:
        """
        Show unified diff of uncommitted changes (staged and unstaged) using git diff.

        Args:
            path: Optional file or directory path to scope the diff. If not provided, shows all changes.

        Returns:
            Unified diff output, or a message if no changes detected.
        """
        target = Path(path).resolve() if path else Path.cwd().resolve()
        logger.debug(f"git_diff: {target}")

        if path and not target.exists():
            return f"Error: Path not found: {target}"

        cwd = str(target if target.is_dir() else target.parent)

        if not await self._is_git_repo(cwd):
            return "Error: Not a git repository."

        path_args = [str(target)] if target.is_file() else []

        # Get unstaged changes
        unstaged = await self._run_git_cmd(["git", "diff"], path_args, cwd)
        # Get staged changes
        staged = await self._run_git_cmd(["git", "diff", "--cached"], path_args, cwd)

        parts: list[str] = []
        if staged and staged.strip():
            parts.append("=== Staged changes ===\n" + staged)
        if unstaged and unstaged.strip():
            parts.append("=== Unstaged changes ===\n" + unstaged)

        if not parts:
            return "No changes detected (git diff is clean)."

        return _truncate("\n".join(parts))

    @tool_method(catch=True)
    async def git_log(
        self,
        path: str | None = None,
        max_count: int = 20,
        file_path: str | None = None,
        author: str | None = None,
        since: str | None = None,
        grep: str | None = None,
    ) -> str:
        """
        Show git commit history. Useful for understanding what changed, when, and by whom.

        Args:
            path: Repository or directory path. Defaults to current working directory.
            max_count: Maximum number of commits to show. Defaults to 20.
            file_path: Show only commits that modified this file.
            author: Filter commits by author name or email (substring match).
            since: Show commits after this date (e.g., "2024-01-01", "2 weeks ago").
            grep: Filter commits whose message contains this string.

        Returns:
            Formatted git log output with commit hash, author, date, and message.
        """
        cwd = str(Path(path).resolve()) if path else str(Path.cwd())
        logger.debug(f"git_log: cwd={cwd}, max_count={max_count}, file={file_path}")

        if not await self._is_git_repo(cwd):
            return "Error: Not a git repository."

        cmd = [
            "git",
            "log",
            f"--max-count={max_count}",
            "--format=%h %ad %an%n  %s",
            "--date=short",
        ]

        if author:
            cmd.append(f"--author={author}")
        if since:
            cmd.append(f"--since={since}")
        if grep:
            cmd.append(f"--grep={grep}")

        if file_path:
            cmd.append("--")
            cmd.append(file_path)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            error = (
                stderr.decode(errors="replace").strip() if stderr else "Unknown error"
            )
            return f"Error: git log failed: {error}"

        output = stdout.decode(errors="replace").strip() if stdout else ""
        if not output:
            return "No commits found matching the given criteria."

        return _truncate(output)

    @tool_method(catch=True)
    async def git_blame(self, file_path: str, path: str | None = None) -> str:
        """
        Show git blame for a file - who last modified each line and when.

        Useful for understanding code provenance: when a vulnerable line was introduced
        and what commit it came from.

        Args:
            file_path: The file to blame (relative to the repo root or absolute).
            path: Repository or directory path. Defaults to current working directory.

        Returns:
            Annotated file with commit hash, author, date, and line number for each line.
        """
        cwd = str(Path(path).resolve()) if path else str(Path.cwd())
        logger.debug(f"git_blame: {file_path} in {cwd}")

        if not await self._is_git_repo(cwd):
            return "Error: Not a git repository."

        cmd = ["git", "blame", "--date=short", file_path]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            error = (
                stderr.decode(errors="replace").strip() if stderr else "Unknown error"
            )
            return f"Error: git blame failed: {error}"

        output = stdout.decode(errors="replace").strip() if stdout else ""
        if not output:
            return "No blame output (file may be empty or untracked)."

        return _truncate(output)

    async def _is_git_repo(self, cwd: str) -> bool:
        """Check if the given path is inside a git repository."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git",
                "rev-parse",
                "--is-inside-work-tree",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            await proc.communicate()
        except (FileNotFoundError, OSError):
            return False
        else:
            return proc.returncode == 0

    async def _run_git_cmd(
        self,
        cmd: list[str],
        path_args: list[str],
        cwd: str,
    ) -> str:
        """Run a git command with optional path scoping and return stdout."""
        if path_args:
            cmd = [*cmd, "--", *path_args]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode(errors="replace") if stdout else ""


def _truncate(output: str) -> str:
    """Truncate output if it exceeds MAX_OUTPUT."""
    if len(output) > MAX_OUTPUT:
        return (
            output[:MAX_OUTPUT] + f"\n\n(Output truncated at {MAX_OUTPUT} characters)"
        )
    return output
