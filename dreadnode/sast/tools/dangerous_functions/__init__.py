"""
Language-specific dangerous function scanners.

Provides fast ripgrep-based pattern scanning for common vulnerability
patterns across Python, Java, Go, and C/C++ codebases.
"""

import asyncio
import shutil
from pathlib import Path

from dreadnode.agents.tools import Toolset
from loguru import logger

from .c_cpp import DangerousFunctionsCCppTool
from .csharp import DangerousFunctionsCSharpTool
from .go import DangerousFunctionsGoTool
from .java import DangerousFunctionsJavaTool
from .python import DangerousFunctionsPythonTool

# Maximum matches per category and total
PER_CATEGORY_LIMIT = 20
TOTAL_LIMIT = 500
OUTPUT_CHAR_LIMIT = 30000

# Category tuple: (id, name, cwes, description, rg_pattern)
CategoryList = list[tuple[str, str, str, str, str]]


class DangerousFunctionsBase(Toolset):
    """Base class for language-specific dangerous function scanners.

    Subclasses provide category lists and file globs; this base class
    implements the shared ripgrep-based scanning logic.
    """

    async def _scan_patterns(
        self,
        *,
        path: str | None,
        categories: list[str] | None,
        all_categories: CategoryList,
        valid_ids: set[str],
        file_glob: str,
        language: str,
    ) -> str:
        """Shared scanning logic for any language."""
        search_path = Path(path) if path else Path.cwd()
        if not search_path.is_absolute():
            search_path = Path.cwd() / search_path
        search_path = search_path.resolve()

        rg_path = shutil.which("rg")
        if not rg_path:
            return "Error: ripgrep (rg) is required but not found in PATH"

        if categories:
            unknown = set(categories) - valid_ids
            if unknown:
                return (
                    f"Error: unknown categories: {', '.join(sorted(unknown))}. "
                    f"Valid: {', '.join(sorted(valid_ids))}"
                )
            selected = [c for c in all_categories if c[0] in set(categories)]
        else:
            selected = list(all_categories)

        logger.debug(
            f"Scanning {search_path} for dangerous {language} patterns ({len(selected)} categories)"
        )

        output_parts: list[str] = []
        total_matches = 0

        for _cat_id, cat_name, cwes, description, pattern in selected:
            if total_matches >= TOTAL_LIMIT:
                output_parts.append(
                    f"\n... total match limit ({TOTAL_LIMIT}) reached, remaining categories skipped"
                )
                break

            remaining = min(PER_CATEGORY_LIMIT, TOTAL_LIMIT - total_matches)
            matches = await self._run_rg(
                rg_path, pattern, search_path, remaining, file_glob
            )

            if not matches:
                continue

            total_matches += len(matches)
            section = [
                f"\n## {cat_name} ({cwes})",
                f"  {description}",
                f"  Matches: {len(matches)}",
            ]
            for file_path, line_num, text in matches:
                line_text = text if len(text) <= 200 else text[:200] + "..."
                section.append(f"  {file_path}:{line_num}: {line_text}")

            output_parts.append("\n".join(section))

        if not output_parts:
            return f"No dangerous function patterns found in {language} files."

        header = f"Dangerous {language} function scan: {total_matches} matches in {search_path}"
        result = header + "\n" + "\n".join(output_parts)

        if len(result) > OUTPUT_CHAR_LIMIT:
            result = result[:OUTPUT_CHAR_LIMIT] + "\n\n... output truncated"

        return result

    async def _run_rg(
        self,
        rg_path: str,
        pattern: str,
        search_path: Path,
        limit: int,
        file_glob: str,
    ) -> list[tuple[str, int, str]]:
        """Run ripgrep for a single pattern and return (file, line, text) tuples."""
        cmd = [
            rg_path,
            "-nH",
            "--field-match-separator=|",
            "--glob",
            file_glob,
            "--regexp",
            pattern,
            str(search_path),
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        if proc.returncode != 0 or not stdout:
            return []

        results: list[tuple[str, int, str]] = []
        for line in stdout.decode(errors="replace").strip().split("\n"):
            if not line:
                continue
            parts = line.split("|", 2)
            if len(parts) < 3:
                continue
            try:
                line_num = int(parts[1])
            except ValueError:
                continue
            results.append((parts[0], line_num, parts[2]))

        return results[:limit]


__all__ = [
    "DangerousFunctionsBase",
    "DangerousFunctionsPythonTool",
    "DangerousFunctionsJavaTool",
    "DangerousFunctionsGoTool",
    "DangerousFunctionsCCppTool",
    "DangerousFunctionsCSharpTool",
    "CategoryList",
]
