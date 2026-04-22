"""
FileMap tool for structural source code analysis.

Provides a token-efficient overview of file structure (classes, functions,
signatures) without reading full content. Other exploration tools (glob, grep,
read, ls) are provided by the platform.
"""

import ast
import asyncio
import re
from collections.abc import Callable
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method
from loguru import logger


# ============================================================================
# Constants
# ============================================================================

MAX_FILE_SIZE = 1_000_000  # 1MB for filemap

# Binary file extensions that should not be parsed
BINARY_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".exe",
    ".dll",
    ".so",
    ".class",
    ".jar",
    ".war",
    ".7z",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".odt",
    ".ods",
    ".odp",
    ".bin",
    ".dat",
    ".obj",
    ".o",
    ".a",
    ".lib",
    ".wasm",
    ".pyc",
    ".pyo",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".svg",
    ".webp",
    ".mp3",
    ".mp4",
    ".wav",
    ".avi",
    ".mov",
    ".mkv",
    ".flv",
    ".wmv",
    ".pdf",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".eot",
}


# ============================================================================
# Language Parsers
# ============================================================================


def _parse_python(source: str) -> list[str]:
    """Parse Python source using ast module, fall back to regex on SyntaxError."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return _parse_python_regex(source)

    entries: list[str] = []

    def _visit(node: ast.AST, indent: int = 0) -> None:
        prefix = "  " * indent
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                entries.append(f"{child.lineno:>5}| {prefix}class {child.name}:")
                _visit(child, indent + 1)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                async_prefix = (
                    "async " if isinstance(child, ast.AsyncFunctionDef) else ""
                )
                args = _format_python_args(child.args)
                returns = ""
                if child.returns:
                    returns = f" -> {ast.unparse(child.returns)}"
                entries.append(
                    f"{child.lineno:>5}| {prefix}{async_prefix}def {child.name}({args}){returns}:"
                )

    _visit(tree)
    return entries


def _format_python_args(args: ast.arguments) -> str:
    """Format function arguments to a compact signature."""
    parts: list[str] = []
    for arg in args.posonlyargs:
        ann = f": {ast.unparse(arg.annotation)}" if arg.annotation else ""
        parts.append(f"{arg.arg}{ann}")
    if args.posonlyargs:
        parts.append("/")
    for arg in args.args:
        ann = f": {ast.unparse(arg.annotation)}" if arg.annotation else ""
        parts.append(f"{arg.arg}{ann}")
    if args.vararg:
        parts.append(f"*{args.vararg.arg}")
    for arg in args.kwonlyargs:
        ann = f": {ast.unparse(arg.annotation)}" if arg.annotation else ""
        parts.append(f"{arg.arg}{ann}")
    if args.kwarg:
        parts.append(f"**{args.kwarg.arg}")
    sig = ", ".join(parts)
    if len(sig) > 80:
        sig = sig[:77] + "..."
    return sig


def _parse_python_regex(source: str) -> list[str]:
    """Regex fallback for Python files that fail ast.parse."""
    return _parse_generic_regex(
        source,
        [
            (
                r"^(\s*)(async\s+)?class\s+(\w+)",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2) or ''}class {m.group(3)}:"
                ),
            ),
            (
                r"^(\s*)(async\s+)?def\s+(\w+)\s*\(",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2) or ''}def {m.group(3)}(...)"
                ),
            ),
        ],
    )


def _parse_js_ts(source: str) -> list[str]:
    """Parse JavaScript/TypeScript source using regex."""
    return _parse_generic_regex(
        source,
        [
            (
                r"^(\s*)export\s+(default\s+)?class\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}export class {m.group(3)}",
            ),
            (
                r"^(\s*)class\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}class {m.group(2)}",
            ),
            (
                r"^(\s*)export\s+(default\s+)?(async\s+)?function\s+(\w+)",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}export {m.group(3) or ''}function {m.group(4)}(...)"
                ),
            ),
            (
                r"^(\s*)(async\s+)?function\s+(\w+)",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2) or ''}function {m.group(3)}(...)"
                ),
            ),
            (
                r"^(\s*)(export\s+)?(const|let|var)\s+(\w+)\s*=\s*(async\s+)?\(",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2) or ''}{m.group(3)} {m.group(4)} = {m.group(5) or ''}(...)"
                ),
            ),
            (
                r"^(\s*)(export\s+)?(const|let|var)\s+(\w+)\s*=\s*(async\s+)?(\w+)\s*=>",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2) or ''}{m.group(3)} {m.group(4)} = {m.group(5) or ''}=> ..."
                ),
            ),
        ],
    )


def _parse_java(source: str) -> list[str]:
    """Parse Java source using regex."""
    return _parse_generic_regex(
        source,
        [
            (
                r"^(\s*)(public|private|protected)?\s*(static\s+)?(abstract\s+)?(class|interface|enum)\s+(\w+)",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{(m.group(2) + ' ') if m.group(2) else ''}{m.group(5)} {m.group(6)}"
                ),
            ),
            (
                r"^(\s*)(public|private|protected)\s+(static\s+)?([\w<>\[\],\s]+?)\s+(\w+)\s*\(",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2)} {(m.group(3) or '').strip()} {m.group(4).strip()} {m.group(5)}(...)".replace(
                        "  ", " "
                    )
                ),
            ),
        ],
    )


def _parse_go(source: str) -> list[str]:
    """Parse Go source using regex."""
    return _parse_generic_regex(
        source,
        [
            (
                r"^type\s+(\w+)\s+(struct|interface)\s*\{",
                lambda m, ln: f"{ln:>5}| type {m.group(1)} {m.group(2)}",
            ),
            (
                r"^func\s+\((\w+)\s+\*?(\w+)\)\s+(\w+)\s*\(",
                lambda m, ln: (
                    f"{ln:>5}| func ({m.group(1)} {m.group(2)}) {m.group(3)}(...)"
                ),
            ),
            (r"^func\s+(\w+)\s*\(", lambda m, ln: f"{ln:>5}| func {m.group(1)}(...)"),
        ],
    )


def _parse_c_cpp(source: str) -> list[str]:
    """Parse C/C++ source using regex."""
    return _parse_generic_regex(
        source,
        [
            (
                r"^(\s*)(class|struct)\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}{m.group(2)} {m.group(3)}",
            ),
            (
                r"^(\s*)namespace\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}namespace {m.group(2)}",
            ),
            (
                r"^([\w:*&<>\s]+?)\s+(\w+)\s*\([^;]*\)\s*\{?\s*$",
                lambda m, ln: f"{ln:>5}| {m.group(1).strip()} {m.group(2)}(...)",
            ),
        ],
    )


def _parse_php(source: str) -> list[str]:
    """Parse PHP source using regex."""
    return _parse_generic_regex(
        source,
        [
            (
                r"^(\s*)(abstract\s+)?(class|interface|trait)\s+(\w+)",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2) or ''}{m.group(3)} {m.group(4)}"
                ),
            ),
            (
                r"^(\s*)(public|private|protected)?\s*(static\s+)?function\s+(\w+)\s*\(",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{(m.group(2) + ' ') if m.group(2) else ''}function {m.group(4)}(...)"
                ),
            ),
        ],
    )


def _parse_ruby(source: str) -> list[str]:
    """Parse Ruby source using regex."""
    return _parse_generic_regex(
        source,
        [
            (
                r"^(\s*)module\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}module {m.group(2)}",
            ),
            (
                r"^(\s*)class\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}class {m.group(2)}",
            ),
            (
                r"^(\s*)def\s+(\w+[\w?!]*)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}def {m.group(2)}",
            ),
        ],
    )


def _parse_generic(source: str) -> list[str]:
    """Generic fallback parser for unsupported languages."""
    return _parse_generic_regex(
        source,
        [
            (
                r"^(\s*)class\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}class {m.group(2)}",
            ),
            (
                r"^(\s*)(async\s+)?def\s+(\w+)",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2) or ''}def {m.group(3)}"
                ),
            ),
            (
                r"^(\s*)(async\s+)?function\s+(\w+)",
                lambda m, ln: (
                    f"{ln:>5}| {m.group(1)}{m.group(2) or ''}function {m.group(3)}"
                ),
            ),
            (
                r"^(\s*)struct\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}struct {m.group(2)}",
            ),
            (
                r"^(\s*)fn\s+(\w+)",
                lambda m, ln: f"{ln:>5}| {m.group(1)}fn {m.group(2)}",
            ),
        ],
    )


def _parse_generic_regex(source: str, patterns: list[tuple]) -> list[str]:
    """Apply a list of (regex, formatter) patterns to source lines."""
    entries: list[str] = []
    compiled = [(re.compile(p), fmt) for p, fmt in patterns]
    for i, line in enumerate(source.split("\n"), start=1):
        for pat, fmt in compiled:
            m = pat.match(line)
            if m:
                entries.append(fmt(m, i))
                break
    return entries


# Extension to parser mapping
EXTENSION_PARSERS: dict[str, Callable[[str], list[str]]] = {
    ".py": _parse_python,
    ".pyw": _parse_python,
    ".js": _parse_js_ts,
    ".jsx": _parse_js_ts,
    ".mjs": _parse_js_ts,
    ".ts": _parse_js_ts,
    ".tsx": _parse_js_ts,
    ".java": _parse_java,
    ".go": _parse_go,
    ".c": _parse_c_cpp,
    ".h": _parse_c_cpp,
    ".cpp": _parse_c_cpp,
    ".hpp": _parse_c_cpp,
    ".cc": _parse_c_cpp,
    ".cxx": _parse_c_cpp,
    ".php": _parse_php,
    ".rb": _parse_ruby,
}

EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".jsx": "JSX",
    ".mjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TSX",
    ".java": "Java",
    ".go": "Go",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++",
    ".hpp": "C++ Header",
    ".cc": "C++",
    ".cxx": "C++",
    ".php": "PHP",
    ".rb": "Ruby",
}


# ============================================================================
# FileMapTool
# ============================================================================


class FileMapTool(Toolset):
    """Structural file overview showing classes, functions, and method signatures with line numbers."""

    @tool_method(catch=True)
    async def filemap(self, file_path: str) -> str:
        """
        Show structural outline of a source file (classes, functions, signatures with line numbers).

        Provides a token-efficient overview of a file's structure without reading the full content.
        Useful for understanding file organization before diving into specific sections with `read`.

        Args:
            file_path: Path to the source file to outline.

        Returns:
            Indented structural outline with line numbers for each class, function, and method.
        """
        filepath = Path(file_path)
        if not filepath.is_absolute():
            filepath = Path.cwd() / filepath
        filepath = filepath.resolve()

        logger.debug(f"FileMap: {filepath}")

        if not filepath.exists():
            return f"Error: File not found: {filepath}"

        if filepath.is_dir():
            return f"Error: Path is a directory, not a file: {filepath}"

        if filepath.suffix.lower() in BINARY_EXTENSIONS:
            return f"Error: Cannot map binary file: {filepath}"

        # Check file size
        file_size = filepath.stat().st_size
        if file_size > MAX_FILE_SIZE:
            return f"Error: File is too large to map ({file_size:,} bytes, limit is {MAX_FILE_SIZE:,}). Use `grep` to search for specific patterns instead."

        def do_parse() -> str:
            source = filepath.read_text(encoding="utf-8", errors="replace")
            lines = source.split("\n")
            total_lines = len(lines)

            ext = filepath.suffix.lower()
            language = EXTENSION_LANGUAGES.get(ext, "Unknown")
            parser = EXTENSION_PARSERS.get(ext, _parse_generic)

            entries = parser(source)

            if not entries:
                return f"File: {filepath} ({language}, {total_lines} lines)\n\n(No classes or functions found)"

            header = f"File: {filepath} ({language}, {total_lines} lines)\n"
            return header + "\n" + "\n".join(entries)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, do_parse)
