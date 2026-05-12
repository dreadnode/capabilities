"""Workflow management for AI red team attack scripts.

Provides tools to save, list, and execute Python attack workflow
scripts with syntax validation and metadata tracking.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import typing as t
from datetime import datetime, timezone
from pathlib import Path

from dreadnode.agents.tools import tool
from dreadnode.app.env import resolve_python_executable

WORKFLOWS_DIR = Path(
    os.environ.get(
        "AIRT_WORKFLOWS_DIR",
        str(Path.home() / "workspace" / "airt" / "workflows"),
    )
)
METADATA_FILE = WORKFLOWS_DIR / ".workflow_metadata.json"


def _load_metadata() -> dict:
    if METADATA_FILE.exists():
        try:
            return json.loads(METADATA_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_metadata(meta: dict) -> None:
    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_FILE.write_text(json.dumps(meta, indent=2))


@tool
def save_workflow(
    filename: t.Annotated[str, "Filename for the workflow (e.g., 'my_attack.py')"],
    code: t.Annotated[str, "Python source code for the workflow"],
    description: t.Annotated[str, "Brief description of what the workflow does"] = "",
) -> str:
    """Save a Python attack workflow with syntax validation.

    Validates the code compiles, saves to ~/workspace/airt/workflows/,
    and records metadata. Use execute_workflow to run saved workflows.
    """
    if "/" in filename or "\\" in filename or ".." in filename:
        return "Error: Invalid filename (no path separators or '..' allowed)."

    if not filename.endswith(".py"):
        filename += ".py"

    try:
        compile(code, filename, "exec")
    except SyntaxError as e:
        return f"Syntax error: {e}"

    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = WORKFLOWS_DIR / filename
    filepath.write_text(code)

    meta = _load_metadata()
    meta[filename] = {
        "description": description,
        "size": len(code),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_metadata(meta)

    return f"Workflow saved: {filepath} ({len(code)} bytes)"


@tool
def list_workflows() -> str:
    """List saved attack workflows with metadata.

    Shows all Python scripts in ~/workspace/airt/workflows/ with
    descriptions, sizes, and save timestamps.
    """
    if not WORKFLOWS_DIR.exists():
        return "No workflows directory found."

    files = sorted(WORKFLOWS_DIR.glob("*.py"))
    if not files:
        return "No workflows saved yet."

    meta = _load_metadata()
    lines = [f"Saved workflows ({len(files)}):"]
    for f in files:
        info = meta.get(f.name, {})
        desc = info.get("description", "")
        size = f.stat().st_size
        saved = info.get("saved_at", "unknown")
        lines.append(f"  - {f.name}: {desc} ({size}B, saved {saved})")

    return "\n".join(lines)


@tool
def execute_workflow(
    filename: t.Annotated[str, "Workflow filename to execute"],
    timeout: t.Annotated[int, "Max execution time in seconds (max 600)"] = 540,
) -> str:
    """Execute a saved attack workflow script.

    Runs the workflow as a subprocess with the configured timeout.
    Returns stdout/stderr output.
    """
    if "/" in filename or "\\" in filename or ".." in filename:
        return "Error: Invalid filename."

    filepath = WORKFLOWS_DIR / filename
    if not filepath.exists():
        return f"Workflow not found: {filename}. Use list_workflows to see available."

    timeout = min(timeout, 600)

    try:
        python_executable = resolve_python_executable()
        result = subprocess.run(
            [python_executable, str(filepath)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(WORKFLOWS_DIR.parent),
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"

        if result.returncode == 0:
            return f"Workflow completed successfully.\n\n{output[:50_000]}"
        return f"Workflow exited with code {result.returncode}.\n\n{output[:50_000]}"
    except subprocess.TimeoutExpired:
        return f"Workflow timed out after {timeout}s."
    except Exception as e:
        return f"Execution error: {e}"
