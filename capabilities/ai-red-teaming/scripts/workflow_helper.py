#!/usr/bin/env python3
"""Workflow helper for saving and listing Python attack scripts.

Saves workflow scripts to ~/workspace/airt/workflows/ with syntax
validation via compile(). Provides listing of saved workflows.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import os
import sys
import time
from pathlib import Path

from dreadnode.app.env import resolve_python_executable

# Get org/workspace from active profile, with fallbacks
def _get_workspace_path() -> Path:
    try:
        from dreadnode.app.config import UserConfig
        config = UserConfig.read()
        profile_data = config.active_profile
        if profile_data:
            _, profile = profile_data
            org_key = profile.organization or "default"
            workspace_key = profile.workspace or "main"
        else:
            org_key = "default"
            workspace_key = "main"
    except Exception:
        # Fallback if config system unavailable
        org_key = "default"
        workspace_key = "main"

    return Path.home() / ".dreadnode" / "airt" / org_key / workspace_key / "workflows"

WORKFLOWS_DIR = Path(os.environ.get("AIRT_WORKFLOWS_DIR")) if os.environ.get("AIRT_WORKFLOWS_DIR") else _get_workspace_path()
METADATA_FILE = WORKFLOWS_DIR / ".workflow_metadata.json"


def _load_metadata() -> dict:
    if METADATA_FILE.exists():
        try:
            return json.loads(METADATA_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_metadata(metadata: dict) -> None:
    METADATA_FILE.write_text(json.dumps(metadata, indent=2))


def save_workflow(params: dict) -> dict:
    filename = params["filename"]
    content = params["content"]
    description = params.get("description", "")

    # Reject path traversal attempts
    if "/" in filename or "\\" in filename or ".." in filename:
        return {"error": "Filename must not contain path separators or '..'"}

    # Ensure .py extension
    if not filename.endswith(".py"):
        filename += ".py"

    # Syntax validation
    try:
        compile(content, filename, "exec")
    except SyntaxError as e:
        return {"error": (f"Syntax error in workflow: {e.msg} (line {e.lineno}, col {e.offset})")}

    # Save the file
    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = WORKFLOWS_DIR / filename
    filepath.write_text(content)

    # Update metadata
    metadata = _load_metadata()
    metadata[filename] = {
        "description": description,
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "size_bytes": len(content.encode()),
    }
    _save_metadata(metadata)

    return {"result": (f"Workflow saved: {filepath}\nSize: {len(content.encode())} bytes\nSyntax: valid")}


def list_workflows(params: dict) -> dict:
    if not WORKFLOWS_DIR.exists():
        return {"result": "No workflows directory found. Save a workflow first."}

    py_files = sorted(WORKFLOWS_DIR.glob("*.py"))
    if not py_files:
        return {"result": "No workflow files found in ~/workspace/airt/workflows/"}

    metadata = _load_metadata()

    lines = [f"Saved workflows ({len(py_files)}):"]
    for f in py_files:
        meta = metadata.get(f.name, {})
        desc = meta.get("description", "")
        saved_at = meta.get("saved_at", "unknown")
        size = f.stat().st_size
        desc_str = f" — {desc}" if desc else ""
        lines.append(f"  - {f.name} ({size}B, saved {saved_at}){desc_str}")

    return {"result": "\n".join(lines)}


def execute_workflow(params: dict) -> dict:
    """Execute a generated workflow script."""
    import subprocess

    filename = params.get("filename", "")
    if not filename:
        return {"error": "filename is required"}

    # Reject path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        return {"error": "Filename must not contain path separators or '..'"}

    if not filename.endswith(".py"):
        filename += ".py"

    filepath = WORKFLOWS_DIR / filename
    if not filepath.exists():
        # List available workflows
        available = [f.name for f in WORKFLOWS_DIR.glob("*.py")] if WORKFLOWS_DIR.exists() else []
        return {"error": f"Workflow not found: {filename}. Available: {available}"}

    timeout = int(params.get("timeout", 300))
    timeout = min(timeout, 600)  # Max 10 minutes

    try:
        python_executable = resolve_python_executable()
        print(f"[INFO] Executing workflow with Python: {python_executable}", file=sys.stderr)
        result = subprocess.run(
            [python_executable, str(filepath)],
            cwd=str(WORKFLOWS_DIR.parent),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output_parts = []
        if result.stdout.strip():
            output_parts.append(result.stdout.strip())
        if result.stderr.strip():
            output_parts.append(f"[stderr]\n{result.stderr.strip()}")

        output = "\n".join(output_parts) or "(no output)"

        if result.returncode != 0:
            return {"result": f"Workflow exited with code {result.returncode}.\n\n{output}"}

        return {"result": f"Workflow completed successfully.\n\n{output}"}

    except subprocess.TimeoutExpired:
        return {"result": f"Workflow timed out after {timeout}s. Partial output may be in ~/workspace/airt/."}
    except Exception as e:
        return {"error": f"Failed to execute workflow: {e}"}


METHODS = {
    "save_workflow": save_workflow,
    "list_workflows": list_workflows,
    "execute_workflow": execute_workflow,
}


def main() -> None:
    raw = sys.stdin.read()
    request = json.loads(raw)
    # The capability wrapper sends method="tool" (type discriminator) and name="save_workflow" etc.
    # Use "name" field which contains the actual tool name.
    method = request.get("name", request.get("method", ""))
    params = request.get("parameters", {})

    handler = METHODS.get(method)
    if not handler:
        print(json.dumps({"error": f"Unknown method: {method}"}))
        sys.exit(1)

    try:
        result = handler(params)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
