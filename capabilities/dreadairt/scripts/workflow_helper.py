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

WORKFLOWS_DIR = Path(
    os.environ.get(
        "DREADAIRT_WORKFLOWS_DIR",
        os.path.expanduser("~/workspace/airt/workflows"),
    )
)
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


METHODS = {
    "save_workflow": save_workflow,
    "list_workflows": list_workflows,
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
