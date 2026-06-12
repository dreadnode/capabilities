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

# Load the shared safe_tool wrapper by file path. Capability tool files are
# loaded as flat modules (no parent package), so relative imports do not work.
import importlib.util as _ilu
from pathlib import Path as _Path
_errors_path = _Path(__file__).resolve().parent / "errors.py"
_spec = _ilu.spec_from_file_location("airt_tools_errors", _errors_path)
_errors_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_errors_mod)
safe_tool = _errors_mod.safe_tool
from dreadnode.app.env import resolve_python_executable


def _resolve_platform_env() -> dict[str, str]:
    """Build env dict with platform credentials for subprocess execution.

    Mirrors attack_runner._resolve_platform_env so manually-executed
    workflows get the same credential resolution as auto-executed ones.
    """
    env = os.environ.copy()
    if env.get("DREADNODE_SERVER") and env.get("DREADNODE_API_KEY"):
        return env
    if env.get("DREADNODE_LLM_BASE") and env.get("DREADNODE_LLM_API_KEY"):
        return env
    try:
        import yaml
        config_path = Path.home() / ".dreadnode" / "config.yaml"
        if config_path.exists():
            config = yaml.safe_load(config_path.read_text())
            active = config.get("active")
            servers = config.get("servers", {})
            if active and active in servers:
                profile = servers[active]
                env.setdefault("DREADNODE_SERVER", profile.get("url", ""))
                env.setdefault("DREADNODE_API_KEY", profile.get("api_key", ""))
                env.setdefault("DREADNODE_ORGANIZATION", profile.get("default_organization", ""))
                env.setdefault("DREADNODE_WORKSPACE", profile.get("default_workspace", ""))
                env.setdefault("DREADNODE_PROJECT", profile.get("default_project", ""))
    except Exception:
        pass
    return env


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


WORKFLOWS_DIR = (
    Path(os.environ.get("AIRT_WORKFLOWS_DIR"))
    if os.environ.get("AIRT_WORKFLOWS_DIR")
    else _get_workspace_path()
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


@safe_tool
def save_workflow(
    filename: t.Annotated[str, "Filename for the workflow (e.g., 'my_attack.py')"],
    code: t.Annotated[str, "Python source code for the workflow"],
    description: t.Annotated[str, "Brief description of what the workflow does"] = "",
) -> str:
    """Save a Python attack workflow with syntax validation.

    Validates the code compiles, saves to ~/.dreadnode/airt/[org]/[workspace]/workflows/,
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

    # Read existing content (if any) for comparison
    existing_content = ""
    if filepath.exists():
        try:
            existing_content = filepath.read_text()
        except Exception:
            pass  # File may be locked/unreadable

    # Attempt write
    try:
        filepath.write_text(code)
    except Exception as e:
        return f"Error writing file: {e}"

    # Verify write succeeded by reading back
    try:
        written_content = filepath.read_text()
        if written_content != code:
            return f"Error: File write incomplete (expected {len(code)} chars, got {len(written_content)})"

        # Check if content actually changed when overwriting
        if existing_content and existing_content == written_content and existing_content != code:
            return f"Warning: File exists but content unchanged - write may have failed silently: {filepath}"

    except Exception as e:
        return f"Error verifying write: {e}"

    # Update metadata only after successful verification
    meta = _load_metadata()
    meta[filename] = {
        "description": description,
        "size": len(code),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_metadata(meta)

    # Success - file confirmed written with correct content
    status = "updated" if existing_content else "created"
    return f"Workflow {status}: {filepath} ({len(code)} bytes) - content verified"


@safe_tool
def list_workflows() -> str:
    """List saved attack workflows with metadata.

    Shows all Python scripts in ~/.dreadnode/airt/[org]/[workspace]/workflows/ with
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


@safe_tool
def execute_workflow(
    filename: t.Annotated[str, "Workflow filename to execute"],
    timeout: t.Annotated[int, "Max execution time in seconds (max 3600)"] = 540,
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

    timeout = min(timeout, 3600)

    try:
        python_executable = resolve_python_executable()
        print(
            f"[INFO] Executing workflow with Python: {python_executable}",
            file=sys.stderr,
        )
        result = subprocess.run(
            [python_executable, str(filepath)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(WORKFLOWS_DIR.parent),
            env=_resolve_platform_env(),
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
