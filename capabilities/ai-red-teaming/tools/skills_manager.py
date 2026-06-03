"""Workflow readiness checks for the AI Red Teaming agent."""

from __future__ import annotations

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


def _resolve_workspace() -> tuple[Path, str, str, str | None]:
    """Resolve the active workspace path. Returns (path, org, workspace, error)."""
    try:
        from dreadnode.app.config import UserConfig

        config = UserConfig.read()
        profile_data = config.active_profile
        if profile_data:
            _, profile = profile_data
            org = profile.organization or "default"
            workspace = profile.workspace or "main"
        else:
            org = "default"
            workspace = "main"
        return (
            Path.home() / ".dreadnode" / "airt" / org / workspace,
            org,
            workspace,
            None,
        )
    except Exception as e:  # noqa: BLE001
        return (
            Path.home() / ".dreadnode" / "airt" / "default" / "main",
            "default",
            "main",
            str(e),
        )


@safe_tool
def validate_workflow_readiness() -> str:
    """Check if the agent is ready to run AI red teaming workflows.

    Verifies the workspace path is resolvable and writable. Returns a brief
    readiness report and surfaces actionable errors if any are found.
    """
    workspace_path, org, workspace, config_err = _resolve_workspace()
    workflows_dir = workspace_path / "workflows"

    report = ["=== Workflow Readiness ===", ""]
    report.append(f"Org / workspace: {org} / {workspace}")
    report.append(f"Workspace path:  {workspace_path}")

    issues: list[str] = []

    if config_err:
        issues.append(f"UserConfig unavailable, using fallback: {config_err}")

    try:
        workflows_dir.mkdir(parents=True, exist_ok=True)
        probe = workflows_dir / ".readiness_probe"
        probe.write_text("ok")
        probe.unlink()
        report.append("Workspace writable: yes")
    except Exception as e:  # noqa: BLE001
        issues.append(f"Workspace not writable: {e}")

    if issues:
        report.append("")
        report.append("=== Issues ===")
        report.extend(f"- {i}" for i in issues)
    else:
        report.append("")
        report.append("Ready.")

    return "\n".join(report)
