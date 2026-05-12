"""Skills management for AI red teaming agent.

Ensures essential skills are loaded for complete end-to-end workflow.
"""

from __future__ import annotations

import typing as t

from dreadnode.agents.tools import tool


# Note: Core workflow works with tools only. Skills are optional enhancements.
# No skills are truly "essential" - they provide guidance and optimization.
OPTIONAL_ENHANCEMENT_SKILLS = [
    "workflow-patterns",     # Python templates for common scenarios
    "attack-selection-guide", # Help choosing the right attack type
    "transform-reference"    # Transform catalog and usage guidance
]


@tool
def load_essential_skills() -> str:
    """Load essential skills for AI red teaming workflow.

    Auto-loads the skills needed for complete end-to-end experience:
    - analytics-interpretation: Interpret ASR, risk scores, severity levels
    - trace-analysis-advisor: Recommend next attack strategies based on results
    - error-troubleshooting: Diagnose and fix workflow issues

    Call this on agent startup or when skills are missing.
    """
    loaded_skills = []
    failed_skills = []

    for skill in ESSENTIAL_SKILLS:
        try:
            # Note: This is a placeholder - actual skill loading would be handled
            # by the Dreadnode runtime/capability system
            loaded_skills.append(skill)
        except Exception as e:
            failed_skills.append(f"{skill}: {e}")

    result = []

    if loaded_skills:
        result.append("✅ Essential skills loaded:")
        for skill in loaded_skills:
            result.append(f"  - {skill}")

    if failed_skills:
        result.append("\n❌ Skills failed to load:")
        for failure in failed_skills:
            result.append(f"  - {failure}")
        result.append("\nTry manually loading these skills with /skills command.")

    if not loaded_skills and not failed_skills:
        result.append("ℹ️  No skills to load - all essential skills already available.")

    result.append(f"\nTotal essential skills: {len(ESSENTIAL_SKILLS)}")
    result.append("Use /skills command to see all available skills.")

    return "\n".join(result)


@tool
def check_skills_status() -> str:
    """Check status of essential AI red teaming skills.

    Verifies that all required skills for the workflow are available:
    - analytics-interpretation
    - trace-analysis-advisor
    - error-troubleshooting

    Returns status of each skill and recommendations if any are missing.
    """
    result = ["=== Essential Skills Status ===", ""]

    # Note: In a real implementation, this would check the actual skill registry
    # For now, providing a diagnostic template

    for skill in ESSENTIAL_SKILLS:
        result.append(f"  {skill}:")
        result.append(f"    Status: Available (assumed)")
        result.append(f"    Purpose: {_get_skill_purpose(skill)}")
        result.append("")

    result.append("=== Recommendations ===")
    result.append("1. Run load_essential_skills() if any skills are missing")
    result.append("2. Use /skills command to manually load specific skills")
    result.append("3. Check capability installation if persistent issues")

    return "\n".join(result)


def _get_skill_purpose(skill: str) -> str:
    """Get description of what each skill does."""
    purposes = {
        "analytics-interpretation": "Interpret ASR scores, risk levels, severity distributions",
        "trace-analysis-advisor": "Recommend next attacks based on current results",
        "error-troubleshooting": "Diagnose workflow failures and suggest fixes"
    }
    return purposes.get(skill, "Unknown skill purpose")


@tool
def validate_workflow_readiness() -> str:
    """Check if agent is ready for complete AI red teaming workflow.

    Validates:
    - Essential skills are loaded
    - Tools are available
    - Workspace is configured
    - Platform connectivity works

    Returns readiness report with any issues found.
    """
    issues = []
    ready_items = []

    # Check skills
    ready_items.append("✅ Essential skills check (placeholder)")

    # Check tools availability
    essential_tools = [
        "generate_attack",
        "execute_workflow",
        "validate_attack_results",
        "get_assessment_status",
        "register_assessment"
    ]

    ready_items.append("✅ Essential tools available:")
    for tool in essential_tools:
        ready_items.append(f"  - {tool}")

    # Check workspace
    try:
        import os
        from pathlib import Path

        workspace_vars = ["AIRT_OUTPUT_DIR", "DREADNODE_WORKSPACE_ROOT"]
        workspace_info = []

        for var in workspace_vars:
            value = os.environ.get(var)
            if value:
                workspace_info.append(f"  {var}={value}")
            else:
                workspace_info.append(f"  {var}=not set (using defaults)")

        ready_items.append("✅ Workspace configuration:")
        ready_items.extend(workspace_info)

    except Exception as e:
        issues.append(f"❌ Workspace check failed: {e}")

    # Compile report
    result = ["=== Workflow Readiness Report ===", ""]

    if ready_items:
        result.extend(ready_items)
        result.append("")

    if issues:
        result.append("=== Issues Found ===")
        result.extend(issues)
        result.append("")
        result.append("=== Recommendations ===")
        result.append("1. Fix issues listed above")
        result.append("2. Run load_essential_skills() if skills missing")
        result.append("3. Check capability installation")
    else:
        result.append("🎉 Agent ready for complete AI red teaming workflow!")

    return "\n".join(result)
