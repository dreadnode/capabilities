"""
Think tool for recording reasoning during security analysis.

Allows the agent to document its reasoning process without taking
any action. Useful for complex analysis that benefits from explicit
step-by-step thinking.
"""

from dreadnode.agents.tools import tool
from loguru import logger


@tool(catch=True)
def think(thought: str) -> str:
    """
    Record a thought, reflection, or reasoning step during analysis.

    Use this tool to think through complex security analysis decisions,
    document your reasoning process, or plan your next steps. This helps
    maintain a clear audit trail of how conclusions were reached.

    This tool does NOT take any action - it only records your reasoning.

    When to use:
    - Breaking down complex data flow analysis
    - Weighing whether a pattern is exploitable
    - Planning the next investigation steps
    - Documenting why something is NOT a vulnerability

    Args:
        thought: Your reasoning, reflection, or analysis. Be specific
            and include relevant details about what you're considering.

    Returns:
        Confirmation that the thought was recorded.
    """
    logger.info(f"Agent thought: {thought}")
    return f"Thought recorded: {thought[:100]}{'...' if len(thought) > 100 else ''}"
