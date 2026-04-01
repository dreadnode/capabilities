"""
Review highlight tool for flagging lower-confidence security findings.

Use this to flag code patterns that deserve human review but don't meet
the bar for a full vulnerability report.
"""

import typing as t
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, PrivateAttr

from dreadnode.agents.tools import Toolset, tool_method


class ReviewPriority(str, Enum):
    """Priority level for flagged items."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReviewHighlight(BaseModel):
    """A code pattern flagged for human review."""

    title: str
    """Short title describing the concern."""

    description: str
    """Detailed description of why this needs review."""

    file_path: str
    """Path to the file containing the concerning code."""

    line_number_start: int
    """Starting line number of the concerning code."""

    line_number_end: int | None = None
    """Ending line number (if multi-line)."""

    priority: ReviewPriority = ReviewPriority.MEDIUM
    """Priority level (high/medium/low)."""

    category: str | None = None
    """Optional category (e.g., 'auth', 'crypto', 'input-validation')."""

    timestamp: str
    """ISO timestamp when the highlight was created."""


class ReviewHighlightReport(BaseModel):
    """Collection of flagged items for review."""

    highlights: list[ReviewHighlight] = []
    """All flagged items."""


class ReviewHighlightTool(Toolset):
    """Tool for flagging code patterns that deserve human review."""

    _highlights: ReviewHighlightReport = PrivateAttr(
        default_factory=lambda: ReviewHighlightReport(highlights=[])
    )

    @property
    def highlights(self) -> ReviewHighlightReport:
        """Access the collected highlights."""
        return self._highlights

    def _log_to_platform(self) -> None:
        """Log review highlight metrics and data to the Dreadnode platform."""
        try:
            from dreadnode import log_metric, log_output

            highlights = self._highlights.highlights

            # Log metrics for tracking
            log_metric("review_highlights_count", len(highlights))

            # Count by priority
            priority_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
            for h in highlights:
                priority_counts[h.priority.value] = (
                    priority_counts.get(h.priority.value, 0) + 1
                )

            for priority, count in priority_counts.items():
                log_metric(f"review_highlights_{priority}", count)

            # Log structured output for UI display
            log_output("review_highlights", [h.model_dump() for h in highlights])

        except Exception as e:
            # Platform integration is optional - don't fail if it's not available
            logger.debug(f"Platform logging unavailable: {e}")

    @tool_method(catch=True)
    def highlight_for_review(
        self,
        title: str,
        description: str,
        file_path: str,
        line_number_start: int,
        priority: t.Literal["high", "medium", "low"] = "medium",
        line_number_end: int | None = None,
        category: str | None = None,
    ) -> str:
        """
        Flag a code pattern for human security review.

        Use this when you find something concerning that doesn't meet the bar
        for a full vulnerability report, but warrants human attention. This
        includes patterns that:

        - Are potentially dangerous but need more context to confirm
        - Represent defense-in-depth concerns
        - Show coding practices that could lead to vulnerabilities
        - Need domain knowledge to evaluate properly

        Args:
            title: Short title describing the concern (e.g., "Unchecked user input
                in SQL query construction").
            description: Detailed description explaining why this needs review,
                what the potential risk is, and what a reviewer should look for.
            file_path: Path to the file containing the concerning code.
            line_number_start: Starting line number of the concerning code.
            priority: Priority level - "high" for likely issues, "medium" for
                moderate concerns, "low" for minor observations.
            line_number_end: Ending line number if the concern spans multiple lines.
            category: Optional category like "auth", "crypto", "input-validation",
                "error-handling", "logging", etc.

        Returns:
            Confirmation message with the highlight ID.
        """
        # Resolve file path
        filepath = Path(file_path)
        if not filepath.is_absolute():
            filepath = Path.cwd() / filepath
        filepath = filepath.resolve()

        if not filepath.exists():
            logger.warning(f"Highlighted file does not exist: {filepath}")

        highlight = ReviewHighlight(
            title=title,
            description=description,
            file_path=str(filepath),
            line_number_start=line_number_start,
            line_number_end=line_number_end,
            priority=ReviewPriority(priority),
            category=category,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        self._highlights.highlights.append(highlight)
        highlight_id = len(self._highlights.highlights)

        # Log to platform for tracking
        self._log_to_platform()

        logger.info(
            f"Flagged for review [{priority.upper()}]: {title} at {filepath}:{line_number_start}"
        )

        location = f"{filepath}:{line_number_start}"
        if line_number_end and line_number_end != line_number_start:
            location = f"{filepath}:{line_number_start}-{line_number_end}"

        return (
            f"Flagged for review (#{highlight_id}):\n"
            f"  Title: {title}\n"
            f"  Location: {location}\n"
            f"  Priority: {priority}\n"
            f"  Category: {category or 'general'}"
        )

    @tool_method(catch=True)
    def get_review_highlights(self) -> str:
        """
        Get all items flagged for human review.

        Returns a summary of all highlights organized by priority.

        Returns:
            Formatted summary of all flagged items.
        """
        highlights = self._highlights.highlights

        if not highlights:
            return "No items have been flagged for review."

        # Group by priority
        by_priority: dict[str, list[tuple[int, ReviewHighlight]]] = {
            "high": [],
            "medium": [],
            "low": [],
        }

        for idx, h in enumerate(highlights, 1):
            by_priority[h.priority.value].append((idx, h))

        lines = [f"Review Highlights ({len(highlights)} total):"]
        lines.append("=" * 50)

        for priority in ["high", "medium", "low"]:
            items = by_priority[priority]
            if not items:
                continue

            lines.append(f"\n[{priority.upper()}] ({len(items)} items)")
            lines.append("-" * 40)

            for idx, h in items:
                location = f"{h.file_path}:{h.line_number_start}"
                if h.line_number_end and h.line_number_end != h.line_number_start:
                    location = (
                        f"{h.file_path}:{h.line_number_start}-{h.line_number_end}"
                    )

                lines.append(f"\n#{idx}: {h.title}")
                lines.append(f"    Location: {location}")
                if h.category:
                    lines.append(f"    Category: {h.category}")
                # Truncate long descriptions
                desc = h.description
                if len(desc) > 200:
                    desc = desc[:197] + "..."
                lines.append(f"    {desc}")

        return "\n".join(lines)


def get_all_highlights(tool: ReviewHighlightTool) -> ReviewHighlightReport:
    """Get all highlights from a tool instance (for programmatic access)."""
    return tool.highlights


def clear_highlights(tool: ReviewHighlightTool) -> None:
    """Clear all stored highlights (useful between runs)."""
    tool._highlights.highlights.clear()
