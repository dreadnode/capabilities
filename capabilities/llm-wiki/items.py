"""Typed Agent Output records for the LLM Wiki capability."""

import typing as t

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

WikiPageKind = t.Literal[
    "overview",
    "source-summary",
    "entity",
    "concept",
    "comparison",
    "synthesis",
]
ClaimConfidence = t.Literal["high", "medium", "low"]
WikiId = t.Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
    ),
]
NonEmptyText = t.Annotated[str, StringConstraints(min_length=1)]
Tag = t.Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
    ),
]


class WikiClaim(BaseModel):
    """One evidence-bearing claim compiled into a wiki page."""

    model_config = ConfigDict(extra="forbid")

    statement: str = Field(
        ...,
        min_length=1,
        description="A concise factual or analytical claim.",
    )
    evidence: list[NonEmptyText] = Field(
        ...,
        min_length=1,
        description="Source URLs, file:line locations, quotations, or artifact references.",
    )
    confidence: ClaimConfidence = Field(
        default="medium",
        description="Confidence justified by the available evidence.",
    )


class WikiPage(BaseModel):
    """A maintained unit of structured knowledge in the LLM Wiki."""

    model_config = ConfigDict(extra="forbid")

    wiki_id: WikiId = Field(
        description=(
            "Stable namespace for one independent wiki in a shared project. "
            "Use the same lowercase kebab-case value for every page in that wiki."
        )
    )
    title: str = Field(..., min_length=1, max_length=512)
    kind: WikiPageKind = Field(description="The page's role in the wiki.")
    summary: str = Field(
        ...,
        min_length=1,
        description="A compact index description used to decide whether to read this page.",
    )
    claims: list[WikiClaim] = Field(
        default_factory=list,
        description="Evidence-bearing facts and conclusions maintained on this page.",
    )
    synthesis: str | None = Field(
        default=None,
        description="Higher-level interpretation derived from the claims.",
    )
    open_questions: list[NonEmptyText] = Field(
        default_factory=list,
        description="Unresolved questions that should guide later ingestion or research.",
    )
    tags: list[Tag] = Field(
        default_factory=list,
        description="Short discovery labels; use lowercase kebab-case.",
    )
    source_refs: list[NonEmptyText] = Field(
        default_factory=list,
        description="Canonical source URLs, file paths, document IDs, or artifact references.",
    )
