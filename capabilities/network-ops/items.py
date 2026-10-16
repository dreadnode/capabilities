"""Structured item types for the network-ops capability.

These Pydantic models define the schemas for items emitted via
``report_item`` during Active Directory and network penetration-testing
engagements. They are referenced by the ``outputs`` key in
``capability.yaml`` (as ``items:ClassName``) and validated at emit time,
so the agent gets immediate feedback on malformed payloads and the
records surface in Agent Output alongside the built-in ``finding`` and
``asset`` types.

Design principles
-----------------
- Fields mirror what an operator can actually observe during
  enumeration — not theoretical nice-to-haves. A field the producer
  cannot reliably know is optional, so realistic findings validate
  instead of failing or being hallucinated.
- Host role is explicit via a ``role`` discriminator rather than
  inferred from which optional fields happen to be populated.
- Field names that the coordinator worker keys on for finding
  extraction (``text``, ``hash_value``, ``severity``) are stable; see
  ``workers/coordinator.py``.

The ``report_item`` tool flattens every declared type's fields into a
single schema keyed by ``item_type``, so a field name shared across
types must carry the same type. ``title`` and ``description`` are
therefore kept string-typed everywhere, and the credential kind is
``credential_type`` to avoid colliding with other literal ``type``
fields.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Host(BaseModel):
    """A host discovered in the environment, with an explicit AD role.

    One model covers both domain controllers and member servers: ``role``
    records what the host is, rather than leaving it to be inferred from
    which optional fields are populated.
    """

    model_config = ConfigDict(extra="ignore")

    title: str = Field(description="Short label for the host, typically the hostname or FQDN.")
    role: Literal["domain_controller", "member_server"] = Field(
        description="Host role in the Active Directory environment."
    )
    hostname: str = Field(description="Short hostname (e.g., 'dc01').")
    ip: str | None = Field(None, description="IP address of the host, if known.")
    fqdn: str | None = Field(None, description="Fully qualified domain name, if known.")
    domain_name: str | None = Field(None, description="AD domain the host serves or belongs to (e.g., 'corp.local').")
    forest_root: str | None = Field(None, description="Forest root domain name (domain controllers only).")


class Hash(BaseModel):
    """A password hash."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(description="Short label, e.g. the account the hash belongs to.")
    hash_value: str = Field(description="The actual hash value.")
    hash_type: Literal["ntlm", "kerberos_tgs", "kerberos_asrep"] = Field(description="Type of hash algorithm used.")


class Credential(BaseModel):
    """A credential, e.g. username/password combination or hash."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(description="Short label, e.g. the account the credential is for.")
    text: str = Field(description="Text representation of the credential.")
    credential_type: Literal["username_password", "hash"] = Field(description="Kind of credential.")


class User(BaseModel):
    """A user account."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(description="Short label for the account, typically the username.")
    username: str = Field(description="Username or account name.")
    domain: str | None = Field(None, description="Domain the user belongs to, if known.")
    description: str | None = Field(None, description="Account description or notes, if available.")


class Share(BaseModel):
    """A network share.

    Only the share name is required; the remaining attributes are
    optional because an operator often observes a share without knowing
    its owner, group, size, or timestamps.
    """

    model_config = ConfigDict(extra="ignore")

    title: str = Field(description="Short label for the share, typically its name.")
    share_name: str = Field(description="Share name (e.g., C$, ADMIN$, SYSVOL).")
    path: str | None = Field(None, description="UNC path to the share, if known.")
    permissions: str | None = Field(
        None, description="Observed permissions for the share (e.g., 'READ', 'READ,WRITE')."
    )
    description: str | None = Field(None, description="Share description or comment.")
    owner: str | None = Field(None, description="Owner of the share, if known.")
    group: str | None = Field(None, description="Group that owns the share, if known.")
    size: int | None = Field(None, description="Size of the share in bytes, if known.")
    last_modified: str | None = Field(None, description="Last modification timestamp, if known.")


class Weakness(BaseModel):
    """A security vulnerability, weakness, or misconfiguration."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(description="Weakness title/name.")
    # Values match the platform's built-in finding severity (dreadnode
    # ItemSeverity). report_item flattens every declared type into one schema,
    # first definition wins, and the built-in finding owns `severity`; a narrower
    # enum here would let the agent pick an offered value (such as "info") that
    # this model then rejects.
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Impact level: critical, high, medium, low, or info."
    )
    cve: str | None = Field(None, description="CVE identifier, if applicable.")
    description: str | None = Field(None, description="Weakness description.")
