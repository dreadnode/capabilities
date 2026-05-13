from typing import Literal

import dreadnode as dn
from dreadnode.agents.tools import tool
from pydantic import BaseModel, Field


class Target(BaseModel):
    ip: str = Field(description="IP address of the target")


class Service(BaseModel):
    """A service running on a host."""

    service_name: str = Field(description="Name of the service (e.g., SMB, SSH, HTTP)")
    version: str = Field(description="Version of the service")


class DomainController(BaseModel):
    """Represents a Domain Controller in an Active Directory environment."""

    hostname: str = Field(description="Short hostname (e.g., 'servername')")
    fqdn: str = Field(description="Fully qualified domain name")
    ip: str = Field(description="IP address of the domain controller")
    domain_name: str = Field(description="AD domain this DC serves (e.g., 'subname.servername.local')")
    forest_root: str | None = Field(None, description="Forest root domain name")


class MemberServer(BaseModel):
    """Represents a Member Server in an Active Directory environment."""

    hostname: str = Field(description="Short hostname (e.g., 'servername')")
    fqdn: str | None = Field(None, description="Fully qualified domain name")
    ip: str = Field(description="IP address of the member server")
    domain_name: str | None = Field(None, description="AD domain the server belongs to")


class Hash(BaseModel):
    """A password hash."""

    hash_value: str = Field(description="The actual hash value")
    hash_type: Literal["ntlm", "kerberos_tgs", "kerberos_asrep"] = Field(description="Type of hash algorithm used")


class Credential(BaseModel):
    """A credential, e.g. username/password combination or hash."""

    text: str = Field(description="Text representation of the credential")
    type: Literal["username_password", "hash"] = Field(description="Type of credential")


class User(BaseModel):
    """A user account."""

    username: str = Field(description="Username or account name")
    domain: str = Field(description="Domain the user belongs to")
    description: list[str] = Field(description="User account description or notes")


class Share(BaseModel):
    """A network share."""

    share_name: str = Field(description="Share name (e.g., C$, ADMIN$, SYSVOL)")
    path: str = Field(description="UNC path to the share")
    description: str = Field(description="Share description or comment")
    permissions: str = Field(description="Permission string for the share")
    type: Literal["read", "write", "execute"] = Field(description="Access type available")
    owner: str = Field(description="Owner of the share")
    group: str = Field(description="Group that owns the share")
    size: int = Field(description="Size of the share in bytes")
    last_modified: str = Field(description="Last modification timestamp")


class Weakness(BaseModel):
    """A security vulnerability, weakness, or misconfiguration."""

    cve: str | None = Field(None, description="CVE identifier")
    title: str = Field(description="Weakness title/name")
    description: str | None = Field(None, description="Weakness description")
    severity: Literal["low", "medium", "high", "critical"] = Field(description="Severity of the weakness")


@tool
def report_item(
    item: DomainController | MemberServer | User | Credential | Share | Hash | Weakness,
) -> None:
    """
    Report a relevant item found during enumeration. \
    Use this tool immediately and often.
    """
    dn.log_output(item.__class__.__name__, item)
