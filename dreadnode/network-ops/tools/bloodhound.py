import asyncio
import os
import time
import typing as t
from enum import Enum

import aiohttp
from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from loguru import logger
from neo4j import AsyncGraphDatabase  # type: ignore[import-untyped]

# BloodHound parameters
VAR_MAP = {
    "url": {"env_var": "BLOODHOUND_URL", "default": "localhost:8080"},
    "username": {"env_var": "BLOODHOUND_USERNAME", "default": "admin"},
    "password": {"env_var": "BLOODHOUND_PASSWORD", "default": "bloodhound"},
    "neo4j_url": {"env_var": "BLOODHOUND_NEO4J_URL", "default": "bolt://localhost:7687"},
    "neo4j_username": {"env_var": "BLOODHOUND_NEO4J_USERNAME", "default": "neo4j"},
    "neo4j_password": {
        "env_var": "BLOODHOUND_NEO4J_PASSWORD",
        "default": "bloodhoundcommunityedition",
    },
    "neo4j_encrypt": {"env_var": "BLOODHOUND_NEO4J_ENCRYPT", "default": False},
    "neo4j_database": {"env_var": "BLOODHOUND_NEO4J_DB", "default": "neo4j"},
}


class CollectionUploadJobStatus(str, Enum):
    """Status codes for BloodHound collection upload jobs."""

    INVALID = -1
    READY = 0
    RUNNING = 1
    COMPLETE = 2
    CANCELED = 3
    TIMED_OUT = 4
    FAILED = 5
    INGESTING = 6
    ANALYZING = 7
    PARTIALLY_COMPLETE = 8


# BloodHound server processing delay for file acceptance (empirically determined).
# Through testing, a minimum delay of 45 seconds was found necessary for the server to reliably recognize uploaded files.
# Lower values may result in the server not recognizing the uploaded file, causing ingestion failures.
UPLOAD_ACCEPTANCE_DELAY = 45  # seconds

# NOTE: Add method names here for standard queries want exposed in the "standard_bloodhound_query" tool
# NOTE: We use this list of strings for annotations below so cant use a decorator pattern instead.
STANDARD_QUERY_NAMES = (
    "find_all_domain_admins",
    "map_domain_trusts",
    "find_tier_zero_locations",
    "map_ou_structure",
    "find_dcsync_privileges",
    "find_foreign_group_memberships",
    "find_domain_users_local_admins",
    "find_domain_users_laps_readers",
    "find_domain_users_high_value_paths",
    "find_domain_users_workstation_rdp",
    "find_domain_users_server_rdp",
    "find_domain_users_privileges",
    "find_domain_admin_non_dc_logons",
    "find_kerberoastable_tier_zero",
    "find_all_kerberoastable_users",
    "find_kerberoastable_most_admin",
    "find_asreproast_users",
    "find_shortest_paths_unconstrained_delegation",
    "find_paths_from_kerberoastable_to_da",
    "find_shortest_paths_to_tier_zero",
    "find_paths_from_domain_users_to_tier_zero",
    "find_shortest_paths_to_domain_admins",
    "find_paths_from_owned_objects",
    "find_pki_hierarchy",
    "find_public_key_services",
    "find_certificate_enrollment_rights",
    "find_esc1_vulnerable_templates",
    "find_esc2_vulnerable_templates",
    "find_enrollment_agent_templates",
    "find_dcs_weak_certificate_binding",
    "find_inactive_tier_zero_principals",
    "find_tier_zero_without_smartcard",
    "find_domains_with_machine_quota",
    "find_smartcard_dont_expire_domains",
    "find_two_way_forest_trust_delegation",
    "find_unsupported_operating_systems",
    "find_users_with_no_password_required",
    "find_users_password_not_rotated",
    "find_nested_tier_zero_groups",
    "find_disabled_tier_zero_principals",
    "find_principals_reversible_encryption",
    "find_principals_des_only_kerberos",
    "find_principals_weak_kerberos_encryption",
    "find_tier_zero_non_expiring_passwords",
    "find_ntlm_relay_edges",
    "find_esc8_vulnerable_cas",
    "find_computers_outbound_ntlm_deny",
    "find_computers_in_protected_users",
    "find_dcs_vulnerable_ntlm_relay",
    "find_computers_webclient_running",
    "find_computers_no_smb_signing",
    "find_global_administrators",
    "find_high_privileged_role_members",
    "find_paths_from_entra_to_tier_zero",
    "find_paths_to_privileged_roles",
    "find_paths_from_azure_apps_to_tier_zero",
    "find_paths_to_azure_subscriptions",
    "find_service_principals_with_app_role_grant",
    "find_service_principals_with_graph_assignments",
    "find_foreign_tier_zero_principals",
    "find_synced_tier_zero_principals",
    "find_external_tier_zero_users",
    "find_disabled_azure_tier_zero_principals",
    "find_devices_unsupported_os",
    "find_entra_users_in_domain_admins",
    "find_onprem_users_owning_entra_objects",
    "find_onprem_users_in_entra_groups",
    "find_templates_no_security_extension",
    "find_templates_with_user_specified_san",
    "find_ca_administrators",
    "find_onprem_users_with_direct_entra_roles",
    "find_onprem_users_with_group_entra_roles",
    "find_onprem_users_with_direct_azure_roles",
    "find_onprem_users_with_group_azure_roles",
)


class Bloodhound(Toolset):
    """
    A toolset for BloodHound CE server.

    Any environment variables will overwrite default configuration for the tool.
    """

    url: str = Config(default="localhost:8080", description="BloodHound CE server URL (host:port)")
    username: str = Config(default="admin", description="BloodHound CE API username")
    password: str = Config(default="bloodhound", description="BloodHound CE API password")
    neo4j_url: str = Config(
        default="bolt://localhost:7687", description="Neo4j database connection URL"
    )
    neo4j_username: str = Config(default="neo4j", description="Neo4j database username")
    neo4j_password: str = Config(
        default="bloodhoundcommunityedition", description="Neo4j database password"
    )
    neo4j_encrypt: bool = Config(
        default=False,
        description="Specify whether to use an encrypted connection between the Neo4j driver and server.",
    )
    neo4j_database: str = Config(
        default="neo4j",
        description="Name of Neo4j database. For Bloodhound CE, default database is 'neo4j'.",
    )

    async def __aenter__(self):
        """Initialize BloodHound toolset with Neo4j driver and API authentication."""
        # Reconcile parameters
        for var, meta in VAR_MAP.items():
            if getattr(self, var) == meta["default"]:
                # since parameter is default value, check if defined in environment
                env_var_value = os.getenv(meta["env_var"], None)
                if env_var_value:
                    setattr(self, var, env_var_value)

        if not self.neo4j_encrypt:
            logger.warning("Neo4j driver connection is not encrypted.")

        self._graph_driver = AsyncGraphDatabase.driver(
            self.neo4j_url,
            auth=(self.neo4j_username, self.neo4j_password),
            encrypted=self.neo4j_encrypt,
        )

        await self.verify_neo4j_connectivity()

        auth_token = await self._api_authenticate()
        if auth_token is None:
            raise RuntimeError(
                f"Could not authenticate to BloodHound REST API at {self.url}. Check credentials and server availability."
            )

        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Clean up resources and close Neo4j driver connection."""
        await self._graph_driver.close()
        if exc_type is not None:
            raise RuntimeError("Error occurred when trying to exit tool context.") from exc

    async def _api_authenticate(self) -> dict | None:
        """Authenticate to BloodHound API and get access token to use for REST API"""

        if (
            getattr(self, "_api_auth_token", None) is not None
            and not self._api_auth_token["auth_expired"]
        ):
            return self._api_auth_token

        url = f"http://{self.url}/api/v2/login"
        auth_data = {
            "login_method": "secret",
            "username": self.username,
            "secret": self.password,
        }
        auth_token = None
        async with (
            aiohttp.ClientSession() as session,
            session.post(url=url, json=auth_data) as resp,
        ):
            auth_token = await resp.json()

        if not auth_token or not isinstance(auth_token.get("data"), dict) or not auth_token["data"]:
            raise RuntimeError(
                f"Couldn't authenticate to BloodHound REST API. Response: {auth_token}"
            )

        self._api_auth_token = auth_token["data"]

        return self._api_auth_token

    async def verify_neo4j_connectivity(self) -> bool:
        """Verify BloodHound Neo4j database connectivity"""
        try:
            async with self._graph_driver.session(database=self.neo4j_database) as session:
                logger.info(
                    f"Attempting to verify connection to Neo4j database '{self.neo4j_database}'..."
                )
                result = await session.run("MATCH (n:User) RETURN count(n) as count")
                record = await result.single()
                count = record["count"]
                logger.info(
                    f"Successfully connected to database '{self.neo4j_database}'. Found {count} users."
                )
                return True
        except Exception as e:
            raise RuntimeError(f"Failed to connect to database '{self.neo4j_database}'.") from e

    # TODO(author): Paging or clipping of response data if too large
    @tool_method(variants=["all"], catch=True)
    async def query_bloodhound(
        self,
        query: t.Annotated[
            str,
            "Cypher BloodHound query to execute. Make sure to use parameter variables in the query for representing data values.",
        ],
        parameters: t.Annotated[
            dict | None,
            "parameter key-values to use in query. keys must match parameter variables in query.",
        ] = None,
    ) -> dict:
        """Execute a Cypher query against the BloodHound Neo4j database."""
        try:
            async with self._graph_driver.session(database=self.neo4j_database) as session:
                result = await session.run(query, parameters=parameters)
                data = [record.data() async for record in result]
                return {"success": True, "data": data}
        except Exception as e:
            raise RuntimeError(f"Query failed on database '{self.neo4j_database}'.") from e

    @tool_method(variants=["all"], catch=True)
    async def standard_bloodhound_query(self, name: str):
        """Execute a (pre-defined) standard query against Bloodhound Neo4j database."""
        if name not in STANDARD_QUERY_NAMES:
            raise ValueError(f"Query name must be one of: {STANDARD_QUERY_NAMES}")
        return await getattr(self, name)()

    # Domain Information Queries

    async def find_all_domain_admins(self) -> dict:
        """Find all users and computers that are members of the Domain Admins group."""
        query = """
        MATCH p = (t:Group)<-[:MemberOf*1..]-(a)
        WHERE (a:User or a:Computer) and t.objectid ENDS WITH '-512'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def map_domain_trusts(self) -> dict:
        """Map all trust relationships between domains in the Active Directory forest."""
        query = """
        MATCH p = (:Domain)-[:TrustedBy]->(:Domain)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_tier_zero_locations(self) -> dict:
        """Find all high-value tier zero assets contained within the domain."""
        query = """
        MATCH p = (t:Base)<-[:Contains*1..]-(:Domain)
        WHERE t.highvalue = true
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def map_ou_structure(self) -> dict:
        """Map the organizational unit (OU) hierarchy structure within the domain."""
        query = """
        MATCH p = (:Domain)-[:Contains*1..]->(:OU)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    # Dangerous Privileges Queries

    async def find_dcsync_privileges(self) -> dict:
        """Find principals with DCSync privileges that can replicate domain credentials."""
        query = """
        MATCH p=(:Base)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_foreign_group_memberships(self) -> dict:
        """Find cross-domain group memberships where users are in groups from different domains."""
        query = """
        MATCH p=(s:Base)-[:MemberOf]->(t:Group)
        WHERE s.domainsid<>t.domainsid
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_domain_users_local_admins(self) -> dict:
        """Find computers where the Domain Users group has local administrator access."""
        query = """
        MATCH p=(s:Group)-[:AdminTo]->(:Computer)
        WHERE s.objectid ENDS WITH '-513'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_domain_users_laps_readers(self) -> dict:
        """Find computers where Domain Users can read LAPS local administrator passwords."""
        query = """
        MATCH p=(s:Group)-[:AllExtendedRights|ReadLAPSPassword]->(:Computer)
        WHERE s.objectid ENDS WITH '-513'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_domain_users_high_value_paths(self) -> dict:
        """Find attack paths from Domain Users to high-value tier zero targets."""
        query = """
        MATCH p=shortestPath((s:Group)-[r*1..]->(t))
        WHERE t.highvalue = true AND s.objectid ENDS WITH '-513' AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_domain_users_workstation_rdp(self) -> dict:
        """Find workstations where Domain Users have RDP access."""
        query = """
        MATCH p=(s:Group)-[:CanRDP]->(t:Computer)
        WHERE s.objectid ENDS WITH '-513' AND NOT toUpper(t.operatingsystem) CONTAINS 'SERVER'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_domain_users_server_rdp(self) -> dict:
        """Find servers where Domain Users have RDP access."""
        query = """
        MATCH p=(s:Group)-[:CanRDP]->(t:Computer)
        WHERE s.objectid ENDS WITH '-513' AND toUpper(t.operatingsystem) CONTAINS 'SERVER'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_domain_users_privileges(self) -> dict:
        """Find all privileges and permissions granted to the Domain Users group."""
        query = """
        MATCH p=(s:Group)-[r]->(:Base)
        WHERE s.objectid ENDS WITH '-513'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_domain_admin_non_dc_logons(self) -> dict:
        """Find Domain Admin sessions on computers that are not domain controllers."""
        query = """
        MATCH (s)-[:MemberOf*0..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
        WITH COLLECT(s) AS exclude
        MATCH p = (c:Computer)-[:HasSession]->(:User)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-512' AND NOT c IN exclude
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    # Kerberos Interaction

    async def find_kerberoastable_tier_zero(self) -> dict:
        """Find high-value tier zero users vulnerable to Kerberoasting attacks."""
        query = """
        MATCH (u:User)
        WHERE u.hasspn=true
        AND u.enabled = true
        AND NOT u.objectid ENDS WITH '-502'
        AND NOT u.gmsa = true
        AND NOT u.msa = true
        AND u.highvalue = true
        RETURN u
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_all_kerberoastable_users(self) -> dict:
        """Find all enabled users with SPNs vulnerable to Kerberoasting attacks."""
        query = """
        MATCH (u:User)
        WHERE u.hasspn=true
        AND u.enabled = true
        AND NOT u.objectid ENDS WITH '-502'
        AND NOT u.gmsa = true
        AND NOT u.msa = true
        RETURN u
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_kerberoastable_most_admin(self) -> dict:
        """Find kerberoastable users with the most administrative access to computers."""
        query = """
        MATCH (u:User)
        WHERE u.hasspn = true
        AND u.enabled = true
        AND NOT u.objectid ENDS WITH '-502'
        AND NOT u.gmsa = true
        AND NOT u.msa = true
        MATCH (u)-[:MemberOf|AdminTo*1..]->(c:Computer)
        WITH DISTINCT u, COUNT(c) AS adminCount
        RETURN u
        ORDER BY adminCount DESC
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_asreproast_users(self) -> dict:
        """Find users vulnerable to AS-REP roasting attacks (no Kerberos pre-authentication)."""
        query = """
        MATCH (u:User)
        WHERE u.dontreqpreauth = true
        AND u.enabled = true
        RETURN u
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    # Shortest Paths Queries

    async def find_shortest_paths_unconstrained_delegation(self) -> dict:
        """Find attack paths to computers with unconstrained Kerberos delegation enabled."""
        query = """
        MATCH p=shortestPath((s)-[r*1..]->(t:Computer))
        WHERE t.unconstraineddelegation = true AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_paths_from_kerberoastable_to_da(self) -> dict:
        """Find attack paths from kerberoastable users to Domain Admins group."""
        query = """
        MATCH p=shortestPath((s:User)-[r*1..]->(t:Group))
        WHERE s.hasspn=true
        AND s.enabled = true
        AND NOT s.objectid ENDS WITH '-502'
        AND NOT s.gmsa = true
        AND NOT s.msa = true
        AND t.objectid ENDS WITH '-512'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_shortest_paths_to_tier_zero(self) -> dict:
        """Find shortest attack paths from any principal to tier zero assets."""
        query = """
        MATCH p=shortestPath((s)-[r*1..]->(t))
        WHERE t.highvalue = true AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_paths_from_domain_users_to_tier_zero(self) -> dict:
        """Find attack paths from Domain Users group to tier zero assets."""
        query = """
        MATCH p=shortestPath((s:Group)-[r*1..]->(t))
        WHERE t.highvalue = true AND s.objectid ENDS WITH '-513' AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_shortest_paths_to_domain_admins(self) -> dict:
        """Find shortest attack paths from any principal to Domain Admins group."""
        query = """
        MATCH p=shortestPath((t:Group)<-[r*1..]-(s:Base))
        WHERE t.objectid ENDS WITH '-512' AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_paths_from_owned_objects(self) -> dict:
        """Find attack paths from owned/compromised principals to other targets."""
        query = """
        MATCH p=shortestPath((s:Base)-[r*1..]->(t:Base))
        WHERE s.owned = true AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    # Active Directory Certificate Services

    async def find_pki_hierarchy(self) -> dict:
        """Map the Active Directory Certificate Services (ADCS) PKI hierarchy."""
        query = """
        MATCH p=()-[:HostsCAService|IssuedSignedBy|EnterpriseCAFor|RootCAFor|TrustedForNTAuth|NTAuthStoreFor*..]->(:Domain)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_public_key_services(self) -> dict:
        """Find all objects within the Public Key Services container in Active Directory."""
        query = """
        MATCH p = (c:Container)-[:Contains*..]->(:Base)
        WHERE c.distinguishedname starts with 'CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC='
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_certificate_enrollment_rights(self) -> dict:
        """Find principals with certificate enrollment rights on certificate templates."""
        query = """
        MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_esc1_vulnerable_templates(self) -> dict:
        """Find certificate templates vulnerable to ESC1 (enrollee supplies subject name)."""
        query = """
        MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
        WHERE ct.enrolleesuppliessubject = true
        AND ct.authenticationenabled = true
        AND ct.requiresmanagerapproval = false
        AND (ct.authorizedsignatures = 0 OR ct.schemaversion = 1)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_esc2_vulnerable_templates(self) -> dict:
        """Find certificate templates vulnerable to ESC2 (Any Purpose EKU misconfiguration)."""
        query = """
        MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(c:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
        WHERE c.requiresmanagerapproval = false
        AND (c.effectiveekus = [''] OR '2.5.29.37.0' IN c.effectiveekus)
        AND (c.authorizedsignatures = 0 OR c.schemaversion = 1)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_enrollment_agent_templates(self) -> dict:
        """Find certificate templates with Certificate Request Agent EKU enabled."""
        query = """
        MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
        WHERE '1.3.6.1.4.1.311.20.2.1' IN ct.effectiveekus
        OR '2.5.29.37.0' IN ct.effectiveekus
        OR SIZE(ct.effectiveekus) = 0
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_dcs_weak_certificate_binding(self) -> dict:
        """Find domain controllers with weak certificate binding enforcement settings."""
        query = """
        MATCH p = (s:Computer)-[:DCFor]->(:Domain)
        WHERE s.strongcertificatebindingenforcementraw = 0 OR s.strongcertificatebindingenforcementraw = 1
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_inactive_tier_zero_principals(self) -> dict:
        """Find tier zero principals that have been inactive for over 60 days."""
        query = """
        WITH 60 as inactive_days
        MATCH (n:Base)
        WHERE n.highvalue = true
        AND n.enabled = true
        AND n.lastlogontimestamp < (datetime().epochseconds - (inactive_days * 86400))
        AND n.lastlogon < (datetime().epochseconds - (inactive_days * 86400))
        AND n.whencreated < (datetime().epochseconds - (inactive_days * 86400))
        AND NOT n.name STARTS WITH 'AZUREADKERBEROS.'
        AND NOT n.objectid ENDS WITH '-500'
        AND NOT n.name STARTS WITH 'AZUREADSSOACC.'
        RETURN n
        """
        return await self.query_bloodhound(query)

    async def find_tier_zero_without_smartcard(self) -> dict:
        """Find tier zero users that do not require smartcard authentication."""
        query = """
        MATCH (u:User)
        WHERE u.highvalue = true
        AND u.enabled = true
        AND u.smartcardrequired = false
        AND NOT u.name STARTS WITH 'MSOL_'
        AND NOT u.name STARTS WITH 'PROVAGENTGMSA'
        AND NOT u.name STARTS WITH 'ADSYNCMSA_'
        RETURN u
        """
        return await self.query_bloodhound(query)

    async def find_domains_with_machine_quota(self) -> dict:
        """Find domains that allow users to join machines to the domain (ms-DS-MachineAccountQuota)."""
        query = """
        MATCH (d:Domain)
        WHERE d.machineaccountquota > 0
        RETURN d
        """
        return await self.query_bloodhound(query)

    async def find_smartcard_dont_expire_domains(self) -> dict:
        """Find domains that don't expire passwords for smartcard-only accounts."""
        query = """
        MATCH (s:Domain)-[:Contains*1..]->(t:Base)
        WHERE s.expirepasswordsonsmartcardonlyaccounts = false
        AND t.enabled = true
        AND t.smartcardrequired = true
        RETURN s
        """
        return await self.query_bloodhound(query)

    async def find_two_way_forest_trust_delegation(self) -> dict:
        """Find bidirectional forest trusts with TGT delegation enabled."""
        query = """
        MATCH p=(n:Domain)-[r:TrustedBy]->(m:Domain)
        WHERE (m)-[:TrustedBy]->(n)
        AND r.trusttype = 'Forest'
        AND r.tgtdelegationenabled = true
        RETURN p
        """
        return await self.query_bloodhound(query)

    async def find_unsupported_operating_systems(self) -> dict:
        """Find computers running unsupported/end-of-life Windows operating systems."""
        query = """
        MATCH (c:Computer)
        WHERE c.operatingsystem =~ '(?i).*Windows.* (2000|2003|2008|2012|xp|vista|7|8|me|nt).*'
        RETURN c
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_users_with_no_password_required(self) -> dict:
        """Find user accounts that do not require a password to be set."""
        query = """
        MATCH (u:User)
        WHERE u.passwordnotreqd = true
        RETURN u
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_users_password_not_rotated(self) -> dict:
        """Find user accounts whose passwords haven't been changed in over 365 days."""
        query = """
        WITH 365 as days_since_change
        MATCH (u:User)
        WHERE u.pwdlastset < (datetime().epochseconds - (days_since_change * 86400))
        AND NOT u.pwdlastset IN [-1.0, 0.0]
        RETURN u
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_nested_tier_zero_groups(self) -> dict:
        """Find groups that are nested within tier zero groups."""
        query = """
        MATCH p=(t:Group)<-[:MemberOf*..]-(s:Group)
        WHERE t.highvalue = true
        AND NOT s.objectid ENDS WITH '-512'
        AND NOT s.objectid ENDS WITH '-519'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_disabled_tier_zero_principals(self) -> dict:
        """Find disabled tier zero principals that should be removed."""
        query = """
        MATCH (n:Base)
        WHERE n.highvalue = true
        AND n.enabled = false
        AND NOT n.objectid ENDS WITH '-502'
        AND NOT n.objectid ENDS WITH '-500'
        RETURN n
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_principals_reversible_encryption(self) -> dict:
        """Find principals storing passwords using reversible encryption."""
        query = """
        MATCH (n:Base)
        WHERE n.encryptedtextpwdallowed = true
        RETURN n
        """
        return await self.query_bloodhound(query)

    async def find_principals_des_only_kerberos(self) -> dict:
        """Find principals configured to use only weak DES encryption for Kerberos."""
        query = """
        MATCH (n:Base)
        WHERE n.enabled = true
        AND n.usedeskeyonly = true
        RETURN n
        """
        return await self.query_bloodhound(query)

    async def find_principals_weak_kerberos_encryption(self) -> dict:
        """Find principals supporting weak Kerberos encryption types (DES, RC4)."""
        query = """
        MATCH (u:Base)
        WHERE 'DES-CBC-CRC' IN u.supportedencryptiontypes
        OR 'DES-CBC-MD5' IN u.supportedencryptiontypes
        OR 'RC4-HMAC-MD5' IN u.supportedencryptiontypes
        RETURN u
        """
        return await self.query_bloodhound(query)

    async def find_tier_zero_non_expiring_passwords(self) -> dict:
        """Find tier zero users with passwords set to never expire."""
        query = """
        MATCH (u:User)
        WHERE u.enabled = true
        AND u.pwdneverexpires = true
        AND u.highvalue = true
        RETURN u
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    # NTLM Relay Attacks Queries

    async def find_ntlm_relay_edges(self) -> dict:
        """Find potential NTLM relay attack paths between principals."""
        query = """
        MATCH p = (n:Base)-[:CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToSMB]->(:Base)
        RETURN p LIMIT 500
        """
        return await self.query_bloodhound(query)

    async def find_esc8_vulnerable_cas(self) -> dict:
        """Find Certificate Authorities vulnerable to ESC8 (HTTP enrollment endpoints)."""
        query = """
        MATCH (n:EnterpriseCA)
        WHERE n.hasvulnerableendpoint=true
        RETURN n
        """
        return await self.query_bloodhound(query)

    async def find_computers_outbound_ntlm_deny(self) -> dict:
        """Find computers configured to restrict outbound NTLM authentication."""
        query = """
        MATCH (c:Computer)
        WHERE c.restrictoutboundntlm = True
        RETURN c LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_computers_in_protected_users(self) -> dict:
        """Find principals that are members of the Protected Users security group."""
        query = """
        MATCH p = (:Base)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH "-525"
        RETURN p LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_dcs_vulnerable_ntlm_relay(self) -> dict:
        """Find domain controllers vulnerable to NTLM relay attacks via LDAP."""
        query = """
        MATCH p = (dc:Computer)-[:DCFor]->(:Domain)
        WHERE (dc.ldapavailable = True AND dc.ldapsigning = False)
        OR (dc.ldapsavailable = True AND dc.ldapsepa = False)
        OR (dc.ldapavailable = True AND dc.ldapsavailable = True AND dc.ldapsigning = False and dc.ldapsepa = True)
        RETURN p
        """
        return await self.query_bloodhound(query)

    async def find_computers_webclient_running(self) -> dict:
        """Find computers with the WebClient service running (useful for coercion attacks)."""
        query = """
        MATCH (c:Computer)
        WHERE c.webclientrunning = True
        RETURN c LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_computers_no_smb_signing(self) -> dict:
        """Find computers that do not require SMB signing (vulnerable to relay attacks)."""
        query = """
        MATCH (n:Computer)
        WHERE n.smbsigning = False
        RETURN n
        """
        return await self.query_bloodhound(query)

    # Azure - General Queries

    async def find_global_administrators(self) -> dict:
        """Find all Azure Global Administrators with tenant-wide privileges."""
        query = """
        MATCH p = (:AZBase)-[:AZGlobalAdmin*1..]->(:AZTenant)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_high_privileged_role_members(self) -> dict:
        """Find members of high-privileged Azure roles like Global Administrator."""
        query = """
        MATCH p=(t:AZRole)<-[:AZHasRole|AZMemberOf*1..2]-(:AZBase)
        WHERE t.name =~ '(?i)(Global Administrator|User Access Administrator|Privileged Role Administrator|Privileged Authentication Administrator|Partner Tier1 Support|Partner Tier2 Support)'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    # Azure - Shortest Paths

    async def find_paths_from_entra_to_tier_zero(self) -> dict:
        """Find attack paths from Entra ID (Azure AD) users to tier zero roles."""
        query = """
        MATCH p=shortestPath((s:AZUser)-[r*1..]->(t:AZBase))
        WHERE t.highvalue = true AND t.name =~ '(?i)(Global Administrator|User Access Administrator|Privileged Role Administrator|Privileged Authentication Administrator|Partner Tier1 Support|Partner Tier2 Support)' AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_paths_to_privileged_roles(self) -> dict:
        """Find attack paths from any Azure principal to privileged Azure roles."""
        query = """
        MATCH p=shortestPath((s:AZBase)-[r*1..]->(t:AZRole))
        WHERE t.name =~ '(?i)(Global Administrator|User Access Administrator|Privileged Role Administrator|Privileged Authentication Administrator|Partner Tier1 Support|Partner Tier2 Support)' AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_paths_from_azure_apps_to_tier_zero(self) -> dict:
        """Find attack paths from Azure applications to tier zero assets."""
        query = """
        MATCH p=shortestPath((s:AZApp)-[r*1..]->(t:AZBase))
        WHERE t.highvalue = true AND s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_paths_to_azure_subscriptions(self) -> dict:
        """Find attack paths from any Azure principal to Azure subscriptions."""
        query = """
        MATCH p=shortestPath((s:AZBase)-[r*1..]->(t:AZSubscription))
        WHERE s<>t
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    # Azure - Microsoft Graph Queries

    async def find_service_principals_with_app_role_grant(self) -> dict:
        """Find Azure service principals with app role grant permissions."""
        query = """
        MATCH p=(:AZServicePrincipal)-[:AZMGGrantAppRoles]->(:AZTenant)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_service_principals_with_graph_assignments(self) -> dict:
        """Find service principals with high-privileged Microsoft Graph API permissions."""
        query = """
        MATCH p=(:AZServicePrincipal)-[:AZMGAppRoleAssignment_ReadWrite_All|AZMGApplication_ReadWrite_All|AZMGDirectory_ReadWrite_All|AZMGGroupMember_ReadWrite_All|AZMGGroup_ReadWrite_All|AZMGRoleManagement_ReadWrite_Directory|AZMGServicePrincipalEndpoint_ReadWrite_All]->(:AZServicePrincipal)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    # Azure - Hygiene Queries

    async def find_foreign_tier_zero_principals(self) -> dict:
        """Find tier zero Azure service principals owned by external organizations."""
        query = """
        MATCH (n:AZServicePrincipal)
        WHERE n.highvalue = true
        AND NOT toUpper(n.appownerorganizationid) = toUpper(n.tenantid)
        AND n.appownerorganizationid CONTAINS '-'
        RETURN n
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_synced_tier_zero_principals(self) -> dict:
        """Find tier zero principals synchronized from on-premises AD to Entra ID."""
        query = """
        MATCH (ENTRA:AZBase)
        MATCH (AD:Base)
        WHERE ENTRA.onpremsyncenabled = true
        AND ENTRA.onpremid = AD.objectid
        AND AD.highvalue = true
        RETURN ENTRA
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_external_tier_zero_users(self) -> dict:
        """Find external guest users with tier zero privileges in Azure."""
        query = """
        MATCH (n:AZUser)
        WHERE n.highvalue = true
        AND n.name CONTAINS '#EXT#@'
        RETURN n
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_disabled_azure_tier_zero_principals(self) -> dict:
        """Find disabled tier zero principals in Azure that should be removed."""
        query = """
        MATCH (n:AZBase)
        WHERE n.highvalue = true
        AND n.enabled = false
        RETURN n
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    async def find_devices_unsupported_os(self) -> dict:
        """Find Azure-joined devices running unsupported Windows operating systems."""
        query = """
        MATCH (n:AZDevice)
        WHERE n.operatingsystem CONTAINS 'WINDOWS'
        AND n.operatingsystemversion =~ '(10.0.19044|10.0.22000|10.0.19043|10.0.19042|10.0.19041|10.0.18363|10.0.18362|10.0.17763|10.0.17134|10.0.16299|10.0.15063|10.0.14393|10.0.10586|10.0.10240|6.3.9600|6.2.9200|6.1.7601|6.0.6200|5.1.2600|6.0.6003|5.2.3790|5.0.2195).?.*'
        RETURN n
        LIMIT 100
        """
        return await self.query_bloodhound(query)

    # Azure - Cross Platform Attack Paths Queries

    async def find_entra_users_in_domain_admins(self) -> dict:
        """Find Entra ID users synced to on-premises AD Domain Admins group."""
        query = """
        MATCH p = (:AZUser)-[:SyncedToADUser]->(:User)-[:MemberOf]->(t:Group)
        WHERE t.objectid ENDS WITH '-512'
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_onprem_users_owning_entra_objects(self) -> dict:
        """Find on-premises users synced to Entra ID with ownership of Azure objects."""
        query = """
        MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZOwns]->(:AZBase)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_onprem_users_in_entra_groups(self) -> dict:
        """Find on-premises users synced to Entra ID that are members of Azure groups."""
        query = """
        MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZMemberOf]->(:AZGroup)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_templates_no_security_extension(self) -> dict:
        """Find certificate templates without security extension flag set."""
        query = """
        MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
        WHERE ct.nosecurityextension = true
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_templates_with_user_specified_san(self) -> dict:
        """Find certificate templates that allow user-specified Subject Alternative Names."""
        query = """
        MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(eca:EnterpriseCA)
        WHERE eca.isuserspecifiessanenabled = True
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_ca_administrators(self) -> dict:
        """Find principals with administrative rights on Certificate Authorities."""
        query = """
        MATCH p = (:Base)-[:ManageCertificates|ManageCA]->(:EnterpriseCA)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_onprem_users_with_direct_entra_roles(self) -> dict:
        """Find on-premises users with direct Entra ID role assignments."""
        query = """
        MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZHasRole]->(:AZRole)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_onprem_users_with_group_entra_roles(self) -> dict:
        """Find on-premises users with Entra ID roles via group membership."""
        query = """
        MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZMemberOf]->(:AZGroup)-[:AZHasRole]->(:AZRole)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_onprem_users_with_direct_azure_roles(self) -> dict:
        """Find on-premises users with direct Azure RBAC role assignments."""
        query = """
        MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZOwner|AZUserAccessAdministrator|AZGetCertificates|AZGetKeys|AZGetSecrets|AZAvereContributor|AZKeyVaultContributor|AZContributor|AZVMAdminLogin|AZVMContributor|AZAKSContributor|AZAutomationContributor|AZLogicAppContributor|AZWebsiteContributor]->(:AZBase)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    async def find_onprem_users_with_group_azure_roles(self) -> dict:
        """Find on-premises users with Azure RBAC roles via group membership."""
        query = """
        MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZMemberOf]->(:AZGroup)-[:AZOwner|AZUserAccessAdministrator|AZGetCertificates|AZGetKeys|AZGetSecrets|AZAvereContributor|AZKeyVaultContributor|AZContributor|AZVMAdminLogin|AZVMContributor|AZAKSContributor|AZAutomationContributor|AZLogicAppContributor|AZWebsiteContributor]->(:AZBase)
        RETURN p
        LIMIT 1000
        """
        return await self.query_bloodhound(query)

    @tool_method(variants=["all"], catch=True)
    async def find_paths_user_to_user(
        self,
        source_user: t.Annotated[str, "source user to search for attack paths from"],
        target_user: t.Annotated[str, "target user to search for attack paths to"],
        domain: t.Annotated[str, "domain name where users exist"],
    ) -> dict:
        """Search for potential exploit/attack paths from source_user to target_user on the given domain."""
        query = """
        MATCH p=shortestPath((user1:User)-[*]->(user2:User))
        WHERE user1.name = $source_name
        AND user2.name = $target_name
        RETURN p
        """
        parameters = {
            "source_name": f"{source_user.upper()}@{domain.upper()}",
            "target_name": f"{target_user.upper()}@{domain.upper()}",
        }
        return await self.query_bloodhound(query, parameters=parameters)

    @tool_method(variants=["all"], catch=True)
    async def upload_collection_zip(
        self,
        filepath: t.Annotated[str, "path to the BloodHound collection zip file"],
        wait_for: t.Annotated[int, "time (seconds) to wait for upload job to complete"] = 90,
    ) -> str:
        """
        Upload a BloodHound collection zip file (that was collected via the SharpHound tool.)
        """

        await self._api_authenticate()

        # Validate the file before uploading
        upload_fn = os.path.abspath(filepath)

        if not os.path.exists(upload_fn):
            raise FileNotFoundError(f"File not found: {upload_fn}")

        if not os.path.isfile(upload_fn):
            raise FileNotFoundError(f"Path is not a file: {upload_fn}")

        if not os.access(upload_fn, os.R_OK):
            raise PermissionError(f"File is not readable: {upload_fn}")

        if not upload_fn.lower().endswith(".zip"):
            logger.warning(f"File does not have .zip extension: {upload_fn}")

        # 1. start BloodHound server upload job
        start_job = {
            "url": f"http://{self.url}/api/v2/file-upload/start",
            "headers": {
                "accept": "application/json",
                "Authorization": f"Bearer {self._api_auth_token['session_token']}",
            },
        }
        job_record_response = await self._async_post_request(resp_type="json", **start_job)
        assert isinstance(job_record_response, dict), "Expected dict response"
        job_record = job_record_response["data"]
        assert isinstance(job_record, dict), "Expected dict in data field"

        if not job_record.get("id", False):
            raise RuntimeError(
                f"Could not start collection upload on BloodHound server. Error: {job_record}."
            )

        # 2. upload BloodHound collection files
        upload_job = {
            "url": f"http://{self.url}/api/v2/file-upload/{job_record['id']}",
            "headers": {
                "accept": "application/zip",
                "Authorization": f"Bearer {self._api_auth_token['session_token']}",
            },
        }
        try:
            upload_job_status = await self._async_post_file(filename=upload_fn, **upload_job)
            logger.info(
                f"[Started] Collection file upload initiated: {upload_fn}.\n\nStatus: {upload_job_status}"
            )
        except Exception as e:
            raise RuntimeError("[Cancelled] Error uploading collection file to BloodHound.") from e

        # NOTE: playing it safe in case BH server upload is slow to accept file
        await asyncio.sleep(UPLOAD_ACCEPTANCE_DELAY)

        # 3. end BloodHound server upload job
        end_job = {
            "url": f"http://{self.url}/api/v2/file-upload/{job_record['id']}/end",
            "headers": {
                "accept": "application/json",
                "Authorization": f"Bearer {self._api_auth_token['session_token']}",
            },
        }
        await self._async_post_request(resp_type="text", **end_job)

        # wait for upload to complete
        upload_job_status = await self.wait_for_upload_completion(
            job_id=job_record["id"], wait_for=wait_for
        )
        if not upload_job_status["complete"]:
            raise RuntimeError(
                f"Timeout error of collection file upload for {upload_fn}.\n\n Dumping upload job status: {upload_job_status}"
            )

        success_msg = f"[Finished] Successfully uploaded {upload_fn} collection file to BloodHound."
        logger.info(success_msg)

        return success_msg

    # Utilities

    async def clear_database(self, wait_for: int = 60) -> t.Any:
        """
        Clear the BloodHound database.

        WARNING:'wait_for' values >=45 are recommended. Lower wait times (for the clear operation to finish) may lead to erroneous state when doing subsequent API operations.

        Note: This method is intentionally not decorated with @tool_method and is intended for internal use only due to its destructive nature.
        """
        await self._api_authenticate()

        clear_db_req = {
            "url": f"http://{self.url}/api/v2/clear-database",
            "headers": {
                "accept": "text/plain",
                "Authorization": f"Bearer {self._api_auth_token['session_token']}",
            },
            "json": {
                "deleteCollectedGraphData": True,
                "deleteFileIngestHistory": False,
                "deleteDataQualityHistory": True,
                "deleteAssetGroupSelectors": [0],
            },
        }

        clear_status = await self._async_post_request(**clear_db_req)

        logger.info("[Started] Clearing BloodHound database.")
        await asyncio.sleep(
            wait_for
        )  # TODO(author): have not found better solution for this, but without a delay/lock on API ops, need this or else can lead to erroneous states.
        logger.info(
            f"[Finished] Waited {wait_for} secs for BloodHound database clear operation to complete."
        )

        return clear_status

    async def wait_for_upload_completion(self, job_id: int | str, wait_for: int = 30) -> dict:
        """Wait for BloodHound collection upload job to complete with timeout."""
        start_time = int(time.time())
        while True:
            await asyncio.sleep(2)
            job_status = await self.upload_job_status(job_id=job_id)
            if job_status["complete"]:
                break
            if start_time + wait_for < int(time.time()):
                break
        return job_status

    async def upload_job_status(self, job_id: int | str) -> dict:
        """
        Check the status of a BloodHound collection upload job.
        """

        await self._api_authenticate()

        upload_status_job = {
            "url": f"http://{self.url}/api/v2/file-upload?id={job_id!s}",
            "headers": {
                "accept": "application/json",
                "Authorization": f"Bearer {self._api_auth_token['session_token']}",
            },
        }
        job_statuses_response = await self._async_get_request(resp_type="json", **upload_status_job)
        assert isinstance(job_statuses_response, dict), "Expected dict response"
        job_status = [j for j in job_statuses_response["data"] if str(j["id"]) == str(job_id)]

        if len(job_status) == 0:
            return {"complete": False, "status": None, "status_human": None}
        job_status_item = job_status[0]

        return {
            "complete": str(job_status_item["status"]) == CollectionUploadJobStatus.COMPLETE,
            "status": job_status_item,
            "status_human": next(
                (s for s in CollectionUploadJobStatus if s.value == str(job_status_item["status"])),
                "UNKNOWN",
            ),
        }

    async def _async_get_request(
        self, resp_type: t.Literal["text", "json"] | None = None, **kwargs
    ) -> dict | str:
        """Execute an async HTTP GET request to the BloodHound API."""
        async with aiohttp.ClientSession() as session, session.get(**kwargs) as resp:
            if resp_type == "json":
                return await resp.json()
            if resp_type == "text":
                return await resp.text()
            return str(resp)

    async def _async_post_request(
        self, resp_type: t.Literal["text", "json"] | None = None, **kwargs
    ) -> dict | str:
        """Execute an async HTTP POST request to the BloodHound API."""
        response = None
        async with aiohttp.ClientSession() as session, session.post(**kwargs) as resp:
            if resp_type == "json":
                response = await resp.json()
            elif resp_type == "text":
                response = await resp.text()
            else:
                response = str(resp)
        return response

    async def _async_post_file(self, url: str, filename: str, **kwargs) -> t.Any:
        """Upload a file to the BloodHound server via async HTTP POST."""
        response = None
        with open(filename, "rb") as fh:  # noqa: ASYNC230
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=fh, **kwargs) as resp:
                    if resp.status != 202:
                        resp.raise_for_status()
                    response = resp
        return response
