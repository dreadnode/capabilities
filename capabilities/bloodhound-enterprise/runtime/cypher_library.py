"""Curated catalog of canonical AD / Azure attack-pattern Cypher queries.

The library exists for two reasons:

1. **Self-driving exploration**. An agent dropped into a fresh BHE
   deployment doesn't know which questions to ask first. The
   library is a curriculum — known-useful queries the agent can
   walk before inventing its own. The :file:`attack-pattern-explore`
   skill drives the walk.

2. **Reference + reuse**. Every query is named, documented,
   read-only, and LIMIT-bounded. The agent can run one by id
   without re-deriving safe Cypher each time, and can use the
   stored body as a starting point when adapting for a one-off
   question.

Each entry is a :class:`AttackPattern` carrying:

- ``id``: short slug (e.g. ``kerb-roastable-tier-zero``).
- ``category``: bucket the pattern belongs to.
- ``name``: human-readable title.
- ``description``: one-paragraph summary of what the query finds
  and *why* it's interesting from an attack-path perspective.
- ``cypher``: the query body, always with an explicit LIMIT.
- ``attack_path_type``: BHE finding type the pattern correlates to
  (when applicable). Helps the explore skill prioritise patterns
  that map to currently-active findings.
- ``references``: free-form list of doc / blog references.

Cypher style invariants the library follows:

- All queries are read-only (no CREATE / MERGE / DELETE / SET).
- Every query has an explicit LIMIT — the runtime adds one if
  missing, but explicit caps make the catalog auditable.
- High-value flags use the documented properties: ``highvalue``,
  ``hasspn``, ``enabled``, ``unconstraineddelegation``,
  ``trustedtoauth``, ``owned``.
- Tier Zero membership is detected via ``highvalue=true`` (the
  computed flag) — selectors and tag membership use a separate
  query family because the property names vary by deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AttackPattern:
    """One curated query with metadata."""

    id: str
    category: str
    name: str
    description: str
    cypher: str
    attack_path_type: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------


CATEGORIES = (
    "domain-admins",
    "tier-zero",
    "kerberos",
    "delegation",
    "adcs",
    "acl-abuse",
    "sessions-lateral",
    "gpo",
    "credentials",
    "azure",
    "trust",
    "owned",
)


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------


_LIBRARY: list[AttackPattern] = [
    # -------------------- Domain admins / trusts --------------------
    AttackPattern(
        id="da-all-members",
        category="domain-admins",
        name="All Domain Admins",
        description=(
            "Every principal that is a transitive member of Domain Admins "
            "(SID ending -512). Direct + nested. The default starting point "
            "for any Active Directory engagement: confirms the actual scope "
            "of the most powerful AD group."
        ),
        cypher=(
            "MATCH p = (g:Group)<-[:MemberOf*1..]-(m) "
            "WHERE g.objectid ENDS WITH '-512' "
            "AND (m:User OR m:Computer) "
            "RETURN p LIMIT 500"
        ),
    ),
    AttackPattern(
        id="ea-all-members",
        category="domain-admins",
        name="All Enterprise Admins",
        description=(
            "Every principal that is a transitive member of Enterprise "
            "Admins (SID ending -519). Forest-wide privilege; inclusion "
            "should be deliberate and rare."
        ),
        cypher=(
            "MATCH p = (g:Group)<-[:MemberOf*1..]-(m) "
            "WHERE g.objectid ENDS WITH '-519' "
            "AND (m:User OR m:Computer) "
            "RETURN p LIMIT 500"
        ),
    ),
    AttackPattern(
        id="domain-trusts",
        category="trust",
        name="Domain Trust Map",
        description=(
            "Every TrustedBy relationship between domains in the forest. "
            "Use to audit cross-forest attack surfaces — incoming trusts "
            "expose the domain to whatever the trusted domain compromises."
        ),
        cypher="MATCH p = (d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN p LIMIT 100",
    ),
    AttackPattern(
        id="dcsync-rights",
        category="domain-admins",
        name="Principals with DCSync rights",
        description=(
            "Principals with GetChanges + GetChangesAll on a Domain — "
            "the right combo to perform DCSync (read every account's "
            "credential material). Should be limited to tier-zero "
            "service accounts; everything else is a finding."
        ),
        cypher=(
            "MATCH p = (n)-[:GetChanges|GetChangesAll]->(d:Domain) "
            "WITH n, d, COLLECT(type(LAST(relationships(p)))) as rights "
            "WHERE 'GetChanges' IN rights AND 'GetChangesAll' IN rights "
            "RETURN n, d LIMIT 200"
        ),
        attack_path_type="DCSync",
    ),
    # -------------------- Tier Zero --------------------
    AttackPattern(
        id="tier-zero-shortest-paths-to",
        category="tier-zero",
        name="Shortest paths to Tier Zero",
        description=(
            "From any non-tier-zero principal to anything flagged as "
            "highvalue. The signature query of attack-path analysis: "
            "shows the most efficient compromise routes the analysis "
            "engine cares about."
        ),
        cypher=(
            "MATCH p = shortestPath((s)-[*1..]->(t)) "
            "WHERE t.highvalue = true AND s <> t AND "
            "(s.highvalue IS NULL OR s.highvalue = false) "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="tier-zero-from-domain-users",
        category="tier-zero",
        name="Paths from Domain Users to Tier Zero",
        description=(
            "Paths where the source is the Domain Users group "
            "(SID ending -513). Every authenticated user is in this "
            "group, so any path here is exploitable by any compromised "
            "account in the domain. The single highest-impact lens."
        ),
        cypher=(
            "MATCH p = shortestPath((g:Group)-[*1..]->(t)) "
            "WHERE g.objectid ENDS WITH '-513' AND t.highvalue = true "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="tier-zero-from-authenticated-users",
        category="tier-zero",
        name="Paths from Authenticated Users to Tier Zero",
        description=(
            "Paths from the Authenticated Users well-known SID. "
            "Broader than Domain Users — also includes computer "
            "accounts and trusted-domain users. Anything reachable "
            "from here is exploitable cross-trust."
        ),
        cypher=(
            "MATCH p = shortestPath((g:Group)-[*1..]->(t)) "
            "WHERE g.objectid = 'S-1-5-11' AND t.highvalue = true "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="tier-zero-sessions",
        category="tier-zero",
        name="Tier Zero principal sessions",
        description=(
            "Computers where tier-zero principals have an active "
            "session. Each session is a credential-theft target — "
            "compromising the session-host gives the attacker the "
            "tier-zero account."
        ),
        cypher=("MATCH (c:Computer)-[:HasSession]->(u) " "WHERE u.highvalue = true " "RETURN c, u LIMIT 200"),
    ),
    AttackPattern(
        id="tier-zero-non-dc",
        category="tier-zero",
        name="Tier Zero principals NOT on a DC",
        description=(
            "Tier-zero principals (highvalue=true) that are NOT "
            "domain controllers. Useful when curating Tier Zero — "
            "non-DC tier-zero objects are usually deliberate "
            "inclusions but should be reviewed for drift."
        ),
        cypher=(
            "MATCH (n) WHERE n.highvalue = true "
            "AND NOT n:Computer OR (n:Computer AND NOT 'Domain Controllers' IN labels(n)) "
            "RETURN n LIMIT 500"
        ),
    ),
    # -------------------- Kerberos --------------------
    AttackPattern(
        id="kerb-roastable-all",
        category="kerberos",
        name="All Kerberoastable users",
        description=(
            "Users with a service principal name (SPN), which makes "
            "their TGS encrypted with their password hash and "
            "offline-crackable. Excludes gMSA / krbtgt / disabled."
        ),
        cypher=(
            "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true "
            "AND NOT u.objectid ENDS WITH '-502' "
            "AND NOT u.gmsa = true AND NOT u.msa = true "
            "RETURN u LIMIT 500"
        ),
        attack_path_type="Kerberoastable",
    ),
    AttackPattern(
        id="kerb-roastable-tier-zero",
        category="kerberos",
        name="Kerberoastable Tier Zero users",
        description=(
            "Tier-zero users with an SPN — the highest-impact "
            "Kerberoasting targets. Cracking one of these gives "
            "the attacker tier-zero credentials directly."
        ),
        cypher=(
            "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true "
            "AND NOT u.objectid ENDS WITH '-502' "
            "AND NOT u.gmsa = true AND NOT u.msa = true "
            "AND u.highvalue = true "
            "RETURN u LIMIT 100"
        ),
        attack_path_type="Kerberoastable",
    ),
    AttackPattern(
        id="kerb-asreproast",
        category="kerberos",
        name="AS-REP roastable users",
        description=(
            "Users with PreAuthentication disabled. Any unauthenticated "
            "attacker can request a TGT and crack it offline. Should "
            "be empty; any results are findings."
        ),
        cypher=("MATCH (u:User) WHERE u.dontreqpreauth = true " "AND u.enabled = true " "RETURN u LIMIT 200"),
        attack_path_type="ASREPRoastable",
    ),
    AttackPattern(
        id="kerb-passwords-never-expire-tier-zero",
        category="credentials",
        name="Tier Zero with PasswordNeverExpires",
        description=(
            "Tier-zero accounts with passwords that don't expire — "
            "long-lived credentials in privileged accounts compound "
            "the impact of an offline crack."
        ),
        cypher=(
            "MATCH (u:User) WHERE u.pwdneverexpires = true "
            "AND u.highvalue = true AND u.enabled = true "
            "RETURN u LIMIT 200"
        ),
    ),
    # -------------------- Delegation --------------------
    AttackPattern(
        id="deleg-unconstrained-non-dc",
        category="delegation",
        name="Unconstrained delegation (non-DC)",
        description=(
            "Computers (or users) with unconstrained delegation set, "
            "excluding domain controllers. Compromising one allows "
            "harvesting any TGT presented to it — a path to forest "
            "compromise via printer-bug-style coercion."
        ),
        cypher=(
            "MATCH (c) WHERE c.unconstraineddelegation = true "
            "AND NOT (c:Computer AND c.objectid ENDS WITH '-1000') "
            "AND NOT EXISTS { "
            "MATCH (c)-[:MemberOf*1..]->(g:Group) "
            "WHERE g.objectid ENDS WITH '-516' } "
            "RETURN c LIMIT 200"
        ),
    ),
    AttackPattern(
        id="deleg-constrained-tier-zero",
        category="delegation",
        name="Constrained delegation onto Tier Zero",
        description=(
            "Principals with constrained delegation rights (S4U2Proxy) "
            "to a tier-zero target — a privilege escalation to the "
            "target identity."
        ),
        cypher=("MATCH p = (n)-[:AllowedToDelegate]->(t) " "WHERE t.highvalue = true " "RETURN p LIMIT 200"),
    ),
    AttackPattern(
        id="deleg-rbcd-writeable",
        category="delegation",
        name="Resource-Based Constrained Delegation writers",
        description=(
            "Principals with WriteAccountRestrictions (or GenericAll/"
            "GenericWrite) on a computer — they can configure RBCD "
            "to themselves and impersonate arbitrary identities to "
            "the computer."
        ),
        cypher=(
            "MATCH p = (n)-[:WriteAccountRestrictions|GenericAll|GenericWrite|Owns|WriteOwner|WriteDacl]->(c:Computer) "
            "WHERE NOT n:Computer OR n.objectid <> c.objectid "
            "RETURN p LIMIT 300"
        ),
    ),
    AttackPattern(
        id="deleg-trustedtoauth",
        category="delegation",
        name="Computers trusted to authenticate (S4U2Self)",
        description=(
            "Computers with TrustedToAuthForDelegation set — combined "
            "with constrained delegation, lets the principal "
            "impersonate any identity to a downstream service."
        ),
        cypher=("MATCH (c:Computer) WHERE c.trustedtoauth = true " "RETURN c LIMIT 200"),
    ),
    # -------------------- ADCS / PKI --------------------
    AttackPattern(
        id="adcs-esc1",
        category="adcs",
        name="ADCS ESC1: Misconfigured cert templates",
        description=(
            "Cert templates that allow a low-privileged enrollee to "
            "specify SubjectAltName, with client authentication EKU "
            "and no manager approval. The most common ADCS abuse — "
            "any enrollee becomes any user."
        ),
        cypher=(
            "MATCH (ct:CertTemplate) "
            "WHERE ct.requiresmanagerapproval = false "
            "AND ct.authenticationenabled = true "
            "AND ct.enrolleessuppliessubject = true "
            "RETURN ct LIMIT 200"
        ),
        attack_path_type="ADCSESC1",
    ),
    AttackPattern(
        id="adcs-esc2",
        category="adcs",
        name="ADCS ESC2: Any-Purpose cert templates",
        description=(
            "Cert templates with an Any-Purpose EKU (or no EKU at "
            "all) and low-privileged enrollment. Issued certificates "
            "can sign anything — code, other certs, you name it."
        ),
        cypher=(
            "MATCH (ct:CertTemplate) "
            "WHERE ct.requiresmanagerapproval = false "
            "AND (ct.effectiveekus IS NULL OR size(ct.effectiveekus) = 0 "
            "     OR '2.5.29.37.0' IN ct.effectiveekus) "
            "RETURN ct LIMIT 200"
        ),
        attack_path_type="ADCSESC2",
    ),
    AttackPattern(
        id="adcs-esc3",
        category="adcs",
        name="ADCS ESC3: Enrollment Agent templates",
        description=(
            "Cert templates with the Enrollment Agent EKU. An "
            "attacker with one such cert can request certs on "
            "behalf of any user, bypassing template policy."
        ),
        cypher=(
            "MATCH (ct:CertTemplate) "
            "WHERE ct.effectiveekus IS NOT NULL "
            "AND ('1.3.6.1.4.1.311.20.2.1' IN ct.effectiveekus "
            "     OR 'Certificate Request Agent' IN ct.effectiveekus) "
            "RETURN ct LIMIT 100"
        ),
        attack_path_type="ADCSESC3",
    ),
    AttackPattern(
        id="adcs-esc4",
        category="adcs",
        name="ADCS ESC4: Writable cert templates",
        description=(
            "Cert templates with weak ACLs — principals other than "
            "tier-zero can write the template's properties, "
            "effectively turning any template into ESC1."
        ),
        cypher=(
            "MATCH p = (n)-[:GenericAll|GenericWrite|Owns|WriteOwner|WriteDacl]->(ct:CertTemplate) "
            "WHERE NOT n.highvalue = true "
            "RETURN p LIMIT 200"
        ),
        attack_path_type="ADCSESC4",
    ),
    AttackPattern(
        id="adcs-esc5",
        category="adcs",
        name="ADCS ESC5: PKI object ACLs",
        description=(
            "Principals with control over PKI objects (CA, "
            "NTAuthCertificates, RootCA) outside Tier Zero. Can "
            "publish rogue templates or issue trusted certs."
        ),
        cypher=(
            "MATCH p = (n)-[:GenericAll|GenericWrite|Owns|WriteOwner|WriteDacl|ManageCa|ManageCertificates]->(ca) "
            "WHERE (ca:EnterpriseCA OR ca:AIACA OR ca:RootCA) "
            "AND NOT n.highvalue = true "
            "RETURN p LIMIT 200"
        ),
        attack_path_type="ADCSESC5",
    ),
    AttackPattern(
        id="adcs-esc6",
        category="adcs",
        name="ADCS ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2",
        description=(
            "Enterprise CAs with the EDITF_ATTRIBUTESUBJECTALTNAME2 "
            "flag set — every cert request can specify SAN, turning "
            "every enrollable template into an ESC1."
        ),
        cypher=("MATCH (ca:EnterpriseCA) " "WHERE ca.isuserspecifiessanenabled = true " "RETURN ca LIMIT 50"),
        attack_path_type="ADCSESC6",
    ),
    AttackPattern(
        id="adcs-esc8",
        category="adcs",
        name="ADCS ESC8: HTTP enrollment + NTLM",
        description=(
            "Enterprise CAs with HTTP enrollment endpoints and NTLM "
            "authentication enabled. NTLM relay against the web "
            "endpoint yields a domain-controller cert — full domain "
            "compromise from an unauthenticated network position."
        ),
        cypher=(
            "MATCH (ca:EnterpriseCA) "
            "WHERE ca.hasenrollmentagentrestrictions = false "
            "AND ca.hasvulnerableendpoint = true "
            "RETURN ca LIMIT 50"
        ),
        attack_path_type="ADCSESC8",
    ),
    AttackPattern(
        id="adcs-esc15",
        category="adcs",
        name="ADCS ESC15: EKUwu",
        description=(
            "Cert templates that allow Subject Alternative Name to "
            "include arbitrary application policies — abuses the "
            "v1 schema to inject EKUs not declared on the template."
        ),
        cypher=(
            "MATCH (ct:CertTemplate) "
            "WHERE ct.schemaversion = 1 "
            "AND ct.enrolleessuppliessubject = true "
            "AND ct.requiresmanagerapproval = false "
            "RETURN ct LIMIT 100"
        ),
        attack_path_type="ADCSESC15",
    ),
    # -------------------- ACL abuse --------------------
    AttackPattern(
        id="acl-genericall-on-tier-zero",
        category="acl-abuse",
        name="GenericAll on Tier Zero",
        description=(
            "Non-tier-zero principals with GenericAll (full control) "
            "over a tier-zero object. The most privileged ACL abuse "
            "— equivalent to ownership."
        ),
        cypher=(
            "MATCH p = (n)-[:GenericAll]->(t) "
            "WHERE t.highvalue = true "
            "AND (n.highvalue IS NULL OR n.highvalue = false) "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="acl-writedacl-on-tier-zero",
        category="acl-abuse",
        name="WriteDacl / WriteOwner on Tier Zero",
        description=(
            "Non-tier-zero principals that can rewrite a tier-zero "
            "object's ACL or claim ownership. One step away from "
            "GenericAll."
        ),
        cypher=(
            "MATCH p = (n)-[:WriteDacl|WriteOwner|Owns]->(t) "
            "WHERE t.highvalue = true "
            "AND (n.highvalue IS NULL OR n.highvalue = false) "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="acl-resetpassword-on-tier-zero",
        category="acl-abuse",
        name="ForceChangePassword on Tier Zero users",
        description=(
            "Non-tier-zero principals with the right to reset a "
            "tier-zero user's password. One reset and the attacker "
            "has the credential."
        ),
        cypher=(
            "MATCH p = (n)-[:ForceChangePassword]->(u:User) "
            "WHERE u.highvalue = true "
            "AND (n.highvalue IS NULL OR n.highvalue = false) "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="acl-shadow-credentials",
        category="acl-abuse",
        name="Shadow Credentials writeable",
        description=(
            "Principals with WriteAccountRestrictions or GenericAll "
            "on tier-zero accounts — can add a key credential and "
            "PKINIT-authenticate as the target."
        ),
        cypher=(
            "MATCH p = (n)-[:AddKeyCredentialLink|WriteAccountRestrictions|GenericAll]->(t) "
            "WHERE t.highvalue = true "
            "AND (n.highvalue IS NULL OR n.highvalue = false) "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="acl-adminsdholder",
        category="acl-abuse",
        name="AdminSDHolder writers",
        description=(
            "Principals with write access to AdminSDHolder. The SDPROP "
            "process applies AdminSDHolder ACLs to every protected "
            "account every hour — a write here propagates to Domain "
            "Admins automatically."
        ),
        cypher=(
            "MATCH p = (n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(c:Container) "
            "WHERE c.distinguishedname STARTS WITH 'CN=ADMINSDHOLDER' "
            "RETURN p LIMIT 100"
        ),
    ),
    # -------------------- Sessions / lateral --------------------
    AttackPattern(
        id="lateral-rdp-targets-domain-users",
        category="sessions-lateral",
        name="RDP targets reachable from Domain Users",
        description=(
            "Computers Domain Users (transitively) can RDP into. "
            "The first-hop lateral movement surface from any "
            "compromised user."
        ),
        cypher=(
            "MATCH p = (g:Group)-[:CanRDP|MemberOf*1..]->(c:Computer) "
            "WHERE g.objectid ENDS WITH '-513' "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="lateral-admin-from-owned",
        category="owned",
        name="Admin paths from owned principals",
        description=(
            "Where currently-marked owned principals can become local "
            "admin (transitively). The "
            "directly-actionable post-compromise inventory."
        ),
        cypher=(
            "MATCH p = shortestPath((s)-[*1..]->(c:Computer)) "
            "WHERE s.owned = true "
            "AND EXISTS { MATCH (s)-[:AdminTo|MemberOf*1..]->(c) } "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="owned-to-tier-zero",
        category="owned",
        name="Owned-to-Tier-Zero shortest paths",
        description=(
            "Shortest paths from any owned principal to anything "
            "tier-zero. The post-incident triage view: 'we've got "
            "footholds — how close are we to a forest compromise?'"
        ),
        cypher=(
            "MATCH p = shortestPath((s)-[*1..]->(t)) "
            "WHERE s.owned = true AND t.highvalue = true AND s <> t "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="lateral-sessions-on-domain-controllers",
        category="sessions-lateral",
        name="Sessions on Domain Controllers",
        description=(
            "Every active session on a domain controller. DCs should "
            "only show service accounts and tier-zero administrators "
            "— anything else is unwanted exposure."
        ),
        cypher=(
            "MATCH (c:Computer)-[:HasSession]->(u:User) "
            "WHERE EXISTS { MATCH (c)-[:MemberOf*1..]->(g:Group) "
            "WHERE g.objectid ENDS WITH '-516' } "
            "RETURN c, u LIMIT 200"
        ),
    ),
    # -------------------- GPOs --------------------
    AttackPattern(
        id="gpo-controllers-non-tier-zero",
        category="gpo",
        name="Non-tier-zero principals controlling GPOs",
        description=(
            "Principals that can edit a GPO who aren't themselves "
            "tier-zero. Editing a GPO that links to a high-value OU "
            "is a privilege escalation."
        ),
        cypher=(
            "MATCH p = (n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO) "
            "WHERE (n.highvalue IS NULL OR n.highvalue = false) "
            "RETURN p LIMIT 200"
        ),
    ),
    AttackPattern(
        id="gpo-linked-to-dc-ou",
        category="gpo",
        name="GPOs linked to Domain Controllers OU",
        description=(
            "GPOs linked to OUs containing domain controllers. "
            "Anyone who can edit one of these GPOs can run code on "
            "every DC under it."
        ),
        cypher=(
            "MATCH p = (g:GPO)-[:GPLink]->(o:OU) "
            "WHERE o.distinguishedname CONTAINS 'OU=DOMAIN CONTROLLERS' "
            "RETURN p LIMIT 100"
        ),
    ),
    AttackPattern(
        id="gpo-linked-to-tier-zero-ou",
        category="gpo",
        name="GPOs linked to Tier Zero OUs",
        description=(
            "GPOs linked to OUs that contain tier-zero objects. A "
            "wider net than the DC-OU view: any tier-zero-bearing "
            "OU's GPO is a tier-zero config surface."
        ),
        cypher=(
            "MATCH (o:OU)-[:Contains*1..]->(t) "
            "WHERE t.highvalue = true "
            "WITH DISTINCT o "
            "MATCH p = (g:GPO)-[:GPLink]->(o) "
            "RETURN p LIMIT 200"
        ),
    ),
    # -------------------- Credentials --------------------
    AttackPattern(
        id="cred-laps-readers",
        category="credentials",
        name="LAPS password readers",
        description=(
            "Principals that can read LAPS-managed local-admin "
            "passwords on domain-joined machines. Each principal × "
            "computer pair is a one-step local-admin path."
        ),
        cypher=("MATCH p = (n)-[:ReadLAPSPassword]->(c:Computer) " "RETURN p LIMIT 500"),
    ),
    AttackPattern(
        id="cred-gmsa-readers",
        category="credentials",
        name="gMSA password readers",
        description=(
            "Principals that can read a Group Managed Service "
            "Account's password. Compromising a reader yields the "
            "service identity directly."
        ),
        cypher=("MATCH p = (n)-[:ReadGMSAPassword]->(u:User) " "WHERE u.gmsa = true " "RETURN p LIMIT 200"),
    ),
    AttackPattern(
        id="cred-stale-tier-zero",
        category="credentials",
        name="Stale Tier Zero accounts",
        description=(
            "Tier-zero accounts that haven't logged on in 90+ days. "
            "Stale accounts compound risk: they're forgotten, often "
            "unmonitored, and their SPNs / delegation rights still "
            "apply if compromised."
        ),
        cypher=(
            "MATCH (u:User) WHERE u.highvalue = true "
            "AND u.lastlogontimestamp IS NOT NULL "
            "AND u.lastlogontimestamp < (timestamp() / 1000 - 7776000) "
            "AND u.enabled = true "
            "RETURN u LIMIT 200"
        ),
    ),
    AttackPattern(
        id="cred-old-passwords-tier-zero",
        category="credentials",
        name="Tier Zero with old passwords",
        description=(
            "Tier-zero accounts whose password hasn't rotated in "
            "180+ days. Long-lived secrets in privileged accounts "
            "increase the offline-crack and replay windows."
        ),
        cypher=(
            "MATCH (u:User) WHERE u.highvalue = true "
            "AND u.pwdlastset IS NOT NULL "
            "AND u.pwdlastset < (timestamp() / 1000 - 15552000) "
            "AND u.enabled = true "
            "RETURN u LIMIT 200"
        ),
    ),
    # -------------------- Azure --------------------
    AttackPattern(
        id="az-global-admins",
        category="azure",
        name="Azure Global Administrators",
        description=(
            "Every principal holding the Global Administrator role "
            "directly or transitively. Tenant-wide privilege; should "
            "be a small fixed list of break-glass accounts."
        ),
        cypher=(
            "MATCH p = (n)-[:AZHasRole|AZMemberOf*1..]->(r:AZRole) "
            "WHERE r.templateid = '62e90394-69f5-4237-9190-012177145e10' "
            "RETURN p LIMIT 100"
        ),
    ),
    AttackPattern(
        id="az-owners-on-subscription",
        category="azure",
        name="Subscription Owners",
        description=(
            "Principals with the Owner role on an Azure subscription. "
            "Can manage every resource in the subscription, including "
            "running code on every VM."
        ),
        cypher=("MATCH p = (n)-[:AZOwns]->(s:AZSubscription) RETURN p LIMIT 200"),
    ),
    AttackPattern(
        id="az-app-credential-rights",
        category="azure",
        name="Apps where users can add credentials",
        description=(
            "Principals with AppRoleAssignment.ReadWrite.All or "
            "Application.ReadWrite.All — can add credentials to any "
            "app and impersonate it. A common cross-tenant escalation."
        ),
        cypher=("MATCH p = (n)-[:AZAddSecret|AZAddOwner]->(a:AZApp) " "RETURN p LIMIT 200"),
    ),
    AttackPattern(
        id="az-vm-runners",
        category="azure",
        name="Azure VM contributors / runners",
        description=(
            "Principals with VM Contributor / Run Command rights on "
            "Azure VMs. Can execute arbitrary code on every targeted "
            "VM as SYSTEM."
        ),
        cypher=("MATCH p = (n)-[:AZVMContributor|AZVMAdminLogin|AZRunCommand]->(v:AZVM) " "RETURN p LIMIT 200"),
    ),
    # -------------------- Trust / cross-domain --------------------
    AttackPattern(
        id="trust-sid-history",
        category="trust",
        name="Principals with SID history",
        description=(
            "Users / groups carrying a SID-history attribute. "
            "Cross-domain ACL tokens that can yield privilege in "
            "the trusted domain — frequently a remnant of botched "
            "migrations."
        ),
        cypher=("MATCH (u) WHERE u.sidhistory IS NOT NULL " "AND size(u.sidhistory) > 0 " "RETURN u LIMIT 200"),
    ),
    AttackPattern(
        id="trust-foreign-tier-zero-controllers",
        category="trust",
        name="Foreign-domain controllers of Tier Zero",
        description=(
            "Tier-zero controllers whose home domain differs from "
            "the target's. Cross-trust attack surface — typically "
            "should be empty in well-segmented forests."
        ),
        cypher=(
            "MATCH p = (n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(t) "
            "WHERE t.highvalue = true "
            "AND n.domain IS NOT NULL AND t.domain IS NOT NULL "
            "AND n.domain <> t.domain "
            "RETURN p LIMIT 200"
        ),
    ),
]


# ---------------------------------------------------------------------------
# Index + lookup
# ---------------------------------------------------------------------------


_BY_ID: dict[str, AttackPattern] = {p.id: p for p in _LIBRARY}


def all_patterns() -> tuple[AttackPattern, ...]:
    """Every pattern in the library, in catalog order."""
    return tuple(_LIBRARY)


def get_pattern(pattern_id: str) -> AttackPattern | None:
    """Look up a pattern by id; ``None`` if absent."""
    return _BY_ID.get(pattern_id)


def patterns_by_category(category: str) -> tuple[AttackPattern, ...]:
    """Every pattern in ``category`` (preserving catalog order)."""
    return tuple(p for p in _LIBRARY if p.category == category)


def patterns_for_finding(attack_path_type: str) -> tuple[AttackPattern, ...]:
    """Every pattern that correlates to ``attack_path_type``."""
    return tuple(p for p in _LIBRARY if p.attack_path_type == attack_path_type)


def category_counts() -> dict[str, int]:
    """``{category: count}`` summary, useful for UI / explore-skill."""
    out: dict[str, int] = {}
    for pattern in _LIBRARY:
        out[pattern.category] = out.get(pattern.category, 0) + 1
    return out


__all__ = [
    "AttackPattern",
    "CATEGORIES",
    "all_patterns",
    "category_counts",
    "get_pattern",
    "patterns_by_category",
    "patterns_for_finding",
]
