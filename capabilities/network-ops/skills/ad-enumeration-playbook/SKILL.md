---
name: ad-enumeration-playbook
description: "Decision tree for Active Directory enumeration. Maps enumeration tasks to tools, defines priority signals, and specifies what findings trigger deeper investigation. Use during the enumeration phase of network operations."
---

# AD Enumeration Playbook

Systematic enumeration produces the attack surface map that drives exploitation. Follow this decision tree to maximize coverage with minimum noise.

## Enumeration Priority Order

Execute in this order. Each phase feeds the next — skip nothing.

### Phase 1: Domain Context (first 2-3 steps)

Establish the AD landscape before enumerating objects.

| Task | Tool | Command Pattern |
|---|---|---|
| Identify domain controllers | netexec SMB scan + identify DCs | `netexec_smb` across target range |
| Domain/forest trust relationships | netexec LDAP `--trusted-for-delegation` or SharpView `get_domain_trust` | Trust direction determines lateral movement feasibility |
| Password policy | netexec SMB `--pass-pol` | **Must retrieve before any credential spraying** |
| Domain functional level | netexec LDAP or SharpView `get_domain` | Determines available attack techniques |

### Phase 2: User and Group Enumeration

| Task | Tool | Priority Signal |
|---|---|---|
| All domain users | netexec LDAP `--users` or SharpView `get_domain_user` | High-privilege groups, service accounts, descriptions with passwords |
| All domain groups | netexec LDAP `--groups` or SharpView `get_domain_group` | Domain Admins, Enterprise Admins, custom admin groups |
| Group membership (recursive) | SharpView `get_domain_group_member` with recurse | Nested group memberships reveal hidden admin access |
| Kerberoastable accounts (SPNs) | netexec LDAP `--kerberoasting` or SharpView `get_domain_user` with SPN filter | **Immediate attack signal** — queue for Kerberoasting |
| AS-REP roastable accounts | netexec LDAP `--asreproast` or SharpView `get_domain_user` with PreauthNotRequired | **Immediate attack signal** — queue for AS-REP roasting |

### Phase 3: Computer and Service Enumeration

| Task | Tool | Priority Signal |
|---|---|---|
| All domain computers | SharpView `get_domain_computer` | Operating system versions, stale accounts |
| Sessions and logged-on users | SharpView `get_net_session`, `get_net_loggedon` | Where high-value users are logged in |
| Local admin access | SharpView `find_local_admin_access` | Hosts where current creds have admin |
| Shares and sensitive files | netexec SMB `--shares`, SharpView `find_domain_share` | READ/WRITE shares, sensitive file names |

### Phase 4: Delegation and ACL Enumeration

| Task | Tool | Priority Signal |
|---|---|---|
| Unconstrained delegation | SharpView `get_domain_computer` with Unconstrained filter | **High-value attack target** — Kerberos relay |
| Constrained delegation | SharpView `get_domain_computer` or `get_domain_user` with delegation filter | S4U2Proxy exploitation paths |
| RBCD candidates | BloodyAD `bloodyad_get_writable` or SharpView ACL queries | Objects where you can write msDS-AllowedToActOnBehalfOfOtherIdentity |
| Interesting ACLs | SharpView `find_interesting_domain_acl` | GenericAll, WriteDACL, WriteOwner on high-value targets |
| AD CS templates | Certipy `find` | Vulnerable templates (ESC1-ESC8) |

## Priority Signals → Next Action

When enumeration reveals these signals, queue the corresponding action:

| Signal | Next Action |
|---|---|
| User with SPN | Kerberoast → crack → test credential |
| User with PreauthNotRequired | AS-REP roast → crack → test credential |
| Writable object (GenericAll, WriteDACL) | Plan ACL abuse via BloodyAD |
| Unconstrained delegation host | Plan Kerberos relay via Krbrelayx |
| Constrained delegation | Plan S4U exploitation via Impacket |
| AD CS vulnerable template | Plan certificate abuse via Certipy |
| Share with READ access | Access and review for credentials/configs |
| User description containing password hints | Test as credential |
| Stale computer accounts | Potential machine account takeover |

## Tool Selection Guide

| Need | First Choice | Alternative |
|---|---|---|
| Bulk user/group enumeration | netexec LDAP | SharpView (more filters) |
| SMB share enumeration | netexec SMB `--shares` | SharpView `get_net_share` |
| ACL analysis | SharpView `find_interesting_domain_acl` | BloodyAD `bloodyad_get_writable` |
| Trust enumeration | SharpView `get_domain_trust` | netexec LDAP |
| Session enumeration | SharpView `get_net_session` | netexec SMB `--sessions` |
| Kerberoastable discovery | netexec LDAP `--kerberoasting` | SharpView with SPN filter |
| Certificate enumeration | Certipy `find` | — |
| DNS enumeration | BloodyAD `bloodyad_get_dnsdump` | SharpView `get_domain_dns_record` |
