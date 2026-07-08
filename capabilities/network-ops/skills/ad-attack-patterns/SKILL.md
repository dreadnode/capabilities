---
name: ad-attack-patterns
description: "Common Active Directory attack chains with tool mappings. Covers Kerberoasting, AS-REP roasting, RBCD, AD CS, DCSync, relay attacks, and credential reuse patterns. Use during exploitation and privilege escalation phases."
---

# AD Attack Patterns

Reference for common AD attack chains. Each pattern lists prerequisites, tool sequence, and success criteria.

## Attack Chains

### Kerberoasting

**Prerequisites:** Valid domain credentials (any privilege level), target user with SPN.

| Step | Tool | Action |
|---|---|---|
| 1. Identify targets | netexec LDAP `--kerberoasting` | Find users with SPNs |
| 2. Request tickets | Impacket `GetUserSPNs.py` | Extract TGS tickets |
| 3. Crack tickets | Hashcat mode 13100 or John `krb5tgs` | Recover plaintext password |
| 4. Verify credential | netexec SMB auth check | Confirm password works, check admin |

**Success:** "Pwn3d!" in netexec output or successful auth.

### AS-REP Roasting

**Prerequisites:** List of usernames OR valid domain creds. Target users with "Do not require Kerberos preauthentication."

| Step | Tool | Action |
|---|---|---|
| 1. Identify targets | netexec LDAP `--asreproast` | Find users without preauth |
| 2. Request AS-REP | Impacket `GetNPUsers.py` | Extract AS-REP hashes |
| 3. Crack hashes | Hashcat mode 18200 or John `krb5asrep` | Recover plaintext password |
| 4. Verify credential | netexec SMB auth check | Confirm and assess access |

### RBCD (Resource-Based Constrained Delegation)

**Prerequisites:** Write access to target's `msDS-AllowedToActOnBehalfOfOtherIdentity`, ability to create or control a computer account.

| Step | Tool | Action |
|---|---|---|
| 1. Identify writable targets | BloodyAD `bloodyad_get_writable` or SharpView ACL | Find objects with write access |
| 2. Create computer account | BloodyAD `add_computer` | Create attacker-controlled machine account |
| 3. Configure RBCD | BloodyAD `add_rbcd` | Set delegation from new computer to target |
| 4. Request ticket via S4U | Impacket `getST.py` (S4U2Self + S4U2Proxy) | Get service ticket impersonating admin |
| 5. Use ticket | Impacket with `-k` flag | Access target as impersonated user |

**Cleanup:** Remove RBCD config with BloodyAD `remove_rbcd`, delete computer account.

### AD CS Exploitation (ESC1-ESC8)

**Prerequisites:** Valid domain credentials, vulnerable certificate template.

| Step | Tool | Action |
|---|---|---|
| 1. Find vulnerable templates | Certipy `find` with `-vulnerable` | Identify ESC* vulnerabilities |
| 2. Request certificate | Certipy `req` with template name | Request cert as target user (ESC1) or current user |
| 3. Authenticate with cert | Certipy `auth` with PFX | Obtain NT hash or TGT |
| 4. Use recovered credential | Impacket or netexec with hash | Access systems with recovered identity |

**Common ESC variants:**
- **ESC1:** Template allows requestor to specify SAN (subject alternative name)
- **ESC2:** Template allows any purpose EKU
- **ESC3:** Certificate agent template abuse
- **ESC4:** Writable template — modify to create ESC1 condition
- **ESC8:** NTLM relay to AD CS HTTP enrollment endpoint

### DCSync

**Prerequisites:** Account with Replicating Directory Changes + Replicating Directory Changes All (typically Domain Admin, or granted via ACL abuse).

| Step | Tool | Action |
|---|---|---|
| 1. Verify replication rights | BloodyAD or SharpView ACL check | Confirm DCSync rights on domain object |
| 2. Dump credentials | Impacket `secretsdump.py` with `-just-dc` | Extract all domain hashes via DRSUAPI |
| 3. Crack priority hashes | Hashcat mode 1000 (NTLM) | Focus on admin accounts first |
| 4. Verify recovered creds | netexec auth checks | Confirm access with recovered hashes |

### Kerberos Relay (Unconstrained Delegation)

**Prerequisites:** Compromise of host with unconstrained delegation, ability to coerce authentication.

| Step | Tool | Action |
|---|---|---|
| 1. Identify delegation hosts | SharpView `get_domain_computer` Unconstrained | Find unconstrained delegation computers |
| 2. Setup relay listener | Krbrelayx `krbrelayx_relay` | Listen for incoming Kerberos auth |
| 3. Coerce authentication | Krbrelayx `krbrelayx_printer_bug` | Trigger SpoolService on DC |
| 4. Capture TGT | Krbrelayx captures delegated ticket | Obtain DC machine account TGT |
| 5. Use TGT for DCSync | Impacket with Kerberos auth | DCSync with captured DC ticket |

### Credential Spraying

**Prerequisites:** User list, knowledge of password policy (lockout threshold).

| Step | Tool | Action |
|---|---|---|
| 1. Get password policy | netexec SMB `--pass-pol` | **Mandatory** — know lockout threshold |
| 2. Spray one password | netexec SMB with user list + single password | Stay under lockout threshold |
| 3. Check results | Look for `[+]` successful auth | Identify valid credentials |
| 4. Verify access level | netexec with valid creds | Check for admin access ("Pwn3d!") |

**Critical:** Never spray more passwords than (lockout_threshold - 2) within the observation window.

## Lateral Movement

After recovering credentials with admin access (`Pwn3d!` confirmed), use remote execution to move through the network. Choose the method based on detection profile and what's available on the target.

### Execution Method Selection

| Method | Tool | Detection Profile | When to Use |
|---|---|---|---|
| WMI | `impacket_wmiexec` | Low — no disk write, no service | **Default choice.** Prefer unless WMI is blocked. |
| DCOM | `impacket_dcomexec` | Low-Medium — depends on object | When WMI is filtered. Try `MMC20` first, then `ShellWindows`. |
| SMBExec | `impacket_smbexec` | Medium — service creation, no binary | When WMI/DCOM blocked but SMB services work. |
| Task Scheduler | `impacket_atexec` | Medium — scheduled task creation | When SMB services and WMI both blocked. |
| PsExec | `impacket_psexec` | High — binary upload + service | Last resort. Reliable but noisy — AV may flag the uploaded binary. |

### Lateral Movement Workflow

| Step | Tool | Action |
|---|---|---|
| 1. Confirm admin access | `netexec_smb_auth` | Verify `(Pwn3d!)` on target host |
| 2. Execute command | `impacket_wmiexec` | Run `whoami` to confirm execution context |
| 3. Gather local info | `impacket_wmiexec` | Run `ipconfig /all`, `net localgroup administrators` |
| 4. Dump credentials | `impacket_secretsdump` | Extract SAM/LSA from the new host |
| 5. Repeat | — | Test new credentials against additional hosts |

## Credential Reuse Patterns

When a credential is recovered, test it systematically:

| Test | Tool | Purpose |
|---|---|---|
| SMB auth all DCs | netexec SMB with target list | Check admin access across DCs |
| SMB auth all servers | netexec SMB with server list | Find additional admin access |
| WinRM access | netexec WinRM | Check for remote execution capability |
| LDAP auth | netexec LDAP | Verify domain validity |
| RDP access | netexec RDP | Check interactive login |
| Share access | smbclient with new creds | Review newly accessible shares |

## Tool Selection for Attack Steps

| Attack Step | Primary Tool | When to Use Alternative |
|---|---|---|
| Hash extraction (AS-REP/TGS) | Impacket | netexec for integrated enumeration+attack |
| Hash cracking | Hashcat | John when hashcat unavailable or GPU issues |
| Credential verification | netexec SMB | netexec LDAP/WinRM for protocol-specific checks |
| ACL manipulation | BloodyAD | Impacket for DACL-specific operations |
| Certificate ops | Certipy | — |
| Delegation abuse | Impacket (S4U) | Krbrelayx for unconstrained delegation relay |
| Credential dump | Impacket secretsdump | — |
| Remote execution | `impacket_wmiexec` | `impacket_smbexec` → `impacket_atexec` → `impacket_dcomexec` → `impacket_psexec` (escalating detection) |
| SPN manipulation | Krbrelayx addspn | BloodyAD for LDAP-based SPN changes |
