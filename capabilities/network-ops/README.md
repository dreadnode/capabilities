# network-ops

A single autonomous agent (`network-ops-agent`) driving a full Active Directory exploitation toolbelt. Point it at an authorized lab network and it runs the kill chain end to end — discovery, enumeration, initial access, privilege escalation, credential harvesting — without stopping to ask. The agent's goal is blunt: compromise every domain it can reach. The Python toolsets are thin wrappers that shell out to the heavy offensive binaries practitioners already use (nmap, NetExec, Impacket, Certipy, bloodyAD, krbrelayx, Hashcat / John, smbclient, SharpView); the agent decides which to fire and when, and logs findings with `report_item` as it goes.

## Setup

The friction here is the toolchain, not the wiring. Each toolset is a wrapper — the actual work happens in external binaries that this capability does **not** install. The manifest ships no `checks:`, so nothing fails closed: a missing binary surfaces as a runtime warning when that toolset initializes, not as a pre-flight error. Stand it up on a host (a Kali box or equivalent pentest image is the path of least resistance) where these are already present:

| Toolset | Needs on PATH / disk | Install |
|---|---|---|
| nmap | `nmap` | distro package |
| netexec | `nxc` | `pipx install netexec` |
| impacket | `secretsdump.py` & friends (auto-discovered on PATH, pip site-packages, or apt examples dir) | `pipx install impacket` |
| certipy | `certipy` (pip) or `certipy-ad` (Kali) — auto-detected | `pip install certipy-ad` |
| bloodyad | `bloodyAD` | `pip install bloodyAD` |
| krbrelayx | scripts under `/opt/krbrelayx/` (override via `script_path`) | `git clone https://github.com/dirkjanm/krbrelayx` |
| cracking | `hashcat` and/or `john`; wordlist at `/usr/share/wordlists/rockyou.txt` | distro packages + rockyou |
| smbclient | `smbclient` | distro `smbclient` package |
| sharpview | `SharpView.exe` (.NET, Windows) or a Mythic C2 / Apollo session for remote execution | drop the binary on PATH |
| reporting | none — logs structured findings into the Dreadnode run | — |

SharpView is the odd one: it's a Windows .NET assembly. Run it locally on a Windows host, or pass an Apollo instance so it executes remotely over Mythic C2. With neither, the rest of the toolbelt still operates.

## What's in the box

Ten toolsets, grouped by where they land in the chain:

**Recon & enumeration**
- **nmap** — host / port / service discovery (quick top-100 sweep or arbitrary nmap args).
- **netexec** (`nxc`) — SMB / LDAP / WinRM / MSSQL / SSH / RDP enumeration and credential spraying across protocols.
- **sharpview** — PowerView-style AD object enumeration (users, groups, ACLs, trusts) via the .NET SharpView port.
- **smbclient** — recursive share listing and file pull with recovered creds.

**Access & escalation**
- **impacket** — the workhorse: AS-REP roasting, Kerberoasting, secretsdump (SAM / NTDS), RBCD / delegation / DACL abuse over the Impacket example scripts.
- **certipy** — AD CS (certificate services) enumeration and template-vulnerability abuse (ESC1-ESC8 class attacks).
- **bloodyad** — LDAP-based privilege escalation: password resets, group-membership edits, DACL writes against the DC.
- **krbrelayx** — Kerberos relay and unconstrained-delegation abuse, SPN add / manipulation.

**Post-exploitation**
- **cracking** — Hashcat and/or John the Ripper for Kerberos and NTLM hashes (time-boxed; defaults to rockyou).
- **reporting** — `report_item` writes structured findings (hosts, DCs, credentials, hashes, shares, weaknesses) into the run as the agent discovers them.

## Usage

Drive it through the agent:

```
>>> @network-ops-agent compromise the lab domain at 10.0.0.0/24
```

It scans, enumerates, roasts and sprays, escalates through whatever AD CS / delegation / DACL paths it finds, dumps and cracks hashes, and reports findings throughout — autonomously, no human in the loop mid-run.

## Before you trust it

- **This is fully active, offensive tooling.** Every toolset touches the target — scanning, authenticating, dumping, relaying, modifying directory objects. There is no passive or read-only mode. Run it **only** against networks you are explicitly authorized to test.
- **The agent is built for a lab.** Its prompt assumes a CTF-style "compromise every domain" objective and a couple of hardcoded out-of-scope accounts (`vagrant`, `ansible`). It will not self-limit beyond that — scope control is the operator's job, enforced by where you point it.
- **It mutates the directory.** bloodyAD, Certipy, and Impacket can reset passwords, alter group membership, write DACLs, and request certificates. These are not reversible by the agent. Expect state change in the target domain.
- **No `checks:` and no tests ship.** Missing binaries degrade silently to runtime warnings per toolset, and there's no test harness over the wrappers — verify your toolchain before a real run.
