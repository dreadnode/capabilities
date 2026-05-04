---
name: credential-theft-hunt
description: Recover credentials and detect credential-theft tradecraft from a memory image — SAM hashes, LSA secrets, cached domain credentials, Kerberos tickets, LSASS access, Mimikatz/Dumpert/NanoDump artifacts.
---

# Credential Theft Hunt

Maps to [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/) (OS Credential Dumping). Cite the relevant sub-technique in findings: T1003.001 LSASS Memory, .002 Security Account Manager, .003 NTDS, .004 LSA Secrets, .005 Cached Domain Credentials, .006 DCSync.

## When to Use
- Post-breach scoping: did the attacker grab creds from this box?
- Confirming lateral-movement hypotheses (were these creds harvestable here?)
- IR wants a seed set for resets (who was logged on + what's extractable)

## The Big Four Credential Stores

| Store | What's in it | Tool |
|---|---|---|
| SAM | Local account NT hashes | `volatility_hashdump` |
| LSA secrets | Service account passwords (cleartext after decrypt), DPAPI masterkey seeds | `volatility_run_plugin windows.lsadump.Lsadump` |
| MSCache (DCC2) | Last N domain logons, hashed | `volatility_run_plugin windows.cachedump.Cachedump` |
| LSASS memory | Live tickets, plaintext, NTLM, TGT/TGS | Dump + offline tooling |

## Procedure

### 1. Extract what's free
Run all three in parallel:
- `volatility_hashdump`
- `volatility_run_plugin windows.lsadump.Lsadump`
- `volatility_run_plugin windows.cachedump.Cachedump`

Note: Vol3's hashdump/lsadump/cachedump are Windows-only and require SYSTEM+SECURITY hives in memory (they normally are).

### 2. Look for *who* was logged on
`volatility_run_plugin windows.getsids.GetSIDs` — SIDs attached to each process reveal the user context. Cross-reference with:
- `volatility_processes` for `explorer.exe`, `winlogon.exe`, `lsass.exe` SIDs
- `volatility_run_plugin windows.sessions.Sessions` for interactive sessions

An attacker-spawned `cmd.exe` running as a different user than `explorer.exe` = token impersonation or runas.

### 3. Hunt LSASS access
LSASS dumping is the #1 credential-theft TTP. Look for:

**Process tree around lsass.exe:**
- `volatility_process_tree` — anything parented under `lsass` is abnormal (lsass shouldn't spawn children except very specific telemetry agents)
- Any process with `lsass.exe` as a *target* handle → candidate dumper

**Handle analysis:**
```
volatility_handles(object_types=["Process"])
```
Filter for handles where the target is `lsass.exe` and the granted access mask includes `PROCESS_VM_READ (0x10)` or `PROCESS_QUERY_INFORMATION (0x400)`. The classic dumper grabs `0x1010` or `0x1FFF`.

**Dumping tool signatures in cmdline/filesystem:**
- `procdump.exe -ma lsass.exe`, `-accepteula` flag
- `rundll32.exe comsvcs.dll, MiniDump <PID> <path> full` (living-off-the-land)
- `tasklist /svc`, `sqldumper.exe`, `createdump.exe`, `werfault -u -p <lsass>`
- Silent Process Exit abuse: `ImageFileExecutionOptions\lsass.exe` with `GlobalFlag=0x200` and `SilentProcessExit` subkey

### 4. Mimikatz / NanoDump / Dumpert indicators
`volatility_yara_scan` with rules for:
- `sekurlsa::logonpasswords`, `mimikatz`, `gentilkiwi`
- `NanoDump`, `dumpert`, `ProcessMitigationImageType`
- Known driver names: `mimidrv.sys`, `mimilib.dll`
- Shellcode calling `MiniDumpWriteDump` via `dbghelp!MiniDumpWriteDump` dynamic import

Inline rule starter:
```yara
rule CredTheft_Mimikatz_Strings {
  strings:
    $s1 = "sekurlsa::logonpasswords" ascii wide
    $s2 = "mimikatz" ascii wide
    $s3 = "gentilkiwi" ascii wide
    $s4 = "kerberos::list" ascii wide
    $s5 = "lsadump::sam" ascii wide
  condition:
    2 of them
}
rule CredTheft_LSASS_Dump_Tooling {
  strings:
    $s1 = "MiniDumpWriteDump" ascii wide
    $s2 = "comsvcs.dll" ascii wide
    $s3 = "MiniDump" ascii wide
    $s4 = "lsass.dmp" ascii wide nocase
  condition:
    3 of them
}
```

### 5. Kerberos ticket extraction
If attacker had SYSTEM + Mimikatz-class tooling, tickets are in LSASS. The memory image still holds them until overwritten.

```
volatility_dump_process(image, pid=<lsass_pid>, output_dir="/tmp/lsass-vad", mode="vad")
```
Then offline with `pypykatz` / `mimikatz` against the dumped VAD set. (Don't try to `sekurlsa` in-image — we're dumping for offline analysis.)

### 6. DPAPI masterkeys
- LSA secrets output includes `DPAPI_SYSTEM` — this is the seed to decrypt every user's DPAPI-protected blob (browser creds, Wi-Fi, saved RDP).
- Collect: user masterkey files (`%APPDATA%\Microsoft\Protect\<SID>\*`) — in memory these appear as file handles held by `svchost.exe`/`lsass.exe`.

## Reporting
For every credential recovered: user, source (SAM/LSA/MSCache/LSASS), format (NT/DCC2/cleartext/TGT), and confidence (direct dump vs. inferred). Pair with access timeline (did this user log on during the incident window?).

## Common Pitfalls
- Empty SAM dump on a domain controller is expected — domain creds live in NTDS, not SAM
- `Guest` / `DefaultAccount` hashes are built-in, not interesting
- LSA secrets sometimes includes `NL$KM` — the cache key, not a password
- MSCache hashes are DCC2 (PBKDF2-SHA1, 10240 rounds) — crackable but slow
