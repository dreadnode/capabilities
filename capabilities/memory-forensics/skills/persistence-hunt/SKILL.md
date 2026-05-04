---
name: persistence-hunt
description: Enumerate persistence mechanisms visible in memory — Run keys, services, scheduled tasks, WMI event subscriptions, COM hijacks, image file execution options, AppInit DLLs, and driver-level persistence.
---

# Persistence Hunt

Maps to multiple MITRE ATT&CK techniques. Cite the matching ID in findings:
- [T1547](https://attack.mitre.org/techniques/T1547/) Boot or Logon Autostart Execution (.001 Run keys, .009 Shortcut, .014 Active Setup)
- [T1546](https://attack.mitre.org/techniques/T1546/) Event Triggered Execution (.003 WMI, .015 COM Hijacking, .012 IFEO)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Windows Service
- [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task

## When to Use
- Intrusion confirmed, scoping long-term footholds
- Re-imaging is on the table and you need to know what survives
- Baseline comparison ("is this install point populated the way it should be?")

## Surface Area (ranked by real-world prevalence)

1. **Registry Run / RunOnce** — most common for commodity malware
2. **Services** — most common for targeted / persistent access
3. **Scheduled Tasks** — very common, cheaper than a service
4. **WMI Event Subscriptions** — stealth favorite, survives reboot + most AV scans
5. **COM hijacks** — TreatAs / InprocServer32 on commonly-instantiated CLSIDs
6. **Image File Execution Options (IFEO)** — Debugger key / GlobalFlag SilentProcessExit
7. **AppInit_DLLs / AppCertDLLs** — largely defanged but still seen
8. **Winlogon / Userinit** — Shell, Userinit, Notify
9. **LSA Authentication/Notification Packages** — SSP abuse
10. **Kernel driver** — rootkit territory
11. **PowerShell profile / env var** — rare but trivial to set

## Procedure

### 1. Registry autorun keys
`volatility_registry_hives` to collect hive offsets, then for each key below call `volatility_registry_key --key '<path>' --recurse`:

```
Software\Microsoft\Windows\CurrentVersion\Run
Software\Microsoft\Windows\CurrentVersion\RunOnce
Software\Microsoft\Windows\CurrentVersion\RunOnceEx
Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
Software\Microsoft\Windows NT\CurrentVersion\Winlogon      (Shell, Userinit, Notify, Taskman)
Software\Microsoft\Windows NT\CurrentVersion\Windows       (AppInit_DLLs, LoadAppInit_DLLs, IconServiceLib)
Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
System\CurrentControlSet\Control\Lsa                       (Authentication Packages, Notification Packages, Security Packages)
System\CurrentControlSet\Control\SecurityProviders\WDigest
System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9   (LSP hijack)
```

Run each under both HKLM and HKCU variants. Score entries:
- Paths in `%TEMP%`, `%APPDATA%`, `%PUBLIC%`, `ProgramData\<random>` → high
- `rundll32`, `mshta`, `regsvr32`, `powershell` with base64 → high
- Binary in `System32` with a stale timestamp + unfamiliar name → medium, verify signer

### 2. Services
`volatility_services`. Sort for:
- `Start=Auto` and `ImagePath` in user-writable dirs
- `ImagePath` begins with `"cmd /c"`, `"powershell"`, `"rundll32"`
- `ServiceDll` under `Parameters` pointing outside `System32`
- Unquoted-path-with-spaces services (classic PrivEsc pattern, occasional persistence)
- Services named to mimic legitimate ones (`WinDefender`, `WindowsUpdate`, `svchost-helper`)

### 3. Scheduled Tasks
Vol3's task plugin support is limited — dump the relevant registry path instead:
```
volatility_registry_key --key 'Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' --recurse
```
For every task: check `Actions` (it's a binary blob encoding command/args), `Hash`, `Id`. Attacker-added tasks often have GUID names but human-readable paths under `\Microsoft\Windows\<odd-folder>\`.

For XML artifacts: `volatility_run_plugin windows.dumpfiles.DumpFiles --virtaddr <offset>` against files under `C:\Windows\System32\Tasks\`.

### 4. WMI event subscriptions (the stealth play)
WMI persistence lives in the `OBJECTS.DATA` repository. From memory, scan for the signature triad: `EventFilter`, `EventConsumer`, `FilterToConsumerBinding`.

```
volatility_yara_scan --rules_inline 'rule WMIPersistence {
  strings:
    $a = "__EventFilter" wide
    $b = "CommandLineEventConsumer" wide
    $c = "ActiveScriptEventConsumer" wide
    $d = "__FilterToConsumerBinding" wide
  condition:
    2 of them
}'
```

Findings → pivot to the owning process and dump that region for offline WMI-repo analysis.

### 5. COM hijacks
High-value CLSIDs the attacker commonly TreatAs-hijacks:
- `{BCDE0395-E52F-467C-8E3D-C4579291692E}` (MMDevEnum)
- `{018D5C66-4533-4307-9B53-224DE2ED1FE6}` (OneDrive)
- Shell extensions loaded by every `explorer.exe`

Query user-hive CLSID subkeys:
```
volatility_registry_key --key 'Software\Classes\CLSID' --recurse
```
Flag any `InprocServer32` or `TreatAs` pointing at a user-writable path.

### 6. IFEO & Silent Process Exit
```
volatility_registry_key --key 'Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' --recurse
```
Look for:
- `Debugger` values on frequently-launched processes (`sethc.exe`, `utilman.exe`, `osk.exe`, `narrator.exe`, `magnify.exe` = sticky-keys family; `taskmgr.exe`, `lsass.exe`)
- `GlobalFlag = 0x200` + corresponding `SilentProcessExit` subkey with a `MonitorProcess` value

### 7. Driver-level persistence
- `volatility_run_plugin windows.modules.Modules` — kernel module list
- `volatility_run_plugin windows.driverscan.DriverScan` — pool-tag carve of drivers
- Diff them: drivers in DriverScan but not Modules → unlinked (DKOM / rootkit)
- Drivers loaded from unusual paths (not `System32\drivers`) or with recent timestamps around the intrusion window → investigate

### 8. SSP / Authentication packages (WDigest, custom SSP)
From step 1: `System\CurrentControlSet\Control\Lsa`
- `Security Packages` / `Authentication Packages` — extra entries beyond defaults = SSP injection (e.g., `mimilib`)
- `WDigest\UseLogonCredential = 1` — plaintext creds re-enabled (cred theft prep, not persistence per se, but usually paired)

## Reporting
Group findings by mechanism class and note re-image verdict: "registry Run, user hive → survives only if profile restored", "service → survives re-image only if drop happens during restore", "WMI → survives unless repository rebuilt", "kernel driver → only BIOS flash guaranteed". Defenders need to know the cleanup bar.

## Common Pitfalls
- Legitimate software loads tons of Run keys — baseline against a clean image if possible
- Vendor services often have weird paths; check the signer before flagging
- WMI yara scan will hit benign Microsoft subscriptions; examine the consumer type and command
