# Memory Triage — Methodology Anchors

Canonical playbooks and frameworks the triage skill is built around. Read when grounding a finding in something authoritative (incident reports, courtroom-ready documentation, peer review).

## SANS 6-Step Memory Triage

The de facto first-pass workflow taught in FOR508 and FOR526. Every step in the triage skill maps to one of these:

1. **Identify rogue processes** — pslist + psscan diff, pstree for lineage anomalies.
2. **Analyze process DLLs and handles** — dlllist gap analysis, handle-target review.
3. **Review network artifacts** — netscan/sockstat, foreign endpoints by PID.
4. **Look for code injection** — malfind, VAD permission/content review.
5. **Check for rootkit signs** — driverscan vs modules, SSDT hooks, kernel callbacks.
6. **Acquire process memory of interest** — VAD/PE/memmap dumps for offline analysis.

Reference: [Memory Forensics Cheat Sheet (SANS)](https://www.sans.org/posters/memory-forensics-cheat-sheet/)

## MITRE D3FEND — Defensive technique IDs

Cite these in reports alongside ATT&CK so the defender can route findings into their detection backlog.

- **D3-PA** — Process Analysis (covers pslist/pstree-style techniques)
- **D3-PCSV** — Process Code Segment Verification (malfind territory: detect unbacked executable VADs)
- **D3-PSMD** — Process Self-Modification Detection (RWX flips, JIT-vs-injection disambiguation)
- **D3-EAL** — Endpoint Activity Logging (handles → logged behaviour mapping)

Reference: [D3FEND Process Analysis](https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/)

## MITRE ATT&CK — Offensive techniques most often seen in memory

The triage table verdict column should map to one of these when escalating:

| Technique | What you'll see in memory |
|---|---|
| **T1055** Process Injection (and sub-techniques 001–015) | malfind hits, RWX VADs, hollowed images, APC artefacts |
| **T1003** OS Credential Dumping (.001 LSASS, .002 SAM, .004 LSA, .005 cached, .006 DCSync) | hashdump output, lsass handles, comsvcs cmdlines |
| **T1547** Boot or Logon Autostart Execution (.001 Run keys, .009 Shortcut Modification, .014 Active Setup) | persistence-hunt registry findings |
| **T1546** Event Triggered Execution (.003 WMI, .015 COM Hijack, .012 IFEO) | persistence-hunt WMI/COM/IFEO findings |
| **T1543** Create or Modify System Process (.003 Windows Service) | svcscan findings |
| **T1574** Hijack Execution Flow (.001 DLL Search Order, .002 DLL Side-Loading) | dlllist anomalies |

References:
- [ATT&CK T1055 Process Injection](https://attack.mitre.org/techniques/T1055/)
- [ATT&CK T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [ATT&CK T1547 Boot/Logon Autostart](https://attack.mitre.org/techniques/T1547/)

## Volatility3 specifics

- **Symbol tables** — Vol3 fetches PDBs from the Microsoft symbol server on first plugin run. Set `VOLATILITY_SYMBOL_DIRS` (`-s` flag) for an air-gapped cache; set `--offline` on `volatility_run_plugin` if the host has no network.
- **Plugin discovery** — `volatility_list_plugins` returns the locally-available catalog. Different Vol3 versions ship different plugins — always check before relying on a plugin name.
- **JSON renderer caveats** — `-r json` returns plugin-specific schemas. Field names are stable within a Vol3 minor version but not across; don't hard-code paths into reporting templates.
- **Long-running plugins** — `windows.memmap`, `windows.timeliner`, whole-image `yarascan` can blow MCP timeouts on multi-GB images. Scope by `--pid` first, raise `timeout` only after the small scan has worked.

Reference: [Volatility3 Symbol Tables](https://volatility3.readthedocs.io/en/stable/symbol-tables.html)
