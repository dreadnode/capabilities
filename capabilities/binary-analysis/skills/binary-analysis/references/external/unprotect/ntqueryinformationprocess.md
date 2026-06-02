## NtQueryInformationProcess

This function retrieves information about a running process. Malware are able to detect if the process is currently being attached to a debugger using the `ProcessDebugPort (0x7)` information class.

A nonzero value returned by the call indicates that the process is being debugged.

* * *

##### Technique Identifiers

[U0120](https://unprotect.it/search/?keyword=U0120) [B0001.012](https://unprotect.it/search/?keyword=B0001.012)

##### Technique Tag

[NtQueryInformationProcess](https://unprotect.it/search/?keyword=NtQueryInformationProcess)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [NtQueryInformationProcess function (winternl.h) - Win32 apps \| Microsoft Docs](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684280(v=vs.85).aspx)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [rootkit.exe](https://unprotect.it/scan/result/4460c351-4e54-4f47-8add-c2f6afd0ae46/) | 10 | 2026-03-24 | 1 month, 2 weeks ago |
| [main.exe](https://unprotect.it/scan/result/91c3f91e-6c8c-4845-984d-2a2b7ecdbd03/) | 11 | 2026-02-07 | 3 months ago |
| [main.exe](https://unprotect.it/scan/result/34ef3948-9a0b-4b36-93a1-bcd5af095ec5/) | 7 | 2026-02-03 | 3 months, 1 week ago |
| [cmd.exe](https://unprotect.it/scan/result/885753fc-4410-4304-8dbc-ca4a8eb1e0d9/) | 7 | 2025-12-10 | 5 months ago |
| [MSBuild.exe](https://unprotect.it/scan/result/bf0a0778-6ab0-49fb-b1f7-9d37090fb89f/) | 10 | 2024-11-15 | 11 months ago |
| [RuntimeBroker.exe](https://unprotect.it/scan/result/435aaac0-62ba-40d3-8c53-9702da1c31c2/) | 11 | 2025-06-05 | 11 months, 1 week ago |
| [TCS30Autoplay\_Net.exe](https://unprotect.it/scan/result/05f0dfd9-09f5-49f8-b064-134ea80a250f/) | 6 | 2025-04-25 | 1 year ago |
| [RustPatchlessCLRLoader.exe](https://unprotect.it/scan/result/ef3e8a52-3555-46e5-baf7-2455ac14b0f1/) | 8 | 2025-03-07 | 1 year, 2 months ago |
| [EternelSuspention.exe](https://unprotect.it/scan/result/7137d9a9-4458-4f45-a595-a364d79df76a/) | 8 | 2024-12-05 | 1 year, 5 months ago |
| [1445a6fae415ff8b97807309ed6d...29636ba6a100dbcf3e3e04924790](https://unprotect.it/scan/result/fd2024a0-4a25-42b5-8304-8a0cde6498a0/) | 7 | 2024-11-19 | 1 year, 5 months ago |

[View All](https://unprotect.it/scan/samples/technique/ntqueryinformationprocess/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
