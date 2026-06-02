## CloseHandle, NtClose

When a process is debugged, calling `NtClose` or `CloseHandle` with an invalid handle will generate a `STATUS_INVALID_HANDLE` exception.

The exception can be cached by an exception handler. If the control is passed to the exception handler, it indicates that a debugger is present.

* * *

##### Technique Identifiers

[U0114](https://unprotect.it/search/?keyword=U0114) [B0001.003](https://unprotect.it/search/?keyword=%20B0001.003)

##### Technique Tags

[closehandle](https://unprotect.it/search/?keyword=closehandle) [ntclose](https://unprotect.it/search/?keyword=%20ntclose)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://www.symantec.com/connect/articles/windows-anti-debug-reference](https://www.symantec.com/connect/articles/windows-anti-debug-reference)
- [Anti-Debug: Object Handles](https://anti-debug.checkpoint.com/techniques/object-handles.html#closehandle)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [merged.exe](https://unprotect.it/scan/result/6f35b784-24e3-45b4-8c12-5a70ba0174cf/) | 6 | 2026-04-24 | 2 weeks, 4 days ago |
| [USBWatcher.exe](https://unprotect.it/scan/result/31f9dc2e-d65b-413c-84fa-4f07ca449de3/) | 7 | 2026-04-18 | 3 weeks, 3 days ago |
| [CVE-2026-20817\_PoC.exe](https://unprotect.it/scan/result/04b49dc6-2fba-4a9f-820c-145cdf2ea204/) | 8 | 2026-04-09 | 1 month ago |
| [Raid.exe](https://unprotect.it/scan/result/ccc43bf1-6c6d-493a-ab41-f95e20317464/) | 7 | 2026-04-08 | 1 month ago |
| [b2a17fbdf536bd79dba9eb5e4ea3...0fdd7eb07ca6c5bdf73de001.exe](https://unprotect.it/scan/result/68bd4309-1382-413c-a76a-afd6a8e426c7/) | 11 | 2026-04-07 | 1 month ago |
| [rootkit.exe](https://unprotect.it/scan/result/4460c351-4e54-4f47-8add-c2f6afd0ae46/) | 10 | 2026-03-24 | 1 month, 2 weeks ago |
| [spread.exe](https://unprotect.it/scan/result/9536ccb4-d919-4efb-849f-47629cf66487/) | 6 | 2026-03-24 | 1 month, 2 weeks ago |
| [ngen.exe](https://unprotect.it/scan/result/5e500691-8021-418b-8272-a56f5bedeb76/) | 7 | 2026-03-20 | 1 month, 3 weeks ago |
| [UnPackMe\_VMProtect\_1.53.exe](https://unprotect.it/scan/result/f0b68c6e-8431-4ed9-bf3f-ea674e592396/) | 7 | 2026-03-19 | 1 month, 3 weeks ago |
| [main.exe](https://unprotect.it/scan/result/91c3f91e-6c8c-4845-984d-2a2b7ecdbd03/) | 11 | 2026-02-07 | 3 months ago |

[View All](https://unprotect.it/scan/samples/technique/closehandle-ntclose/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
