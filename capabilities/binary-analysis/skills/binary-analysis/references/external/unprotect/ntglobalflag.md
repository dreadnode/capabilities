## NtGlobalFlag

The information that the system uses to determine how to create heap structures is stored at an undocumented location in the PEB at offset `0x68`. If the value at this location is `0x70`, we know that we are running in a debugger.

The `NtGlobalFlag` field of the Process Environment Block (0x68 offset on 32-Bit and 0xBC on 64-bit Windows) is 0 by default. Attaching a debugger doesn’t change the value of NtGlobalFlag. However, if the process was created by a debugger, the following flags will be set:

- `FLG_HEAP_ENABLE_TAIL_CHECK` (0x10)
- `FLG_HEAP_ENABLE_FREE_CHECK` (0x20)
- `FLG_HEAP_VALIDATE_PARAMETERS` (0x40)

The presence of a debugger can be detected by checking a combination of those flags.

* * *

##### Technique Identifiers

[U0111](https://unprotect.it/search/?keyword=U0111) [B0001.036](https://unprotect.it/search/?keyword=B0001.036)

##### Technique Tag

[ntglobalflag](https://unprotect.it/search/?keyword=ntglobalflag)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [OpenProcess](https://unprotect.it/featured-api/openprocess/)
- [GetProcAddress](https://unprotect.it/featured-api/getprocaddress/)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://www.aldeid.com/wiki/PEB-Process-Environment-Block/NtGlobalFlag](https://www.aldeid.com/wiki/PEB-Process-Environment-Block/NtGlobalFlag)
- [Anti-Debug: Debug Flags](https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-ntglobalflag)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [al-khaser.exe](https://unprotect.it/scan/result/a832424e-8914-40db-8f14-6b7ce65878f2/) | 24 | 2024-11-13 | 1 year, 5 months ago |

[View All](https://unprotect.it/scan/samples/technique/ntglobalflag/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
