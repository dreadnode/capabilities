## INT3 Instruction Scanning

Instruction `INT3` is an interruption which is used as Software breakpoints. These breakpoints are set by modifying the code at the target address, replacing it with a byte value `0xCC` (INT3 / Breakpoint Interrupt).

The exception `EXCEPTION_BREAKPOINT` (0x80000003) is generated, and an exception handler will be raised. Malware identify software breakpoints by scanning for the byte 0xCC in the protector code and/or an API code.

* * *

##### Technique Identifiers

[U0105](https://unprotect.it/search/?keyword=U0105) [B0001.025](https://unprotect.it/search/?keyword=%20B0001.025)

##### Technique Tag

[int3](https://unprotect.it/search/?keyword=int3)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [IsDebuggerPresent](https://unprotect.it/featured-api/isdebuggerpresent/)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://www.blackhat.com/presentations/bh-usa-07/Quist\_and\_Valsmith/Whitepaper/bh-usa-07-quist\_and\_valsmith-WP.pdf](https://www.blackhat.com/presentations/bh-usa-07/Quist_and_Valsmith/Whitepaper/bh-usa-07-quist_and_valsmith-WP.pdf)
- [Anti-Debug: Assembly instructions](https://anti-debug.checkpoint.com/techniques/assembly.html#int3)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [moduledll.dll](https://unprotect.it/scan/result/a0032497-e139-4604-85c4-a141a3ace86c/) | 6 | 2026-04-24 | 2 weeks, 4 days ago |
| [merged.exe](https://unprotect.it/scan/result/6f35b784-24e3-45b4-8c12-5a70ba0174cf/) | 6 | 2026-04-24 | 2 weeks, 4 days ago |
| [USBWatcher.exe](https://unprotect.it/scan/result/31f9dc2e-d65b-413c-84fa-4f07ca449de3/) | 7 | 2026-04-18 | 3 weeks, 3 days ago |
| [CVE-2026-20817\_PoC.exe](https://unprotect.it/scan/result/04b49dc6-2fba-4a9f-820c-145cdf2ea204/) | 8 | 2026-04-09 | 1 month ago |
| [Raid.exe](https://unprotect.it/scan/result/ccc43bf1-6c6d-493a-ab41-f95e20317464/) | 7 | 2026-04-08 | 1 month ago |
| [b2a17fbdf536bd79dba9eb5e4ea3...0fdd7eb07ca6c5bdf73de001.exe](https://unprotect.it/scan/result/68bd4309-1382-413c-a76a-afd6a8e426c7/) | 11 | 2026-04-07 | 1 month ago |
| [XClient1.exe](https://unprotect.it/scan/result/feee611d-0976-4fcc-8269-2e0e2b3a9e1d/) | 4 | 2026-04-04 | 1 month, 1 week ago |
| [2\_5339247083163523934.exe](https://unprotect.it/scan/result/2bca9d18-9dbb-4db8-b263-d3bd5aa7dea9/) | 6 | 2026-03-27 | 1 month, 2 weeks ago |
| [rootkit.exe](https://unprotect.it/scan/result/4460c351-4e54-4f47-8add-c2f6afd0ae46/) | 10 | 2026-03-24 | 1 month, 2 weeks ago |
| [spread.exe](https://unprotect.it/scan/result/9536ccb4-d919-4efb-849f-47629cf66487/) | 6 | 2026-03-24 | 1 month, 2 weeks ago |

[View All](https://unprotect.it/scan/samples/technique/int3-instruction-scanning/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
