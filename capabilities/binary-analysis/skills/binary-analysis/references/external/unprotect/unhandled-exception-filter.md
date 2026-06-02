## Unhandled Exception Filter

An application-defined function that passes unhandled exceptions to the debugger, if the process is being debugged. Otherwise, it optionally displays an application error message box and causes the exception handler to be executed.

If an exception occurs and no exception handler is registered, the `UnhandledExceptionFilter` function will be called. It is possible to register a custom unhandled exception filter using the `SetUnhandledExceptionFilter`. But if the program is running under a debugger, the custom filter won’t be called, and the exception will be passed to the debugger.

Therefore, if the unhandled exception filter is registered and the control is passed to it, then the process is not running with a debugger.

* * *

##### Technique Identifiers

[U0108](https://unprotect.it/search/?keyword=U0108) [B0001.030](https://unprotect.it/search/?keyword=%20B0001.030)

##### Technique Tag

[exception](https://unprotect.it/search/?keyword=exception)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [UnhandledExceptionFilter](https://unprotect.it/featured-api/unhandledexceptionfilter/)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [SetUnhandledExceptionFilter Anti Debug Trick \| Evilcodecave's Weblog](https://evilcodecave.wordpress.com/2008/07/24/setunhandledexception-filter-anti-debug-trick/)
- [Anti-Debug: Exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [merged.exe](https://unprotect.it/scan/result/6f35b784-24e3-45b4-8c12-5a70ba0174cf/) | 6 | 2026-04-24 | 2 weeks, 4 days ago |
| [USBWatcher.exe](https://unprotect.it/scan/result/31f9dc2e-d65b-413c-84fa-4f07ca449de3/) | 7 | 2026-04-18 | 3 weeks, 3 days ago |
| [CVE-2026-20817\_PoC.exe](https://unprotect.it/scan/result/04b49dc6-2fba-4a9f-820c-145cdf2ea204/) | 8 | 2026-04-09 | 1 month ago |
| [Raid.exe](https://unprotect.it/scan/result/ccc43bf1-6c6d-493a-ab41-f95e20317464/) | 7 | 2026-04-08 | 1 month ago |
| [rootkit.exe](https://unprotect.it/scan/result/4460c351-4e54-4f47-8add-c2f6afd0ae46/) | 10 | 2026-03-24 | 1 month, 2 weeks ago |
| [spread.exe](https://unprotect.it/scan/result/9536ccb4-d919-4efb-849f-47629cf66487/) | 6 | 2026-03-24 | 1 month, 2 weeks ago |
| [ngen.exe](https://unprotect.it/scan/result/5e500691-8021-418b-8272-a56f5bedeb76/) | 7 | 2026-03-20 | 1 month, 3 weeks ago |
| [write.exe](https://unprotect.it/scan/result/6c15124e-cc01-40bc-9985-7d599c1bd647/) | 5 | 2026-03-20 | 1 month, 3 weeks ago |
| [UnPackMe\_VMProtect\_1.53.exe](https://unprotect.it/scan/result/f0b68c6e-8431-4ed9-bf3f-ea674e592396/) | 7 | 2026-03-19 | 1 month, 3 weeks ago |
| [Malware.unknown.exe.malz](https://unprotect.it/scan/result/68ee2243-c13a-462c-8474-ad23e2b52c2a/) | 8 | 2026-02-22 | 2 months, 2 weeks ago |

[View All](https://unprotect.it/scan/samples/technique/unhandled-exception-filter/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
