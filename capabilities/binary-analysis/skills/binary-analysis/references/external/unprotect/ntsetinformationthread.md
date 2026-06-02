## NtSetInformationThread

[NtSetInformationThread](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationthread) can be used to hide threads from debuggers using the `ThreadHideFromDebugger``ThreadInfoClass` (`0x11` / `17`). This is intended to be used by an external process, but any thread can use it on itself.

After the thread is hidden from the debugger, it will continue running but the debugger won’t receive events related to this thread. This thread can perform anti-debugging checks such as code checksum, debug flags verification, etc.

* * *

##### Technique Identifiers

[U0119](https://unprotect.it/search/?keyword=U0119) [B0001.014](https://unprotect.it/search/?keyword=%20B0001.014)

##### Technique Tag

[NtSetInformationThread](https://unprotect.it/search/?keyword=NtSetInformationThread)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [IsDebuggerPresent](https://unprotect.it/featured-api/isdebuggerpresent/)
- [ResumeThread](https://unprotect.it/featured-api/resumethread/)
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


- [ZwSetInformationThread function (ntddk.h) - Windows drivers \| Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntddk/nf-ntddk-zwsetinformationthread)
- [Anti-Debug NtSetInformationThread \| ntquery](https://ntquery.wordpress.com/2014/03/29/anti-debug-ntsetinformationthread/)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [al-khaser.exe](https://unprotect.it/scan/result/a832424e-8914-40db-8f14-6b7ce65878f2/) | 24 | 2024-11-13 | 1 year, 5 months ago |

[View All](https://unprotect.it/scan/samples/technique/ntsetinformationthread/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
