## NtSetDebugFilterState

The `NtSetDebugFilterState` and `DbgSetDebugFilterState` functions are used by malware to detect the presence of a kernel mode debugger. These functions allow the malware to set up a debug filter, which is a mechanism that can be used to detect and respond to the presence of a debugger.

When a kernel mode debugger is present, the debug filter will be triggered, and the malware can then take actions to evade detection and continue to operate. This technique is commonly used by malware to avoid analysis by security researchers and avoid being detected by security software. By using these functions, the malware can operate stealthily and evade detection, making it difficult for analysts to reverse engineer the malware and understand its capabilities and behaviors.

* * *

##### Technique Identifier

[U0103](https://unprotect.it/search/?keyword=U0103)

##### Technique Tags

[NtSetDebugFilterState](https://unprotect.it/search/?keyword=NtSetDebugFilterState) [DbgSetDebugFilterState](https://unprotect.it/search/?keyword=%20DbgSetDebugFilterState) [Kernel mode debugger detection](https://unprotect.it/search/?keyword=%20Kernel%20mode%20debugger%20detection) [Debug filter](https://unprotect.it/search/?keyword=%20Debug%20filter)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [GetProcAddress](https://unprotect.it/featured-api/getprocaddress/)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### Attachments

By downloading or using the attached resources, you are agreeing to be bound by the [terms and conditions](https://unprotect.it/page/terms-and-conditions/) outlined by the provider of the
resources. It is important to review and understand these terms before proceeding with the download or use of
the files. If you do not agree to the terms, or are unable to agree to them, please do not download or use the
attached resources.


Additionally, it's important to be aware of the potential risks that come with downloading resources from
unknown sources, as they may contain malware or other malicious content. It's highly recommended to scan the
resources with an up-to-date antivirus software before opening or using them.


Please note that even if you take the necessary precautions to check the resources, it is not possible to
guarantee that they are completely safe and risk-free. Use of the attached resources is at your own risk.


- [NtSetDebugFilterState.pdf (NtSetDebugFilterState as Anti-Debug) - 437.7 kB](https://unprotect.it/media/archive/2022/06/22/NtSetDebugFilterState.pdf)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [al-khaser.exe](https://unprotect.it/scan/result/a832424e-8914-40db-8f14-6b7ce65878f2/) | 24 | 2024-11-13 | 1 year, 5 months ago |

[View All](https://unprotect.it/scan/samples/technique/ntsetdebugfilterstate/)

* * *

##### Created

March 23, 2019


##### Last Revised

March 24, 2026
