## Detecting Running Process: EnumProcess API

Anti-monitoring is a technique used by malware to prevent security professionals from detecting and analyzing it. One way that malware can accomplish this is by using the `EnumProcess` function to search for specific processes, such as ollydbg.exe or wireshark.exe, which are commonly used by security professionals to monitor and analyze running processes on a system.

By detecting these processes and taking evasive action, such as terminating itself or encrypting its own code, malware can prevent security professionals from gaining visibility into its activities and disrupt their efforts to analyze it.

* * *

##### Technique Identifiers

[U0109](https://unprotect.it/search/?keyword=U0109) [U0405](https://unprotect.it/search/?keyword=U0405) [U1306](https://unprotect.it/search/?keyword=U1306)

##### Technique Tags

[EnumProcess function](https://unprotect.it/search/?keyword=EnumProcess%20function) [Ollydbg.exe](https://unprotect.it/search/?keyword=%20Ollydbg.exe) [Wireshark.exe](https://unprotect.it/search/?keyword=%20Wireshark.exe) [Monitoring](https://unprotect.it/search/?keyword=%20Monitoring) [Analysis](https://unprotect.it/search/?keyword=%20Analysis)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [OpenProcess](https://unprotect.it/featured-api/openprocess/)

##### Evasion Categories

[![Sandbox Evasion icon](https://unprotect.it/media/2024/04/08/icons8-leak.svg)**Sandbox Evasion**](https://unprotect.it/techniques/?pre_select=sandbox-evasion)

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

[![Anti-Monitoring icon](https://unprotect.it/media/2024/04/08/icons8-security-cameras.svg)**Anti-Monitoring**](https://unprotect.it/techniques/?pre_select=anti-monitoring)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [Enumerating All Processes - Win32 apps \| Microsoft Docs](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682623(v=vs.85).aspx)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [b2a17fbdf536bd79dba9eb5e4ea3...0fdd7eb07ca6c5bdf73de001.exe](https://unprotect.it/scan/result/68bd4309-1382-413c-a76a-afd6a8e426c7/) | 11 | 2026-04-07 | 1 month ago |
| [Lab01-04.exe](https://unprotect.it/scan/result/7f4d8aa4-fdef-41b9-80d1-716a581ea275/) | 6 | 2025-09-26 | 7 months, 2 weeks ago |
| [botnpwds.exe](https://unprotect.it/scan/result/51f35681-0053-4745-a79d-cc23725b38d1/) | 10 | 2025-09-24 | 7 months, 2 weeks ago |
| [1445a6fae415ff8b97807309ed6d...29636ba6a100dbcf3e3e04924790](https://unprotect.it/scan/result/fd2024a0-4a25-42b5-8304-8a0cde6498a0/) | 7 | 2024-11-19 | 1 year, 5 months ago |
| [0f52170adf871c6983d7aaa2162a...7b5850a294feaa71dcaffcf661a2](https://unprotect.it/scan/result/3b14cf95-12f6-4adb-9338-d46a689e036f/) | 12 | 2024-11-19 | 1 year, 5 months ago |
| [al-khaser.exe](https://unprotect.it/scan/result/a832424e-8914-40db-8f14-6b7ce65878f2/) | 24 | 2024-11-13 | 1 year, 5 months ago |

[View All](https://unprotect.it/scan/samples/technique/detecting-running-process-enumprocess-api/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
