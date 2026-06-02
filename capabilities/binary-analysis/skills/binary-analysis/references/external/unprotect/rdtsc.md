## RDTSC

The Read-Time-Stamp-Counter (RDTSC) instruction can be used by malware to determine how quicky the processor executes the program's instructions. It returns the count of the number of ticks since the last system reboot as a 64-bit value placed into `EDX:EAX`.

It will execute RDTSC twice and then calculate the difference between low order values and check it with CMP condition. If the difference lays below `0FFFh` no debugger is found if it is above or equal, then application is debugged.

* * *

##### Technique Identifier

[U0126](https://unprotect.it/search/?keyword=U0126)

##### Technique Tag

[RDTSC](https://unprotect.it/search/?keyword=RDTSC)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [An Anti-Reverse Engineering Guide - CodeProject](https://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide)
- [https://www.aldeid.com/wiki/RDTSC-Read-Time-Stamp-Counter](https://www.aldeid.com/wiki/RDTSC-Read-Time-Stamp-Counter)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [Raid.exe](https://unprotect.it/scan/result/ccc43bf1-6c6d-493a-ab41-f95e20317464/) | 7 | 2026-04-08 | 1 month ago |
| [2\_5339247083163523934.exe](https://unprotect.it/scan/result/2bca9d18-9dbb-4db8-b263-d3bd5aa7dea9/) | 6 | 2026-03-27 | 1 month, 1 week ago |
| [rootkit.exe](https://unprotect.it/scan/result/4460c351-4e54-4f47-8add-c2f6afd0ae46/) | 10 | 2026-03-24 | 1 month, 2 weeks ago |
| [ngen.exe](https://unprotect.it/scan/result/5e500691-8021-418b-8272-a56f5bedeb76/) | 7 | 2026-03-20 | 1 month, 3 weeks ago |
| [loader.exe](https://unprotect.it/scan/result/a9149d24-aa48-4f31-b951-b92a44db6476/) | 5 | 2026-03-14 | 1 month, 3 weeks ago |
| [BBHloader.exe](https://unprotect.it/scan/result/b8d3ea9d-43bc-4830-ae12-ca4e065986ce/) | 6 | 2026-03-10 | 2 months ago |
| [library.dll](https://unprotect.it/scan/result/ee4e0d1e-60c3-45f7-962b-510dcb391663/) | 8 | 2026-03-06 | 2 months ago |
| [DelphinDesktop.dll](https://unprotect.it/scan/result/dcbb961f-0b54-4803-a721-42eee0fdb029/) | 8 | 2026-03-05 | 2 months ago |
| [um.exe](https://unprotect.it/scan/result/d64c0d5b-6a9b-4a4a-a1a1-e067435f6338/) | 7 | 2026-03-02 | 2 months, 1 week ago |
| [Malware.unknown.exe.malz](https://unprotect.it/scan/result/68ee2243-c13a-462c-8474-ad23e2b52c2a/) | 8 | 2026-02-22 | 2 months, 2 weeks ago |

[View All](https://unprotect.it/scan/samples/technique/rdtsc/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
