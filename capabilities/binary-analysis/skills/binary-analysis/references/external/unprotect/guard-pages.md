## Guard Pages

Memory breakpoints are a technique used by malware to detect if a debugger is present. This technique involves setting up a "guard page" in memory, which is a page of memory that is protected by the operating system and cannot be accessed by normal code. If a debugger is present, the malware can use this guard page to detect its presence.

This technique works by putting a return address onto the stack, then accessing the guard page. If the operating system detects that the guard page has been accessed, it will raise a STATUS\_GUARD\_PAGE\_VIOLATION exception. The malware can then check for this exception, and if it is present, it can assume that no debugging is taking place. This allows the malware to evade detection and continue to operate without being interrupted by a debugger.

* * *

##### Technique Identifiers

[U0102](https://unprotect.it/search/?keyword=U0102) [B0006.006](https://unprotect.it/search/?keyword=%20B0006.006)

##### Technique Tags

[Memory breakpoints](https://unprotect.it/search/?keyword=Memory%20breakpoints) [Guard pages](https://unprotect.it/search/?keyword=%20Guard%20pages) [Debugger detection](https://unprotect.it/search/?keyword=%20Debugger%20detection) [STATUS\_GUARD\_PAGE\_VIOLATION](https://unprotect.it/search/?keyword=%20STATUS_GUARD_PAGE_VIOLATION)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [VirtualAlloc](https://unprotect.it/featured-api/virtualalloc/)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [Anti-debugging Techniques Cheat Sheet - 0xAA - Random notes on security](http://antukh.com/blog/2015/01/19/malware-techniques-cheat-sheet/)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [hid-tools.dll](https://unprotect.it/scan/result/a987f6e2-e083-4242-a0ad-c7b715993cbd/) | 13 | 2025-09-22 | 7 months, 2 weeks ago |
| [FBH.dll](https://unprotect.it/scan/result/9a8bb157-bfdc-4135-8f42-a6884f5f95f1/) | 10 | 2025-03-22 | 1 year, 1 month ago |
| [kernel32.dll](https://unprotect.it/scan/result/227bc4d9-9923-4756-9ea4-08f647a6ce26/) | 13 | 2024-12-30 | 1 year, 4 months ago |
| [br1.dll](https://unprotect.it/scan/result/19a1cfcb-2235-4553-83c1-ebc0e1f7ff08/) | 10 | 2024-12-03 | 1 year, 5 months ago |
| [396845aea1f1be292df345ea0a27...e8a89ce9487aea9996771dd7b48c](https://unprotect.it/scan/result/a2b38af0-d7a5-41b4-bab1-d1cfe86484b8/) | 6 | 2024-11-19 | 1 year, 5 months ago |
| [23b1971659b16e186f9e1b36d8bc...e512b346e78f77dc314503aac59a](https://unprotect.it/scan/result/5d7a5260-3bc1-4023-8a56-477be1fb7b44/) | 13 | 2024-11-19 | 1 year, 5 months ago |
| [al-khaser.exe](https://unprotect.it/scan/result/a832424e-8914-40db-8f14-6b7ce65878f2/) | 24 | 2024-11-13 | 1 year, 5 months ago |
| [wdext.exe](https://unprotect.it/scan/result/4314758d-ee9c-4068-b74b-f3492347cc73/) | 10 | 2024-11-13 | 1 year, 5 months ago |

[View All](https://unprotect.it/scan/samples/technique/guard-pages/)

* * *

##### Created

March 23, 2019


##### Last Revised

March 24, 2026
