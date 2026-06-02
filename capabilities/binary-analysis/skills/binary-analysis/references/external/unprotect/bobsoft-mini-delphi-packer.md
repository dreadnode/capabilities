## BobSoft Mini Delphi Packer

The Delphi programming language can be an easy way to write applications and programs that leverage Windows API functions. In fact, some actors deliberately include the default libraries as a diversion to hamper static analysis and make the application "look legit" during dynamic analysis.

The packer goes to great lengths to ensure that it is not running in an analysis environment. Normal user activity involves many application windows being rotated or changed over a period of time. The first variant of the packer uses `GetForegroundWindow` API to check for the user activity of changing windows at least three times before it executes further. If it does not see the change of windows, it puts itself into an infinite sleep.

* * *

##### Technique Identifier

[U1428](https://unprotect.it/search/?keyword=U1428)

##### Technique Tags

[delphi](https://unprotect.it/search/?keyword=delphi) [packer](https://unprotect.it/search/?keyword=%20packer)

##### Evasion Categories

[![Packers icon](https://unprotect.it/media/2024/04/08/icons8-compress.svg)**Packers**](https://unprotect.it/techniques/?pre_select=packers)

### Detection Rules

### Contributor

- [Thomas Roccia (fr0gger)](https://unprotect.it/users/public/profile/fr0gger/)

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://www.mandiant.com/resources/increased-use-of-delphi-packer-to-evade-malware-classification](https://www.mandiant.com/resources/increased-use-of-delphi-packer-to-evade-malware-classification)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [superman.exe](https://unprotect.it/scan/result/1b8507da-695c-40eb-b1da-9824accdc6a0/) | 6 | 2026-04-20 | 3 weeks, 1 day ago |
| [Torture.exe](https://unprotect.it/scan/result/87fda2de-7d02-477d-8f47-cf1fbb2b397e/) | 9 | 2025-12-16 | 4 months, 3 weeks ago |
| [efak.exe](https://unprotect.it/scan/result/84d3c549-f369-495e-85cf-13ac23135b6f/) | 6 | 2025-12-13 | 4 months, 4 weeks ago |
| [3KTrangXinhTQ.exe](https://unprotect.it/scan/result/46f13a8f-567c-4a44-9a45-6dc2b35b2569/) | 2 | 2025-12-01 | 5 months, 1 week ago |
| [TORKpro300.exe](https://unprotect.it/scan/result/bd133fc4-531d-4ed5-bf9d-179228dc39b8/) | 3 | 2025-07-08 | 10 months ago |
| [TuAnhPro.exe](https://unprotect.it/scan/result/af37cf5c-e21b-4ce7-a3f2-4ebf52a5dffc/) | 2 | 2025-07-04 | 10 months, 1 week ago |
| [mel.exe.exe](https://unprotect.it/scan/result/dcfba569-9464-4ead-a9ca-1f9b2cc20215/) | 4 | 2025-06-25 | 10 months, 2 weeks ago |
| [DP\_Simple\_Player.exe](https://unprotect.it/scan/result/ea9cba92-ae99-4b41-a467-da5452520482/) | 5 | 2025-05-13 | 11 months, 4 weeks ago |
| [23b1971659b16e186f9e1b36d8bc...e512b346e78f77dc314503aac59a](https://unprotect.it/scan/result/5d7a5260-3bc1-4023-8a56-477be1fb7b44/) | 13 | 2024-11-19 | 1 year, 5 months ago |

[View All](https://unprotect.it/scan/samples/technique/bobsoft-mini-delphi-packer/)

* * *

##### Created

June 21, 2022


##### Last Revised

March 24, 2026
