## Detecting Virtual Environment Artefacts

Malware often checks for artifacts left by virtualization platforms to determine if it is running inside a virtual environment. Detecting such artifacts allows the malware to adapt its behavior, delay execution, or avoid exposing malicious functionality during analysis.

- QEMU: QEMU registers artifacts in the Windows registry. For example, the key `HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0` contains the value `Identifier` with data `QEMU`. Another check is the key `HARDWARE\Description\System` with the value `SystemBiosVersion` and data `QEMU`.

- VirtualBox: The VirtualBox Guest Additions leave multiple registry artifacts. Searching the registry for the string `VBOX` often reveals keys that expose the presence of VirtualBox.

- VMware (Registry & Files): VMware installs tools in `C:\Program Files\VMware\VMware Tools`, and related registry entries may also contain information about the virtual hard drive, network adapters, or virtual mouse. Searching the registry for `VMware` can reveal these indicators.

- VMware (Memory): VMware also leaves artifacts in memory. Critical processor structures may be moved or altered inside a VM, leaving recognizable footprints. Malware can scan physical memory for strings such as `VMware` to confirm that it is running in a virtualized environment.


* * *

##### Technique Identifier

[U1332](https://unprotect.it/search/?keyword=U1332)

##### Evasion Categories

[![Sandbox Evasion icon](https://unprotect.it/media/2024/04/08/icons8-leak.svg)**Sandbox Evasion**](https://unprotect.it/techniques/?pre_select=sandbox-evasion)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [Sandbox Evasion Cheat Sheet](https://www.slideshare.net/ThomasRoccia/sandbox-evasion-cheat-sheet)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [TR\_ Latest ICV Requirement.eml](https://unprotect.it/scan/result/a4752b23-3d58-4514-9cca-6b19848812a7/) | 3 | 2026-05-12 | 8 hours, 34 minutes ago |
| [SKY2027.exe](https://unprotect.it/scan/result/ad86d80c-5acb-4092-a1fa-7466d85ada28/) | 4 | 2026-04-30 | 1 week, 5 days ago |
| [AutoNest.exe](https://unprotect.it/scan/result/4f1cdc81-4e8f-441f-b9e0-6034837a9436/) | 2 | 2026-04-20 | 3 weeks, 1 day ago |
| [superman.exe](https://unprotect.it/scan/result/1b8507da-695c-40eb-b1da-9824accdc6a0/) | 6 | 2026-04-20 | 3 weeks, 1 day ago |
| [USBWatcher.exe](https://unprotect.it/scan/result/31f9dc2e-d65b-413c-84fa-4f07ca449de3/) | 7 | 2026-04-18 | 3 weeks, 3 days ago |
| [VehicalLogger.dll](https://unprotect.it/scan/result/b5a83546-06b6-4ac9-9e57-832e073817fc/) | 5 | 2026-04-06 | 1 month ago |
| [Client-built.exe](https://unprotect.it/scan/result/19fe1cc9-8081-4ea6-9e5c-f35afa0a0aeb/) | 5 | 2026-04-02 | 1 month, 1 week ago |
| [agent.exe](https://unprotect.it/scan/result/e9bf733e-44a4-447a-ae6c-a5e535b690f0/) | 7 | 2026-04-01 | 1 month, 1 week ago |
| [FilterKeysSetter.exe](https://unprotect.it/scan/result/30b549fb-3741-415f-9674-5db964303866/) | 5 | 2026-03-28 | 1 month, 2 weeks ago |
| [LEGO Voyagers installer.exe](https://unprotect.it/scan/result/09b6ead7-9c07-4795-9a37-cfe7142f3ab1/) | 4 | 2026-03-25 | 1 month, 2 weeks ago |

[View All](https://unprotect.it/scan/samples/technique/detecting-virtual-environment-artefacts/)

* * *

##### Created

March 11, 2019


##### Last Revised

March 24, 2026
