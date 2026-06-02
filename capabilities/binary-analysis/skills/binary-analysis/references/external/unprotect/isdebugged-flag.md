## IsDebugged Flag

While a process is running, the location of the PEB can be referenced by the location `fs:[30h]`. For anti-debugging, malware will use that location to check the `BeingDebugged` flag, which indicates whether the specified process is being debugged.

* * *

##### Technique Identifiers

[U0113](https://unprotect.it/search/?keyword=U0113) [B0001.019](https://unprotect.it/search/?keyword=B0001.019)

##### Technique Tag

[NtQueryInformationProcess](https://unprotect.it/search/?keyword=NtQueryInformationProcess)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [WriteProcessMemory](https://unprotect.it/featured-api/writeprocessmemory/)
- [OpenProcess](https://unprotect.it/featured-api/openprocess/)
- [ReadProcessMemory](https://unprotect.it/featured-api/readprocessmemory/)
- [GetProcAddress](https://unprotect.it/featured-api/getprocaddress/)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
