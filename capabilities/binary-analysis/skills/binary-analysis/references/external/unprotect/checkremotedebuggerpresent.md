## CheckRemoteDebuggerPresent

CheckRemoteDebuggerPresent is a kernel32.dll function that sets (-1)0xffffffff in the DebuggerPresent parameter if a debugger is present. Internally, it also uses NtQueryInformationProcess with ProcessDebugPort as a ProcessInformationClass parameter.

* * *

##### Technique Identifiers

[U0121](https://unprotect.it/search/?keyword=U0121) [B0001.002](https://unprotect.it/search/?keyword=%20B0001.002)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [CheckRemoteDebuggerPresent function (debugapi.h) - Win32 apps \| Microsoft Docs](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679280(v=vs.85).aspx)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
