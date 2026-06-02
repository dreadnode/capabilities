## CsrGetProcessID

This function is undocumented within `OpenProcess`. It can be used to get the PID of CRSS.exe, which is a `SYSTEM` process. By default, a process has the `SeDebugPrivilege` privilege in their access token disabled.

However, when the process is loaded by a debugger such as OllyDbg or WinDbg, the `SeDebugPrivilege` privilege is enabled. If a process is able to open CRSS.exe process, it means that the process `SeDebugPrivilege` enabled in the access token, and thus, suggesting that the process is being debugged.

If we call `OpenProcess` and pass the ID returned by `CsrGetProcessId`, no error will occur if the `SeDebugPrivilege` has been set with `SetPrivilege` / `AdjustTokenPrivileges`.

* * *

##### Technique Identifier

[U0115](https://unprotect.it/search/?keyword=U0115)

##### Technique Tag

[CsrGetProcessID](https://unprotect.it/search/?keyword=CsrGetProcessID)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [OpenProcess](https://unprotect.it/featured-api/openprocess/)
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


- [https://www.gironsec.com/blog/2013/12/other-antidebug-tricks/](https://www.gironsec.com/blog/2013/12/other-antidebug-tricks/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
