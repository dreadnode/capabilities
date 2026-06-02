## NtDelayExecution

[NtDelayExecution](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtDelayExecution.html) can be used to delay the execution of the calling thread. NtDelayExecution accepts a parameter "DelayInterval", which is the number of milliseconds to delay. Once executed, NtDelayExecution "pauses" execution of the calling program whuch can cause a timeout of the sandbox or loss of control in a debugger.

Additionally, some higher level WinAPI functions invoke NtDelayExeuction. For example, the WinAPI function [Beep](https://learn.microsoft.com/en-us/windows/win32/api/utilapiset/nf-utilapiset-beep), which plays an audible tone for a specified number of milliseconds, calls into NtDelayExecution. In this manner, malware can invoke the Beep function to similarly cause a delay in the program execution.

* * *

##### Technique Identifiers

[U1344](https://unprotect.it/search/?keyword=U1344) [U0133](https://unprotect.it/search/?keyword=U0133)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [NtDelayExecution](https://unprotect.it/featured-api/ntdelayexecution/)

##### Evasion Categories

[![Sandbox Evasion icon](https://unprotect.it/media/2024/04/08/icons8-leak.svg)**Sandbox Evasion**](https://unprotect.it/techniques/?pre_select=sandbox-evasion)

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Contributor

- [Kyle Cucci (d4rksystem)](https://unprotect.it/users/public/profile/d4rksystem/)

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtDelayExecution.html)
- [https://securityliterate.com/beeeeeeeeep-how-malware-uses-the-beep-winapi-function-for-anti-analysis/](https://securityliterate.com/beeeeeeeeep-how-malware-uses-the-beep-winapi-function-for-anti-analysis/)

* * *

##### Created

August 17, 2024


##### Last Revised

March 24, 2026
