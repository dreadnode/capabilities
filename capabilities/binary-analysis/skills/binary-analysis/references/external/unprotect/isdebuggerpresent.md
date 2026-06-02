## IsDebuggerPresent

This function checks specific flag in the Process Environment Block (PEB) for the field IsDebugged which will return zero if the process is not running into a debugger or a nonzero if a debugger is attached.

If you want to understand the underlying process of [IsDebuggerPresent](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent) API you can check the code snippet section for the following method: [IsDebugged Flag](https://search.unprotect.it/map/anti-debugging/isdebugged-flag/).

* * *

##### Technique Identifiers

[U0122](https://unprotect.it/search/?keyword=U0122) [B0001.008](https://unprotect.it/search/?keyword=%20B0001.008)

##### Technique Tag

[isdebuggerpresent](https://unprotect.it/search/?keyword=isdebuggerpresent)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [IsDebuggerPresent](https://unprotect.it/featured-api/isdebuggerpresent/)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [IsDebuggerPresent function (debugapi.h) - Win32 apps \| Microsoft Docs](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680345(v=vs.85).aspx)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
