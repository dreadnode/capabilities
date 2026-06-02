## Debug Registers, Hardware Breakpoints

Hardware breakpoints allow a debugger to pause execution at specific memory addresses without modifying the program code. They are stored in special CPU registers (DR0 through DR3 on Intel CPUs).

For anti-debugging, malware can inspect the values of these debug registers. If any of the registers contain a non-empty value, it indicates that a hardware breakpoint has been set by a debugger.

A common way to capture this information is by calling RtlCaptureContext(), which retrieves the current thread’s execution context, including the debug registers. The malware can then check DR0–DR3. If one of them is populated, it signals the presence of an active debugger using hardware breakpoints.

* * *

##### Technique Identifiers

[U0127](https://unprotect.it/search/?keyword=U0127) [B0001.005](https://unprotect.it/search/?keyword=%20B0001.005)

##### Technique Tag

[DR0](https://unprotect.it/search/?keyword=DR0)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [GetCurrentThread function (processthreadsapi.h) - Win32 apps \| Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread)
- [GetThreadContext function (processthreadsapi.h) - Win32 apps \| Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
- [Viewing and Editing Registers in WinDbg - Windows drivers \| Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/registers-window)
- [The Unbreakable Multi-Layer Anti-Debugging System - SANS ISC](https://isc.sans.edu/diary/31658)

* * *

##### Created

November 13, 2020


##### Last Revised

March 24, 2026
