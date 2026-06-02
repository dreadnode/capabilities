## DLL Unhooking

Endpoint Detection and Response (EDR) tools use a technique known as hooking to monitor sensitive system functions within the DLLs of loaded processes. Hooking is a method of live-patching system DLLs, enabling EDRs to intercept the flow of a program and evaluate its legitimacy.

Here's how it works: EDRs modify the first instructions of the functions within the DLLs. When these functions are called, the program's execution flow is diverted to the EDR's code (housed within a DLL loaded by the EDR in the program). In this redirected state, the EDR can inspect the function's arguments to determine whether their usage is legitimate or potentially malicious. If the usage is deemed legitimate, the EDR restores the program's execution flow, allowing the function to proceed as normal.

However, to evade detection by an EDR, malware can employ a method known as "unhooking." This process involves restoring the entire DLL code section (.text) to its original state. To accomplish this, malware needs access to an unmodified (unhooked) DLL, which it can acquire in several ways:

1 - directly from the system, which can potentially be detected via an open handle;

2 - by opening a remote file, which requires the malware author to host a DLL matching the OS version of the target system remotely;

3 - by initiating a suspended process and retrieving the content of its DLL before it gets hooked.

Typically, the DLL most commonly hooked/unhooked is NTDLL.dll, as it is the closest to the kernel. However, some EDRs may also hook APIs contained in higher-level DLLs, such as kernel32.dll or user32.dll.

* * *

##### Technique Identifier

[U0522](https://unprotect.it/search/?keyword=U0522)

##### Evasion Categories

[![Antivirus/EDR Evasion icon](https://unprotect.it/media/2024/04/08/test.svg)**Antivirus/EDR Evasion**](https://unprotect.it/techniques/?pre_select=antivirus-evasion)

### Code Snippets

### Contributor

- [Dreamkinn](https://unprotect.it/users/public/profile/dreamkinn/)

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [GitHub - optiv/Freeze: Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods](https://github.com/optiv/Freeze)
- [https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)

* * *

##### Created

July 3, 2023


##### Last Revised

March 24, 2026
