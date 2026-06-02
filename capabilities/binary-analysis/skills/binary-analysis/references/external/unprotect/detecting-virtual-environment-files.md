## Detecting Virtual Environment Files

Some files are created by Virtualbox and VMware on the system.

Malware can check the different folders to find Virtualbox artifacts like VBoxMouse.sys.

Malware can check the different folders to find VMware artifacts like vmmouse.sys, vmhgfs.sys.

### Some Files Example

Below is a list of files that can be detected on virtual machines:

- "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\agent.pyw",
- "C:\\WINDOWS\\system32\\drivers\\vmmouse.sys",
- "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys",
- "C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys",
- "C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys",
- "C:\\WINDOWS\\system32\\drivers\\VBoxSF.sys",
- "C:\\WINDOWS\\system32\\drivers\\VBoxVideo.sys",
- "C:\\WINDOWS\\system32\\vboxdisp.dll",
- "C:\\WINDOWS\\system32\\vboxhook.dll",
- "C:\\WINDOWS\\system32\\vboxmrxnp.dll",
- "C:\\WINDOWS\\system32\\vboxogl.dll",
- "C:\\WINDOWS\\system32\\vboxoglarrayspu.dll",
- "C:\\WINDOWS\\system32\\vboxoglcrutil.dll",
- "C:\\WINDOWS\\system32\\vboxoglerrorspu.dll",
- "C:\\WINDOWS\\system32\\vboxoglfeedbackspu.dll",
- "C:\\WINDOWS\\system32\\vboxoglpassthroughspu.dll",
- "C:\\WINDOWS\\system32\\vboxservice.exe",
- "C:\\WINDOWS\\system32\\vboxtray.exe",
- "C:\\WINDOWS\\system32\\VBoxControl.exe"

* * *

##### Technique Identifier

[U1333](https://unprotect.it/search/?keyword=U1333)

##### Evasion Categories

[![Sandbox Evasion icon](https://unprotect.it/media/2024/04/08/icons8-leak.svg)**Sandbox Evasion**](https://unprotect.it/techniques/?pre_select=sandbox-evasion)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [Stopping Malware With a Fake Virtual Machine \| McAfee Blog](https://securingtomorrow.mcafee.com/mcafee-labs/stopping-malware-fake-virtual-machine/)

* * *

##### Created

March 11, 2019


##### Last Revised

March 24, 2026
