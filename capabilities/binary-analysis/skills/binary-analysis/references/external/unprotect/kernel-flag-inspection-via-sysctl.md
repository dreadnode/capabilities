## kernel flag inspection via sysctl

The `sysctl` anti-debugging technique can be abused by malware to detect and evade debugging tools on macOS or BSD-like systems. By querying the kernel for process information, malware checks flags (e.g., `0x800`) to see if a debugger is attached. If detected, the malware can terminate, alter behavior, or enter a dormant state to avoid analysis.

This technique blends with legitimate system calls, it makes detection harder, and allow to bypass sandboxes analysis. BANSHEE Stealer (`11aa6eeca2547fcf807129787bec0d576de1a29b56945c5a8fb16ed8bf68f782`) uses this method to evade reverse-engineering and maintain stealth.

* * *

##### Technique Identifier

[U0135](https://unprotect.it/search/?keyword=U0135)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://www.elastic.co/security-labs/beyond-the-wail](https://www.elastic.co/security-labs/beyond-the-wail)

* * *

##### Created

January 11, 2025


##### Last Revised

March 24, 2026
