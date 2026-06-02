## CPUID

The CPUID instruction is a low-level command that allows you to retrieve information about the CPU that is currently running. This instruction, which is executed at the CPU level (using the bytecode 0FA2), is available on all processors that are based on the Pentium architecture or newer.

You can use the CPUID instruction to retrieve various pieces of information about the CPU, such as the brand of the CPU, the operating system, or the presence of a hypervisor. This is done by specifying the "leaf" information you want to retrieve (such as 0 for the brand of the CPU) in the EAX register, and then executing the instruction. The result will be returned in the EBX, EDX, and ECX registers as a string.

For example, when you request leaf information 0, you may see the brand of the CPU or the virtualization technology in use. Some common strings that you may see include "KVMKVMKVM" for KVM, "Microsoft Hv" for Hyper-V, "VMwareVMware" for VMware, and "GenuineIntel" for an Intel CPU.

The information returned by the CPUID instruction can vary depending on the platform and the specific CPU model.

* * *

##### Technique Identifiers

[U1324](https://unprotect.it/search/?keyword=U1324) [B0009.034](https://unprotect.it/search/?keyword=B0009.034)

##### Technique Tags

[CPUID](https://unprotect.it/search/?keyword=CPUID) [instruction](https://unprotect.it/search/?keyword=%20instruction) [CPU level](https://unprotect.it/search/?keyword=%20CPU%20level) [bytecode 0FA2](https://unprotect.it/search/?keyword=%20bytecode%200FA2) [running CPU](https://unprotect.it/search/?keyword=%20running%20CPU) [Pentium](https://unprotect.it/search/?keyword=%20Pentium) [brand of the CPU](https://unprotect.it/search/?keyword=%20brand%20of%20the%20CPU) [Hypervisor](https://unprotect.it/search/?keyword=%20Hypervisor) [leaf information](https://unprotect.it/search/?keyword=%20leaf%20information) [EAX register](https://unprotect.it/search/?keyword=%20EAX%20register) [EBX](https://unprotect.it/search/?keyword=%20EBX) [EDX](https://unprotect.it/search/?keyword=%20EDX) [ECX](https://unprotect.it/search/?keyword=%20ECX) [virtualisation](https://unprotect.it/search/?keyword=%20virtualisation) [plateforms](https://unprotect.it/search/?keyword=%20plateforms) [KVM](https://unprotect.it/search/?keyword=%20KVM) [Microsoft Hv](https://unprotect.it/search/?keyword=%20Microsoft%20Hv) [Hyper V](https://unprotect.it/search/?keyword=%20Hyper%20V) [VMware](https://unprotect.it/search/?keyword=%20VMware) [GenuineIntel](https://unprotect.it/search/?keyword=%20GenuineIntel)

##### Evasion Categories

[![Sandbox Evasion icon](https://unprotect.it/media/2024/04/08/icons8-leak.svg)**Sandbox Evasion**](https://unprotect.it/techniques/?pre_select=sandbox-evasion)

### Code Snippets

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [Anti-VM - Bletchley Park](https://sites.google.com/site/bletchleypark2/malware-analysis/malware-technique/anti-vm)
- [GitHub - a0rtega/pafish: Pafish is a testing tool that uses different techniques to detect virtual machines and malware analysis environments in the same way that malware families do](https://github.com/a0rtega/pafish)

* * *

##### Created

March 11, 2019


##### Last Revised

March 24, 2026
