## SIDT, Red Pill

Red Pill is a technique used by malware to determine whether it is running on a physical machine or a virtual machine. The Red Pill technique involves executing the SIDT instruction, which retrieves the value of the Interrupt Descriptor Table Register (IDTR) and stores it in a memory location.

On a physical machine, the IDTR will contain the address of the Interrupt Descriptor Table (IDT), which is a data structure used by the operating system to manage interrupts. However, on a virtual machine, the IDTR will contain the address of the IDT for the virtual machine, which is different from the IDT for the host machine.

By comparing the IDTR on a physical and a virtual machine, malware can determine whether it is running on a physical or a virtual machine. This information can be used by the malware to adjust its behavior accordingly.

* * *

##### Technique Identifiers

[U1328](https://unprotect.it/search/?keyword=U1328) [B0009.030](https://unprotect.it/search/?keyword=B0009.030)

##### Technique Tags

[Anti-VM technique](https://unprotect.it/search/?keyword=Anti-VM%20technique) [SIDT instruction](https://unprotect.it/search/?keyword=%20SIDT%20instruction) [IDTR register](https://unprotect.it/search/?keyword=%20IDTR%20register) [IDT](https://unprotect.it/search/?keyword=%20IDT) [Interrupts](https://unprotect.it/search/?keyword=%20Interrupts) [Virtual machine](https://unprotect.it/search/?keyword=%20Virtual%20machine) [Interrupt Descriptor Table (IDT)](https://unprotect.it/search/?keyword=%20Interrupt%20Descriptor%20Table%20(IDT))

##### Evasion Categories

[![Sandbox Evasion icon](https://unprotect.it/media/2024/04/08/icons8-leak.svg)**Sandbox Evasion**](https://unprotect.it/techniques/?pre_select=sandbox-evasion)

### Code Snippets

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://litigationconferences.com/wp-content/uploads/2017/05/Introduction-to-Evasive-Techniques-v1.0.pdf](https://litigationconferences.com/wp-content/uploads/2017/05/Introduction-to-Evasive-Techniques-v1.0.pdf)

* * *

##### Created

March 11, 2019


##### Last Revised

March 24, 2026
