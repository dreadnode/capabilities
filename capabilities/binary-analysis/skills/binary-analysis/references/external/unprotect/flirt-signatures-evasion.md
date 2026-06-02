## FLIRT Signatures Evasion

FLIRT Signature evasion is a technique used by malware to hide malicious code inside legitimate functions from known libraries. FLIRT (Fast Library Identification and Recognition Technology) is a database that contains signature patterns for identifying known functions from legitimate libraries.

Malware authors can abuse these signatures by modifying or adding specific bytes to the code, so that it appears to be a legitimate function when scanned by a FLIRT database. This can trick reverse engineering tools that rely on FLIRT signatures without performing further analysis, and make it more difficult for security analysts to identify and analyze the malware.

By using this technique, malware authors can evade detection and make their code more difficult to understand and analyze.

* * *

##### Technique Identifier

[U0220](https://unprotect.it/search/?keyword=U0220)

##### Technique Tags

[FLIRT (Fast Library Identification and Recognition Technology)](https://unprotect.it/search/?keyword=FLIRT%20(Fast%20Library%20Identification%20and%20Recognition%20Technology)) [Signature evasion](https://unprotect.it/search/?keyword=%20Signature%20evasion) [Code modification](https://unprotect.it/search/?keyword=%20Code%20modification) [Legitimate functions](https://unprotect.it/search/?keyword=%20Legitimate%20functions)

##### Evasion Categories

[![Anti-Disassembly icon](https://unprotect.it/media/2024/04/08/icons8-dna.svg)**Anti-Disassembly**](https://unprotect.it/techniques/?pre_select=anti-disassembly)

### Code Snippets

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [IDA F.L.I.R.T. Technology: In-Depth – Hex Rays](https://hex-rays.com/products/ida/tech/flirt/in_depth/)
- [GitHub - Maktm/FLIRTDB: A community driven collection of IDA FLIRT signature files](https://github.com/Maktm/FLIRTDB)
- [VirusTotal](https://www.virustotal.com/gui/file/a41ba65405a032f4450ba80882cdd01d715d9d1684f4204050566be29a6dedb0)

* * *

##### Created

July 1, 2022


##### Last Revised

March 24, 2026
