## Bad String Format

Bad string format is a technique used by malware to evade detection and analysis by OllyDbg, a popular debugger used by security researchers and analysts. This technique involves using malformed strings that exploit a known bug in OllyDbg, causing the debugger to crash or behave unexpectedly.

For example, the malware may use a string with multiple %s inputs, which OllyDbg is not able to handle correctly. This causes the debugger to crash or behave in an unpredictable manner, making it difficult for the analyst to continue their analysis. This technique can be effective in disrupting the analysis process and making it more difficult for the analyst to understand the malware's capabilities and behavior. However, it is only effective against OllyDbg, and other debuggers may not be affected by this technique.

* * *

##### Technique Identifier

[U0104](https://unprotect.it/search/?keyword=U0104)

##### Technique Tags

[Bad string format](https://unprotect.it/search/?keyword=Bad%20string%20format) [OllyDbg](https://unprotect.it/search/?keyword=%20OllyDbg) [Debugger evasion](https://unprotect.it/search/?keyword=%20Debugger%20evasion) [String manipulation](https://unprotect.it/search/?keyword=%20String%20manipulation)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [OpenRCE](http://www.openrce.org/reference_library/anti_reversing_view/8/OllyDbg%20Filename%20Format%20String/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
