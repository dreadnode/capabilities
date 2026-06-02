## Heap Flag

`ProcessHeap` is located at `0x18` in the PEB structure. This first heap contains a header with fields used to tell the kernel whether the heap was created within a debugger. The heap contains two fields which are affected by the presence of a debugger. These fields are `Flags` and `ForceFlags`.

The values of `Flags and ForceFlags` are normally set to `HEAP_GROWABLE` and `0`, respectively.

On 64-bit Windows XP, and Windows Vista and higher, if a debugger is present, the Flags field is set to a combination of these flags:

- `HEAP_GROWABLE (2)`
- `HEAP_TAIL_CHECKING_ENABLED (0x20)`
- `HEAP_FREE_CHECKING_ENABLED (0x40)`
- `HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)`

When a debugger is present, the ForceFlags field is set to a combination of these flags:

- `HEAP_TAIL_CHECKING_ENABLED (0x20)`
- `HEAP_FREE_CHECKING_ENABLED (0x40)`
- `HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)`

* * *

##### Technique Identifiers

[U0112](https://unprotect.it/search/?keyword=U0112) [B0001.021](https://unprotect.it/search/?keyword=B0001.021)

##### Technique Tag

[heapflag](https://unprotect.it/search/?keyword=heapflag)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software](https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software)
- [Anti-Debug: Debug Flags](https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
