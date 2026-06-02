## TLS Callback

TLS (Thread Local Storage) callbacks are a mechanism in Windows that allows a program to define a function that will be called when a thread is created. These callbacks can be used to perform various tasks, such as initializing thread-specific data or modifying the behavior of the thread.

As an anti-debugging technique, a program can use a TLS callback to execute code before the main entry point of the program, which is defined in the PE (Portable Executable) header. This allows the program to run secretly in a debugger, as the debugger will typically start at the main entry point and may not be aware of the TLS callback.

The program can use the TLS callback to detect whether it is being debugged, and if it is, it can terminate the process or take other actions to evade debugging. This technique can be used to make it more difficult for a debugger to attach to the process and to hinder reverse engineering efforts.

* * *

##### Technique Identifier

[U0124](https://unprotect.it/search/?keyword=U0124)

##### Technique Tags

[TLS callbacks](https://unprotect.it/search/?keyword=TLS%20callbacks) [anti-debugging technique](https://unprotect.it/search/?keyword=%20anti-debugging%20technique) [thread](https://unprotect.it/search/?keyword=%20thread) [main entry point](https://unprotect.it/search/?keyword=%20main%20entry%20point) [debugger](https://unprotect.it/search/?keyword=%20debugger)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://resources.infosecinstitute.com/debugging-tls-callbacks/#gref](https://resources.infosecinstitute.com/debugging-tls-callbacks/#gref)
- [InfoSec Handlers Diary Blog - SANS Internet Storm Center](https://isc.sans.edu/diary/How+Malware+Defends+Itself+Using+TLS+Callback+Functions/6655)

### Matching Samples 10 most recent

| Sample Name | Matching Techniques | First Seen | Last Seen |
| --- | --- | --- | --- |
| [main.exe](https://unprotect.it/scan/result/91c3f91e-6c8c-4845-984d-2a2b7ecdbd03/) | 11 | 2026-02-07 | 3 months ago |
| [a.exe](https://unprotect.it/scan/result/530969af-e4f9-46e0-9cae-25262d995fee/) | 7 | 2025-10-03 | 7 months, 1 week ago |
| [program.exe](https://unprotect.it/scan/result/093c22ab-4ae0-4665-9ab8-fd4c4c3a4a0a/) | 6 | 2025-10-01 | 7 months, 1 week ago |
| [DSViper\_AES.exe](https://unprotect.it/scan/result/b6d748d6-bb33-4b77-b107-bdc460a3f35e/) | 8 | 2025-09-23 | 7 months, 2 weeks ago |
| [xor.exe](https://unprotect.it/scan/result/4961addf-cc84-4d84-9e53-469ff36a2ccb/) | 6 | 2025-08-30 | 8 months, 1 week ago |
| [hemlockwin.exe](https://unprotect.it/scan/result/cb1b5e27-6ffb-40b2-9d07-81bc16cc6f1a/) | 8 | 2025-08-06 | 9 months ago |
| [teste.exe](https://unprotect.it/scan/result/ae663450-7c5c-430f-abed-755b49e253a1/) | 6 | 2025-07-29 | 9 months, 2 weeks ago |
| [libcrypto-1\_1.dll](https://unprotect.it/scan/result/a572656c-f83b-4ec2-acb4-5a386352f669/) | 7 | 2025-07-01 | 10 months, 1 week ago |
| [loader.exe](https://unprotect.it/scan/result/493fa404-0b00-4051-bf25-0d8f6d2f4a36/) | 8 | 2025-05-29 | 11 months, 1 week ago |
| [hello.exe](https://unprotect.it/scan/result/81928427-e265-4796-b549-6d78f2f911ab/) | 8 | 2024-12-27 | 1 year, 4 months ago |

[View All](https://unprotect.it/scan/samples/technique/tls-callback/)

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
