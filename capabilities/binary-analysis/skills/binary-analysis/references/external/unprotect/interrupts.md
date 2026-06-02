## Interrupts

Adversaries may use exception-based anti-debugging techniques to detect whether their code is being executed in a debugger. These techniques rely on the fact that most debuggers will trap exceptions and not immediately pass them to the process being debugged for handling.

By triggering an exception and checking whether it is handled properly, the adversary's code can determine whether it is being executed in a debugger and take appropriate action, such as exiting or altering its behavior. This can be achieved using interrupt instructions such as INT 3 or UD2 to trigger the exception. This technique can be used to evade detection and make reverse engineering more difficult.

* * *

##### Technique Identifier

[U0106](https://unprotect.it/search/?keyword=U0106)

##### Featured Windows API's

 Below, you will find a list of the most commonly used Windows API's that are currently utilized by
 malware authors for current evasion technique. This list is meant to provide an overview of the
 API's that are commonly used for this purpose. If there are any API's that you feel should be
 included on this list, please do not hesitate to contact us. We will be happy to update the list and
 provide any additional information or documentation that may be helpful.


- [IsDebuggerPresent](https://unprotect.it/featured-api/isdebuggerpresent/)

##### Evasion Categories

[![Anti-Debugging icon](https://unprotect.it/media/2024/04/08/icons8-bug_uaiUrWu.svg)**Anti-Debugging**](https://unprotect.it/techniques/?pre_select=anti-debugging)

### Code Snippets

### Detection Rules

* * *

##### Created

March 18, 2019


##### Last Revised

March 24, 2026
