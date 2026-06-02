## Deleting Troubleshoot Information and Core Dumps

Commands like `rm -rf /data/var/statedumps/*` and `rm -rf /data/var/cores/*` delete state dumps and core dumps, which are generated when processes crash. These files contain memory snapshots, stack traces, and runtime states of processes at the time of failure. They are often used to debug and understand the causes of crashes or application malfunctions.

Attackers use this technique to eliminate artifacts that could provide direct evidence of exploitation or the presence of malicious payloads in memory. For example, a core dump might reveal details about injected code, command execution, or runtime states that indicate malicious intent. By deleting these files, attackers erase critical forensic evidence, leaving investigators with no memory or process-level data to analyze.

## ![Linux](https://unprotect.it/static/img/linux.png)     Linux Note

### How Deleting State Dumps and Core Dumps Works in Linux

#### What Are State Dumps and Core Dumps?

- **State Dumps:** Files that capture the state of an application or system at a specific point in time, often including diagnostic information for troubleshooting.
- **Core Dumps:** Files generated when a program crashes unexpectedly. They contain a snapshot of the program's memory, including:
- Stack traces (call history leading to the crash).
- Memory content (e.g., variables, heap data, or instructions).
- Register states at the time of the crash.

These files are typically stored in directories like `/var/core/`, `/var/crash/`, or custom paths defined by the application (`/data/var/statedumps/` in the example).

* * *

#### How Do Commands Like `rm -rf` Work?

The commands `rm -rf /data/var/statedumps/*` and `rm -rf /data/var/cores/*` recursively and forcefully remove files within the specified directories:
1\. **Recursive Deletion (`-r`):** Deletes all files and subdirectories within the target directory.
2\. **Force Option (`-f`):** Ignores warnings, such as permission errors or non-existent files, ensuring deletion proceeds without interruption.
3\. **Wildcard (`*`):** Matches all files and directories within the target path.

For example:
\- `rm -rf /data/var/statedumps/*`: Deletes all state dump files.
\- `rm -rf /data/var/cores/*`: Deletes all core dump files.

These commands execute quickly and leave no easily accessible trace of the deleted files unless backups or shadow copies exist.

* * *

#### How It Can Be Abused

Attackers use this technique to eliminate critical forensic artifacts that could expose their activities. Here's how:

01. **Erasing Evidence of Exploitation:**
02. Core dumps may reveal traces of memory-resident payloads, such as:
    - Shellcode injected during an exploit.
    - Malicious commands or operations that caused the crash.
03. By deleting core dumps, attackers hide the exact steps or tools used in their exploitation process.

04. **Hindering Reverse Engineering:**

05. Analysts often use core dumps to reconstruct the sequence of events leading to a crash or failure. For example:
    - Determining the input that triggered a vulnerability.
    - Identifying malicious functions or code injected into memory.
06. Without core dumps, it becomes harder to analyze the exploit or payload.

07. **Concealing Persistence Mechanisms:**

08. Core dumps might contain information about how malicious code interacts with the system, such as:
    - Environment variables.
    - Loaded libraries or modules.
09. Deleting these files prevents investigators from identifying potential persistence mechanisms.

10. **Disrupting Incident Response:**

11. State dumps and core dumps provide real-time insights into what went wrong. Deleting them forces responders to rely on less detailed logs or indirect evidence, prolonging the investigation and increasing the chance of missing critical details.


* * *

##### Technique Identifier

[U0311](https://unprotect.it/search/?keyword=U0311)

##### Evasion Categories

[![Anti-Forensic icon](https://unprotect.it/media/2024/04/08/icons8-murder-chalk.svg)**Anti-Forensic**](https://unprotect.it/techniques/?pre_select=anti-forensic)

### Code Snippets

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [Ivanti Connect Secure VPN Targeted in New Zero-Day Exploitation \| Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day?hl=en)

* * *

##### Created

January 16, 2025


##### Last Revised

March 24, 2026
