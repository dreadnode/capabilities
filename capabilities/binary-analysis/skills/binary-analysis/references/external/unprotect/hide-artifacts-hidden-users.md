## Hide Artifacts: Hidden Users

Adversaries may use hidden users to hide the presence of user accounts they create or modify. Administrators may want to hide users when there are many user accounts on a given system or if they want to hide their administrative or other management accounts from other users.

Adversaries may hide user accounts in Windows. Adversaries can set the HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList Registry key value to 0 for a specific user to prevent that user from being listed on the logon screen.

* * *

##### Technique Identifier

[T1564.002](https://unprotect.it/search/?keyword=T1564.002)

##### Technique Tags

[Defense Evasion](https://unprotect.it/search/?keyword=Defense%20Evasion) [HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList](https://unprotect.it/search/?keyword=%20HKLM\SOFTWARE\Microsoft\Windows%20NT\CurrentVersion\Winlogon\SpecialAccounts\UserList) [Dragonfly](https://unprotect.it/search/?keyword=%20Dragonfly) [supress users from login screen](https://unprotect.it/search/?keyword=%20supress%20users%20from%20login%20screen)

##### Evasion Categories

[![Defense Evasion [Mitre] icon](https://unprotect.it/media/2024/04/08/icons8-burglar.svg)**Defense Evasion \[Mitre\]**](https://unprotect.it/techniques/?pre_select=Defense-Evasion-Mitre)

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [Hide Artifacts: Hidden Users, Sub-technique T1564.002 - Enterprise \| MITRE ATT&CK®](https://attack.mitre.org/techniques/T1564/002/)

* * *

##### Created

January 31, 2023


##### Last Revised

March 24, 2026
