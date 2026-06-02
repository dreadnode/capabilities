## NixImports

A .NET malware loader employs API-Hashing and dynamic invocation to circumvent static analysis. NixImports utilizes managed API-Hashing to dynamically determine most of its required functions during runtime. For function resolution, HInvoke needs two specific hashes: typeHash and methodHash, representing the type name and the method's full name, respectively. At runtime, HInvoke scans the entire mscorlib to locate the corresponding type and method. Consequently, HInvoke doesn't generate any import references for the methods accessed through it.

Additionally, NixImports is designed to minimize the use of well-known methods. Wherever possible, it opts for internal methods over their standard wrappers. This strategy helps in evading the basic hooks and monitoring systems used by certain security tools.

* * *

##### Technique Identifier

[U1434](https://unprotect.it/search/?keyword=U1434)

##### Technique Tags

[NixImports](https://unprotect.it/search/?keyword=NixImports) [packer](https://unprotect.it/search/?keyword=%20packer) [.net](https://unprotect.it/search/?keyword=%20.net)

##### Evasion Categories

[![Packers icon](https://unprotect.it/media/2024/04/08/icons8-compress.svg)**Packers**](https://unprotect.it/techniques/?pre_select=packers)

### Detection Rules

### Contributors

- [Jonathan Peters](https://unprotect.it/users/public/profile/jonathan-peters/)
- [dr4k0nia](https://unprotect.it/users/public/profile/dr4k0nia/)

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [GitHub - dr4k0nia/NixImports: A .NET malware loader, using API-Hashing to evade static analysis](https://github.com/dr4k0nia/NixImports/tree/master)
- [NixImports a .NET loader using HInvoke \| dr4k0nia](https://dr4k0nia.github.io/posts/NixImports-a-NET-loader-using-HInvoke/)

* * *

##### Created

January 14, 2024


##### Last Revised

March 24, 2026
