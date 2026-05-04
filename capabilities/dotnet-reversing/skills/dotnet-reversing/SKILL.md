---
name: dotnet-reversing
description: Use when reverse engineering .NET assemblies, decompiling DLLs/EXEs, or hunting for vulnerabilities in .NET applications.
---

# .NET Reverse Engineering

## Quick Start

```
dotnet_scan_binaries(path="/target")           # find all .NET binaries
dotnet_list_namespaces(path="App.dll")         # survey structure
dotnet_search_by_name(path="App.dll", search="password")  # find interesting types/methods
dotnet_decompile_type(path="App.dll", type_name="App.AuthService")  # read the code
```

## Tools

| Tool | Purpose |
|------|---------|
| `dotnet_scan_binaries(path, pattern?, exclude?)` | Find .NET binaries. `exclude` is comma-separated patterns to skip. |
| `dotnet_list_namespaces(path)` | List namespaces |
| `dotnet_list_types(path)` / `dotnet_list_types_in_namespace(path, namespace)` | List types |
| `dotnet_list_methods(path)` / `dotnet_list_methods_in_type(path, type_name)` | List methods |
| `dotnet_decompile_type(path, type_name)` | Decompile a type to C# — **preferred for targeted analysis** |
| `dotnet_decompile_methods(path, method_names)` | Decompile specific methods by name |
| `dotnet_decompile_module(path)` | Decompile entire assembly — **avoid, output is huge** |
| `dotnet_search_by_name(path, search)` | Find types/methods by **name** |
| `dotnet_search_references(path, search)` | Find methods that **call or use** an API in IL bytecode |
| `dotnet_get_call_flows(paths, method_name, max_depth?)` | Trace how a method is reached from entry points |
| `dotnet_download_nuget(package, version?, output_dir?)` | Download NuGet package for analysis |
| `report_finding(file, method, criticality, content)` | Report a finding. Criticality: `critical`/`high`/`medium`/`low`/`info` |
| `report_auth(auth_material)` | Report hardcoded credentials, API keys, tokens |
| `report_poc(poc)` | Save a proof-of-concept with exploitation steps |
| `finish_task(success, markdown_summary)` | Mark task complete with summary |

**Key difference**: `search_by_name` finds things *named* "Sql", while `search_references` finds code that *uses* SqlCommand.

## Vulnerability Hunting Workflow

### Phase 1: Survey
```
dotnet_scan_binaries(path="/app")
dotnet_list_namespaces(path="Target.dll")
```
Identify the application structure. Focus on non-Microsoft assemblies.

### Phase 2: Search for Security-Sensitive Patterns

Use `dotnet_search_by_name` for name-based searches and `dotnet_search_references` for IL bytecode/API usage searches. Run these across each target assembly.

**Name searches** (`search_by_name`): `password`, `credential`, `secret`, `apikey`, `token`, `auth`, `encrypt`, `decrypt`, `hash`, `query`, `endpoint`, `url`

**API/IL reference searches** (`search_references`):
- **Deserialization (RCE):** `BinaryFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`, `LosFormatter`, `JsonConvert.DeserializeObject`, `XmlSerializer`, `JavaScriptSerializer`
- **Command execution:** `Process.Start`, `System.Diagnostics.Process`, `PowerShell`, `cmd.exe`
- **Crypto:** `System.Security.Cryptography`
- **File I/O:** `System.IO.File`, `FileStream`, `StreamReader`, `Path.Combine`
- **SQL:** `SqlCommand`, `ExecuteNonQuery`, `ExecuteReader`
- **HTTP (SSRF):** `HttpClient`, `WebRequest`, `HttpWebRequest`
- **XML (XXE):** `XmlReader`, `XmlDocument`, `XDocument`, `XmlTextReader`
- **LDAP:** `DirectorySearcher`, `DirectoryEntry`, `System.DirectoryServices`

### Phase 3: Decompile Suspicious Code
```
dotnet_decompile_type(path="App.dll", type_name="App.Services.AuthenticationService")
```
Read the actual C# source. Look for:
- Hardcoded credentials
- Weak crypto (MD5, SHA1, DES, static IVs/keys)
- SQL string concatenation
- Unsanitized user input in file paths
- Dangerous deserialization
- Command injection

### Phase 4: Trace Attack Paths
```
dotnet_get_call_flows(
    paths=["App.dll", "App.Core.dll"],
    method_name="ExecuteCommand",
    max_depth=10
)
```
Find how vulnerable methods are reached from entry points (controllers, handlers, public APIs).

### Phase 5: Report Findings
```
report_finding(
    file="App.dll",
    method="AuthService.ValidateToken",
    criticality="high",
    content="Hardcoded JWT secret found:\n```csharp\nprivate static string Secret = \"supersecret123\";\n```"
)

report_auth(auth_material="API key in config: `sk-1234567890abcdef`")

report_poc(poc="## Exploitation\n1. Extract JWT secret\n2. Forge admin token\n3. ...")

finish_task(success=True, markdown_summary="Found 2 high-severity issues...")
```
Always report findings to persist them to the Dreadnode platform.

## Common Vulnerability Patterns

### Hardcoded Credentials
```csharp
// Look for string literals in auth code
private static string ApiKey = "sk-1234567890abcdef";
connectionString = "Server=db;User=admin;Password=P@ssw0rd";
```

### Insecure Deserialization
```csharp
// BinaryFormatter = RCE
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);  // VULNERABLE

// Type-controlling JSON deserialization
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // VULNERABLE
});
```

### Command Injection
```csharp
// User input in process arguments
Process.Start("cmd.exe", "/c " + userInput);  // VULNERABLE
```

### Path Traversal
```csharp
// Unsanitized path concatenation
string path = Path.Combine(baseDir, userFileName);  // VULNERABLE if userFileName = "../../../etc/passwd"
File.ReadAllText(path);
```

### SQL Injection
```csharp
// String concatenation in queries
string query = "SELECT * FROM users WHERE id = " + userId;  // VULNERABLE
cmd.CommandText = query;
```

### Weak Cryptography
```csharp
// Deprecated algorithms
MD5.Create().ComputeHash(data);  // Weak hash
DES.Create();  // Weak cipher
new RijndaelManaged { Mode = CipherMode.ECB };  // Weak mode
```

## Critical Rules

**DO:**
- Always start with `dotnet_scan_binaries` to find targets
- Use `dotnet_decompile_type` for targeted analysis (not `dotnet_decompile_module`)
- Report ALL findings with `report_finding` — even low-severity ones
- Use `report_auth` immediately when you find credentials
- Call `finish_task` when analysis is complete

**DO NOT:**
- Use `dotnet_decompile_module` on large assemblies — it will overflow context
- Skip reporting — findings must be persisted to the platform
- Analyze only one assembly — check ALL binaries in the target directory
- Ignore Microsoft/System assemblies completely — they can have vulnerabilities too

## Tips

- **Start narrow**: Use `dotnet_decompile_type` not `dotnet_decompile_module` — smaller output, faster analysis
- **Search IL references**: `dotnet_search_references` finds actual usage in bytecode, not just type names
- **Cross-assembly tracing**: `dotnet_get_call_flows` accepts multiple assemblies to trace calls across DLLs
- **NuGet analysis**: Download packages with `dotnet_download_nuget` to analyze third-party dependencies
- **Exclude noise**: Use `exclude` parameter in `dotnet_scan_binaries` to skip files, e.g. `exclude="Microsoft.,System."`
- **Batch searches**: Run multiple `search_references` calls to cover all vulnerability classes before decompiling
