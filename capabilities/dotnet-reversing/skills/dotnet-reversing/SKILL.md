---
name: dotnet-reversing
description: Use when reverse engineering .NET assemblies, decompiling DLLs/EXEs, or hunting for vulnerabilities in .NET applications.
---

# .NET Reverse Engineering

Load the `vuln-assessment-methodology` skill alongside this one for severity
calibration, disprove-first discipline, and reporting standards.

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

### Phase 3: Decompile and Verify
```
dotnet_decompile_type(path="App.dll", type_name="App.Services.AuthenticationService")
```
Read the actual C# source. When you find a dangerous pattern, **read the full
function and its callers** before drawing conclusions. Check for:
- Hardcoded credentials
- Weak crypto (MD5, SHA1, DES, static IVs/keys)
- SQL string concatenation — **but check if the concatenated value comes from
  user input (HTTP param) vs config/env var. Only HTTP-sourced values are high severity.**
- Unsanitized user input in file paths
- Dangerous deserialization
- Command injection — **but check if the calling function has validation/filtering.
  If validation exists, look for bypasses rather than reporting "no sanitization."**

#### .NET-specific: JWT ReadToken is not always a finding

`ReadToken`/`ReadJwtToken` without `ValidateToken` is NOT a vulnerability when
the token is validated by a downstream service (Azure AD, ARM) or used only for
metadata extraction (expiry, caching). Only report it when unvalidated claims
drive authorization decisions.

### Phase 4: Trace Attack Paths
```
dotnet_get_call_flows(
    paths=["App.dll", "App.Core.dll"],
    method_name="ExecuteCommand",
    max_depth=10
)
```
Find how vulnerable methods are reached from entry points (controllers, handlers, public APIs).

### Phase 5: Assess Severity and Report

Assign severity based on actual exploitability — not the vulnerability class
name. The `vuln-assessment-methodology` skill has the full guidance; the
essentials:

| Source of dangerous input | Access required | Severity |
|---|---|---|
| HTTP request parameter | Unauthenticated, internet-facing | Critical/High |
| HTTP request parameter | Authenticated user | High/Medium |
| HTTP request parameter | Internal network only | Medium |
| Config file / env var | Container or host access | Low |
| Hardcoded value (as sink input) | N/A | Not a finding (but hardcoded credentials are — see methodology skill) |

**Before reporting every finding:**
- Trace the data flow from attacker-controlled source to sink
- Actively try to disprove it — look for validation, encoding, authorization
- If defensive code exists, demonstrate a specific bypass or retract
- Verify severity reflects exploitability, not vulnerability class name

```
report_finding(
    file="App.dll",
    method="AuthService.ValidateToken",
    criticality="critical",
    content="Hardcoded JWT signing secret in source code:\n```csharp\nprivate static string Secret = \"supersecret123\";\n```"
)

report_auth(auth_material="API key in config: `sk-1234567890abcdef`")

report_poc(poc="## Exploitation\n1. Extract JWT secret\n2. Forge admin token\n3. ...")

finish_task(success=True, markdown_summary="Found 2 high-severity issues...")
```
Always report findings to persist them to the Dreadnode platform.

## .NET Vulnerability Patterns: Vulnerable vs Safe

For each pattern, both vulnerable AND safe versions are shown. You must
check which one the code matches before reporting.

### Hardcoded Credentials
```csharp
// VULNERABLE — real secret in source code
private static string ApiKey = "sk-1234567890abcdef";
connectionString = "Server=db;User=admin;Password=P@ssw0rd";

// NOT A FINDING — loaded from config/env
var apiKey = Configuration["ApiKey"];
var connStr = Environment.GetEnvironmentVariable("DB_CONNECTION");

// NOT A FINDING — misleading error message (not a real credential)
throw new Exception("Api Key is invalid. Subscription validation failed.");
```

### Insecure Deserialization
```csharp
// VULNERABLE — BinaryFormatter with untrusted input
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(untrustedStream);

// VULNERABLE — TypeNameHandling enables type control
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All
});

// SAFE — System.Text.Json (no type handling by default)
var obj = JsonSerializer.Deserialize<MyType>(json);

// SAFE — TypeNameHandling.None (default)
JsonConvert.DeserializeObject<MyType>(json);
```

### Command Injection
```csharp
// VULNERABLE — direct interpolation
Process.Start("cmd.exe", "/c " + userInput);
Arguments = $"-c \"{command} {string.Join(" ", args)}\"";

// PARTIALLY SAFE — has validation, but check for bypasses
var error = ValidateCommand(command); // blocks ; && || | etc.
if (error != null) return error;
// If ValidateCommand misses characters like " or ${ }, it's
// an incomplete validation bypass (Medium), not "no sanitization" (High)

// SAFE — no shell, direct exec with argument array
Process.Start("myapp", new[] { "--flag", sanitizedValue });
```

### SQL Injection
```csharp
// VULNERABLE — user input concatenated into SQL
string query = "SELECT * FROM users WHERE id = " + request.UserId;

// LOW RISK — env var / config value concatenated (defense-in-depth issue)
// Attacker needs container access to control env var
string proc = "[" + schemaFromEnvVar + "].[MyProcedure]";

// SAFE — parameterized query
cmd.CommandText = "SELECT * FROM users WHERE id = @id";
cmd.Parameters.AddWithValue("@id", userId);
```

### Blazor XSS (MarkupString)
```csharp
// VULNERABLE — user input directly cast to MarkupString
builder.AddContent(0, (MarkupString)userInput);

// SAFE — HtmlEncoded BEFORE MarkupString cast
var encoded = WebUtility.HtmlEncode(userInput);
var colored = AnsiParser.ConvertToHtml(encoded, state); // adds <span> tags
builder.AddContent(0, (MarkupString)colored); // MarkupString needed for spans

// SAFE — Markdown pipeline with HTML disabled
pipeline.DisableHtml();
var html = Markdown.ToHtml(input, pipeline);
builder.AddContent(0, (MarkupString)html);
```

### JWT Validation
```csharp
// VULNERABLE — claims trusted for local authorization
var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
if (token.Claims.First(c => c.Type == "role").Value == "admin")
    GrantAdminAccess(); // No signature verification!

// SAFE — token read for metadata, validated by downstream service
var token = handler.ReadJwtToken(jwt);
var expiry = token.ValidTo; // Just extracting expiry for caching
return DelegatedTokenCredential.Create(jwt); // Azure AD validates the sig
```

### Path Traversal
```csharp
// VULNERABLE — user input in path without validation
string path = Path.Combine(baseDir, userFileName);
File.ReadAllText(path);

// SAFE — canonicalization check
string full = Path.GetFullPath(Path.Combine(baseDir, userFileName));
if (!full.StartsWith(baseDir)) throw new SecurityException();
```

## Critical Rules

**DO:**
- Always start with `dotnet_scan_binaries` to find targets
- Use `dotnet_decompile_type` for targeted analysis (not `dotnet_decompile_module`)
- Report all verified findings with `report_finding` — even low-severity ones
- Use `report_auth` only for real credentials, not error messages or placeholders
- Call `finish_task` when analysis is complete

**DO NOT:**
- Report `ReadToken`/`ReadJwtToken` as "JWT bypass" when the token is validated server-side
- Report `MarkupString` as XSS when the content is `HtmlEncode`d upstream
- Use `dotnet_decompile_module` on large assemblies — it will overflow context

## Tips

- **Start narrow**: Use `dotnet_decompile_type` not `dotnet_decompile_module` — smaller output, faster analysis
- **Search IL references**: `dotnet_search_references` finds actual usage in bytecode, not just type names
- **Cross-assembly tracing**: `dotnet_get_call_flows` accepts multiple assemblies to trace calls across DLLs
- **NuGet analysis**: Download packages with `dotnet_download_nuget` to analyze third-party dependencies
- **Exclude noise**: Use `exclude` parameter in `dotnet_scan_binaries` to skip files, e.g. `exclude="Microsoft.,System."`
- **Batch searches**: Run multiple `search_references` calls to cover all vulnerability classes before decompiling
