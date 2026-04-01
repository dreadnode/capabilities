"""C#/.NET dangerous function scanner."""

from dreadnode.agents.tools import tool_method

from . import CategoryList, DangerousFunctionsBase

_FILE_GLOB = "*.{cs,csx,cshtml,razor}"

_CATEGORIES: CategoryList = [
    (
        "sql_injection",
        "SQL Injection",
        "CWE-89",
        "String concatenation in SQL commands or raw queries without parameterization",
        r'(SqlCommand|SqlDataAdapter|OleDbCommand|OdbcCommand)\s*\(.*\+|"(SELECT|INSERT|UPDATE|DELETE)\b.*\+|\.ExecuteSqlRaw\s*\(.*\+|\.FromSqlRaw\s*\(.*\+',
    ),
    (
        "deserialization",
        "Unsafe Deserialization",
        "CWE-502",
        ".NET deserialization APIs allowing arbitrary type instantiation / RCE via gadget chains",
        r"\bBinaryFormatter\b|\bSoapFormatter\b|\bLosFormatter\b|\bObjectStateFormatter\b|\bNetDataContractSerializer\b|\bJavaScriptSerializer\b.*DeserializeObject|TypeNameHandling\s*[=:]\s*TypeNameHandling\.(All|Auto|Objects|Arrays)",
    ),
    (
        "command_injection",
        "Command Injection",
        "CWE-78",
        "Process execution APIs where arguments may include user input",
        r"Process\.Start\s*\(|ProcessStartInfo\s*\(|new\s+Process\s*\{|\.FileName\s*=.*\+|\.Arguments\s*=.*\+",
    ),
    (
        "xxe",
        "XML External Entity Injection",
        "CWE-611",
        "XML parsers without explicitly disabled DTD processing or external entities",
        r"new\s+XmlDocument\s*\(|XmlReader\.Create\s*\(|new\s+XmlTextReader\s*\(|new\s+XPathDocument\s*\(|XDocument\.Load\s*\(|\.DtdProcessing\s*=\s*DtdProcessing\.(Parse|Ignore)|\.ProhibitDtd\s*=\s*false|\.XmlResolver\s*=\s*new\s+XmlUrlResolver",
    ),
    (
        "path_traversal",
        "Path Traversal",
        "CWE-22",
        "File operations with user-controllable paths lacking ../ sanitization",
        r"new\s+FileStream\s*\(.*\+|File\.(ReadAll|WriteAll|Open|Copy|Move|Delete|Exists)\w*\s*\(.*\+|Directory\.(Create|Delete|Move|Exists)\s*\(.*\+|Path\.Combine\s*\(.*Request\.|\.MapPath\s*\(.*\+",
    ),
    (
        "weak_crypto",
        "Weak Cryptography",
        "CWE-327, CWE-328",
        "Broken or outdated cryptographic algorithms",
        r"\b(DES|TripleDES|RC2|MD5|SHA1)\.Create\s*\(|\bDESCryptoServiceProvider\b|\bTripleDESCryptoServiceProvider\b|\bRC2CryptoServiceProvider\b|\bMD5CryptoServiceProvider\b|\bSHA1CryptoServiceProvider\b|\bRijndaelManaged\b|CipherMode\.ECB|\.CreateEncryptor\s*\(.*CipherMode\.ECB",
    ),
    (
        "insecure_random",
        "Insecure Random Number Generation",
        "CWE-330",
        "Predictable RNG used where cryptographic randomness is needed",
        r"new\s+Random\s*\(|Random\.Shared\.|System\.Random\b",
    ),
    (
        "hardcoded_credentials",
        "Hardcoded Credentials",
        "CWE-798",
        "Passwords, keys, tokens, or connection strings embedded in source code",
        r'(?i)(password|passwd|pwd|secret|apikey|api_key|token|connectionstring)\s*=\s*"[^"]{4,}"|new\s+NetworkCredential\s*\(.*".*".*".*"|SqlConnection\s*\(.*".*Password=',
    ),
    (
        "ldap_injection",
        "LDAP Injection",
        "CWE-90",
        "LDAP queries built with string concatenation",
        r"DirectorySearcher\s*\(.*\+|\.Filter\s*=.*\+.*Request|DirectoryEntry\s*\(.*\+|new\s+DirectorySearcher\b",
    ),
    (
        "xss",
        "Cross-Site Scripting Sinks",
        "CWE-79",
        "Output of user input without encoding in ASP.NET contexts",
        r"@Html\.Raw\s*\(|Response\.Write\s*\(.*Request|\.innerHTML\s*=|HttpUtility\.HtmlDecode\s*\(.*Request|WriteLiteral\s*\(.*Request",
    ),
    (
        "open_redirect",
        "Unvalidated Redirect",
        "CWE-601",
        "Redirects using request parameters without validation",
        r"\.Redirect\s*\(.*Request|RedirectToAction\s*\(.*Request|\.RedirectPermanent\s*\(.*Request|return\s+Redirect\s*\(.*Request",
    ),
    (
        "csrf_disabled",
        "CSRF Protection Disabled",
        "CWE-352",
        "Anti-forgery validation explicitly disabled or missing on state-changing endpoints",
        r"\[IgnoreAntiforgeryToken\]|options\.SuppressXFrameOptionsHeader|ValidateAntiForgeryToken.*false|services\.AddAntiforgery.*Cookie.*SameSiteMode\.None",
    ),
    (
        "insecure_tls",
        "Insecure TLS Configuration",
        "CWE-295, CWE-326",
        "Disabled certificate validation or legacy protocol versions",
        r"ServerCertificateValidationCallback\s*=|ServicePointManager\.ServerCertificateValidationCallback|SslProtocols\.(Ssl2|Ssl3|Tls\b|Tls11)|ServerCertificateCustomValidationCallback.*=.*true|\.CheckCertificateRevocationList\s*=\s*false",
    ),
    (
        "ssrf",
        "Server-Side Request Forgery",
        "CWE-918",
        "HTTP requests with user-controlled URLs",
        r"new\s+HttpClient\s*\(|HttpClient\.(Get|Post|Put|Delete|Send)Async\s*\(.*\+|new\s+WebClient\s*\(|WebClient\.(Download|Upload)\w+\s*\(.*\+|WebRequest\.Create\s*\(.*\+|new\s+Uri\s*\(.*Request\.",
    ),
    (
        "unsafe_reflection",
        "Unsafe Reflection",
        "CWE-470",
        "Dynamic type loading or method invocation with potentially untrusted input",
        r"Type\.GetType\s*\(.*\+|Activator\.CreateInstance\s*\(.*\+|Assembly\.Load(From|File)?\s*\(.*\+|\.InvokeMember\s*\(.*\+|MethodInfo\.Invoke\s*\(",
    ),
    (
        "xpath_injection",
        "XPath Injection",
        "CWE-643",
        "XPath expressions built with concatenation",
        r"\.SelectNodes\s*\(.*\+|\.SelectSingleNode\s*\(.*\+|XPathExpression\.Compile\s*\(.*\+|\.Evaluate\s*\(.*\+.*XPath",
    ),
    (
        "log_injection",
        "Log Injection",
        "CWE-117",
        "User-controlled data in log statements without sanitization",
        r"(Log|_log|_logger|logger)\.(Information|Warning|Error|Debug|Fatal|Verbose)\s*\(.*Request\.|ILogger\.\w+\s*\(.*Request\.",
    ),
    (
        "regex_dos",
        "Regular Expression DoS",
        "CWE-1333",
        "Regex compiled from user input, risking catastrophic backtracking",
        r"new\s+Regex\s*\(.*Request\.|Regex\.(Match|IsMatch|Replace)\s*\(.*Request\.|new\s+Regex\s*\(.*\+",
    ),
    (
        "zip_slip",
        "Archive Path Traversal",
        "CWE-22",
        "Archive extraction without validating entry paths",
        r"ZipFile\.ExtractToDirectory\s*\(|ZipArchiveEntry|\.ExtractToFile\s*\(|\.FullName.*\.\.[\\/]|TarEntry|GZipStream",
    ),
    (
        "viewstate_insecure",
        "Insecure ViewState",
        "CWE-642",
        "ASP.NET ViewState without MAC validation — allows tampering and deserialization attacks",
        r"EnableViewStateMac\s*=\s*false|ViewStateEncryptionMode\s*=\s*ViewStateEncryptionMode\.Never|__VIEWSTATE",
    ),
    (
        "header_injection",
        "HTTP Header Injection",
        "CWE-113",
        "User input placed directly into response headers",
        r"\.AppendHeader\s*\(.*Request|\.AddHeader\s*\(.*Request|Response\.Headers\.Add\s*\(.*Request|Response\.Cookies\.Append\s*\(.*Request",
    ),
    (
        "mass_assignment",
        "Mass Assignment / Over-Posting",
        "CWE-915",
        "Model binding without [Bind] restrictions, allowing attackers to set unintended properties",
        r"\b(TryUpdateModel|UpdateModel|TryUpdateModelAsync)\s*\(",
    ),
    (
        "entity_framework_raw",
        "Raw SQL in Entity Framework",
        "CWE-89",
        "EF Core raw SQL methods with string interpolation or concatenation",
        r"\.FromSqlRaw\s*\(.*\+|\.ExecuteSqlRaw\s*\(.*\+|\.FromSqlInterpolated\s*\(.*\+|Database\.ExecuteSqlCommand\s*\(.*\+",
    ),
    (
        "cors_misconfiguration",
        "Permissive CORS",
        "CWE-942",
        "Overly broad CORS policies",
        r'\.AllowAnyOrigin\s*\(|\.WithOrigins\s*\(\s*"\*"|Access-Control-Allow-Origin.*\*|\.SetIsOriginAllowed\s*\(.*=>\s*true',
    ),
    (
        "insecure_cookie",
        "Insecure Cookie Configuration",
        "CWE-614, CWE-1004",
        "Cookies missing Secure, HttpOnly, or SameSite attributes",
        r"\.Cookie\.HttpOnly\s*=\s*false|\.Cookie\.SecurePolicy\s*=\s*CookieSecurePolicy\.(None|SameAsRequest)|SameSiteMode\.None|\.Cookie\.Secure\s*=\s*false",
    ),
    (
        "debug_enabled",
        "Debug/Diagnostic Exposure",
        "CWE-215",
        "Debug mode or developer exception pages enabled in production-facing code",
        r'app\.UseDeveloperExceptionPage\s*\(|<compilation\s+debug\s*=\s*"true"|<customErrors\s+mode\s*=\s*"Off"|\.EnableDetailedErrors\s*\(\s*true|\.IsDevelopment\s*\(\s*\)\s*\)\s*\{?\s*$',
    ),
    (
        "jwt_misconfiguration",
        "JWT Validation Bypass",
        "CWE-345, CWE-347",
        "JWT token validation with security checks disabled",
        r"ValidateIssuerSigningKey\s*=\s*false|ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|ValidateLifetime\s*=\s*false|RequireSignedTokens\s*=\s*false|RequireExpirationTime\s*=\s*false",
    ),
]

_CATEGORY_IDS = {cat[0] for cat in _CATEGORIES}


class DangerousFunctionsCSharpTool(DangerousFunctionsBase):
    """Scan C#/.NET source files for dangerous function patterns."""

    @tool_method(catch=True)
    async def scan_dangerous_functions_csharp(
        self,
        path: str | None = None,
        categories: list[str] | None = None,
    ) -> str:
        """
        Scan C#/.NET source files for dangerous function patterns grouped by
        vulnerability category. Each category targets specific CWEs.

        Available categories: sql_injection, deserialization, command_injection,
        xxe, path_traversal, weak_crypto, insecure_random, hardcoded_credentials,
        ldap_injection, xss, open_redirect, csrf_disabled, insecure_tls, ssrf,
        unsafe_reflection, xpath_injection, log_injection, regex_dos, zip_slip,
        viewstate_insecure, header_injection, mass_assignment,
        entity_framework_raw, cors_misconfiguration, insecure_cookie,
        debug_enabled, jwt_misconfiguration.
        Pass a subset to narrow the scan.

        Args:
            path: Directory to scan. Defaults to current working directory.
            categories: List of category IDs to scan. Defaults to all.

        Returns:
            Matches grouped by category with CWE, description, and file:line hits.
        """
        return await self._scan_patterns(
            path=path,
            categories=categories,
            all_categories=_CATEGORIES,
            valid_ids=_CATEGORY_IDS,
            file_glob=_FILE_GLOB,
            language="C#",
        )
