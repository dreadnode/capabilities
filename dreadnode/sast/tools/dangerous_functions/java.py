"""Java dangerous function scanner."""

from dreadnode.agents.tools import tool_method

from . import CategoryList, DangerousFunctionsBase

_FILE_GLOB = "*.{java,jsp}"

_CATEGORIES: CategoryList = [
    (
        "sql_injection",
        "SQL Injection",
        "CWE-89",
        "String concatenation in SQL queries or raw Statement usage instead of PreparedStatement",
        r'"(SELECT|INSERT|UPDATE|DELETE)\b.*\+',
    ),
    (
        "deserialization",
        "Unsafe Deserialization",
        "CWE-502",
        "Java native deserialization of potentially untrusted data - ObjectInputStream, XMLDecoder, XStream",
        r"\bObjectInputStream\b|\breadObject\s*\(|\bXMLDecoder\b|\.fromXML\s*\(",
    ),
    (
        "xxe",
        "XML External Entity (XXE)",
        "CWE-611",
        "XML parser instantiation - verify external entities and DTDs are disabled",
        r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.(newInstance|newFactory)",
    ),
    (
        "command_injection",
        "Command Injection",
        "CWE-78",
        "Runtime.exec() or ProcessBuilder - verify user input cannot reach command arguments",
        r"getRuntime\s*\(\s*\)\.exec\s*\(|new\s+ProcessBuilder\s*\(",
    ),
    (
        "path_traversal",
        "Path Traversal",
        "CWE-22",
        "File or Path built from request data - check for ../ sanitization",
        r"new\s+File\s*\(.*get(Parameter|PathInfo|Header|RequestURI|ServletPath)|Paths\.get\s*\(.*get(Parameter|PathInfo|Header|RequestURI|ServletPath)",
    ),
    (
        "ldap_injection",
        "LDAP Injection",
        "CWE-90",
        "LDAP directory context or filter string built with concatenation",
        r'\b(InitialDirContext|InitialLdapContext)\b|"\(.*="\s*\+',
    ),
    (
        "weak_crypto",
        "Weak Cryptography",
        "CWE-327, CWE-328",
        "Broken or outdated algorithms - MD5, DES, RC4, SHA-1, ECB mode",
        r'getInstance\s*\(\s*"(MD5|DES|DESede|RC4|SHA-?1|AES/ECB)',
    ),
    (
        "insecure_random",
        "Insecure Random Number Generation",
        "CWE-330",
        "java.util.Random and Math.random() are predictable - use SecureRandom for security-sensitive values",
        r"new\s+Random\s*\(|Math\.random\s*\(",
    ),
    (
        "log_injection",
        "Log Injection",
        "CWE-117",
        "Logging user-controlled request data without CRLF sanitization",
        r"log(ger)?\.\w+\s*\(.*getParameter|log(ger)?\.\w+\s*\(.*getHeader",
    ),
    (
        "xss",
        "Cross-Site Scripting (XSS) Sinks",
        "CWE-79",
        "Output that includes request data without encoding - potential reflected XSS",
        r"\.print(ln)?\s*\(.*get(Parameter|Header|RequestURI)|\.write\s*\(.*get(Parameter|Header|RequestURI)",
    ),
    (
        "el_injection",
        "Expression Language Injection",
        "CWE-917",
        "Spring SpEL or OGNL evaluation with potentially untrusted input - remote code execution",
        r"SpelExpressionParser\s*\(|\.parseExpression\s*\(|OgnlUtil|ValueStack.*findValue|ActionContext.*get\(",
    ),
    (
        "jndi_injection",
        "JNDI Injection",
        "CWE-74",
        "InitialContext.lookup with potential user input - JNDI injection (Log4Shell class)",
        r"InitialContext\s*\(|\.lookup\s*\(.*\+|JndiLookup",
    ),
    (
        "ssrf",
        "Server-Side Request Forgery (SSRF)",
        "CWE-918",
        "URL/HttpURLConnection opened with user-controlled input - may reach internal services",
        r"new\s+URL\s*\(.*get(Parameter|Header|Attribute)|new\s+URL\s*\(.*\+|new\s+URI\s*\(.*get(Parameter|Header|Attribute)",
    ),
    (
        "tls_insecure",
        "Insecure TLS Configuration",
        "CWE-295",
        "Custom TrustManager or HostnameVerifier that accepts all - disables certificate validation",
        r"X509TrustManager|TrustAllCerts|AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted.*return\s*;",
    ),
    (
        "jackson_deserialization",
        "Unsafe Jackson Deserialization",
        "CWE-502",
        "Jackson enableDefaultTyping or @JsonTypeInfo allow polymorphic deserialization - RCE via gadget chains",
        r"enableDefaultTyping\s*\(|@JsonTypeInfo\s*\(.*Id\.(CLASS|MINIMAL_CLASS)|activateDefaultTyping\s*\(",
    ),
    (
        "script_engine_injection",
        "Script Engine Code Injection",
        "CWE-94, CWE-95",
        "ScriptEngine.eval or GroovyShell with user input - arbitrary code execution (RCE)",
        r"ScriptEngine.*\.eval\s*\(|ScriptEngineManager|GroovyShell|GroovyClassLoader|Eval\.me\s*\(",
    ),
    (
        "template_injection",
        "Server-Side Template Injection (SSTI)",
        "CWE-94, CWE-1336",
        "Velocity/FreeMarker/Pebble template engines can execute arbitrary code from user input",
        r"VelocityEngine|Velocity\.evaluate|Velocity\.mergeTemplate|freemarker\.template|Template\.process|PebbleEngine|VelocityContext",
    ),
    (
        "xpath_injection",
        "XPath Injection",
        "CWE-643",
        "XPath expression built with concatenation - can bypass auth or extract XML data",
        r"XPath\.compile\s*\(.*\+|\.evaluate\s*\(.*\+.*get(Parameter|Header|Attribute)|XPath\.compile\s*\(.*get(Parameter|Header|Attribute)",
    ),
    (
        "unsafe_reflection",
        "Unsafe Reflection",
        "CWE-470",
        "Class.forName/getMethod/newInstance with user input - can instantiate arbitrary classes",
        r"Class\.forName\s*\(.*\+|\.forName\s*\(.*get(Parameter|Header|Attribute)|\.newInstance\s*\(.*get(Parameter|Header)",
    ),
    (
        "open_redirect",
        "Unvalidated Redirect",
        "CWE-601",
        "sendRedirect or Location header set from request data without validation - phishing/token theft",
        r'sendRedirect\s*\(.*get(Parameter|Header|Attribute)|setHeader\s*\(\s*"Location".*get(Parameter|Header)',
    ),
    (
        "http_response_splitting",
        "HTTP Response Splitting / CRLF Injection",
        "CWE-113",
        "User input in HTTP response headers without CRLF sanitization - cache poisoning, XSS",
        r"setHeader\s*\(.*get(Parameter|Header|Attribute)|addHeader\s*\(.*get(Parameter|Header)",
    ),
    (
        "nosql_injection",
        "NoSQL Injection",
        "CWE-943",
        "MongoDB query built with string concatenation or $where clause - query manipulation or RCE",
        r'BasicDBObject.*\$where|\.put\s*\(\s*"\$where".*\+|MongoCollection.*find\s*\(.*\+',
    ),
    (
        "yaml_deserialization",
        "Unsafe SnakeYAML Deserialization",
        "CWE-502",
        "SnakeYAML Yaml().load() deserializes arbitrary Java classes - RCE (CVE-2022-1471)",
        r"new\s+Yaml\s*\(\s*\)\.load\s*\(|yaml\.load\s*\(|yaml\.loadAll\s*\(",
    ),
    (
        "zip_slip",
        "Zip Slip / Archive Path Traversal",
        "CWE-22",
        "ZipEntry.getName() used in file path without ../ validation - arbitrary file write",
        r"ZipEntry|ZipInputStream|TarArchiveEntry|JarEntry|ZipFile.*getEntry",
    ),
    (
        "csrf_disabled",
        "CSRF Protection Disabled",
        "CWE-352",
        "Spring Security CSRF explicitly disabled - allows cross-site request forgery attacks",
        r"csrf\(\)\.disable\(\)|csrf\.disable\(\)|\.csrf\(.*disable|AbstractHttpConfigurer::disable",
    ),
    (
        "smtp_header_injection",
        "SMTP / Email Header Injection",
        "CWE-93",
        "User input in email headers without CRLF sanitization - spam injection",
        r"\.setSubject\s*\(.*get(Parameter|Header)|\.addRecipient\s*\(.*get(Parameter|Header)|InternetAddress\s*\(.*get(Parameter|Header)",
    ),
    (
        "hql_injection",
        "HQL / JPQL Injection",
        "CWE-89, CWE-564",
        "Hibernate/JPA createQuery with string concatenation - ORM-level SQL injection",
        r"createQuery\s*\(.*\+|createNativeQuery\s*\(.*\+|createSQLQuery\s*\(.*\+|createFilter\s*\(.*\+",
    ),
    (
        "xml_injection",
        "XML Injection via String Building",
        "CWE-91",
        "XML document built by string concatenation with user input - element injection, SAML bypass",
        r'"<\w+>".*\+.*get(Parameter|Header|Attribute)|StringBuilder.*append.*"<.*>".*get(Parameter|Header)',
    ),
    (
        "mass_assignment",
        "Mass Assignment / Autobinding",
        "CWE-915",
        "Spring @ModelAttribute or BeanUtils without field restrictions - attacker can set isAdmin/role/price",
        r"@ModelAttribute|WebDataBinder|BeanUtils\.copyProperties|BeanUtils\.populate",
    ),
    (
        "unsafe_tls_protocol",
        "Insecure SSL/TLS Protocol Version",
        "CWE-326, CWE-757",
        "Explicitly requesting SSLv3/TLSv1.0/TLSv1.1 - vulnerable to POODLE/BEAST attacks",
        r'SSLContext\.getInstance\s*\(\s*"(SSL|TLSv1|TLSv1\.1)"|setEnabledProtocols.*SSLv3|setEnabledProtocols.*TLSv1[^.]',
    ),
    (
        "redos",
        "Regular Expression Denial of Service (ReDoS)",
        "CWE-1333, CWE-400",
        "Pattern.compile with user-controlled input - catastrophic backtracking causes CPU exhaustion",
        r"Pattern\.compile\s*\(.*get(Parameter|Header|Attribute)|Pattern\.compile\s*\(.*request\.",
    ),
    (
        "spring_actuator_exposed",
        "Exposed Spring Boot Actuator",
        "CWE-200",
        "Actuator endpoints exposed without auth - leaks env vars, credentials, heap dumps",
        r"management\.endpoints\.web\.exposure\.include.*\*|management\.security\.enabled.*false",
    ),
    (
        "trust_boundary_violation",
        "Trust Boundary Violation",
        "CWE-501",
        "Unvalidated user input stored in HttpSession - session poisoning, privilege escalation",
        r"\.setAttribute\s*\(.*get(Parameter|Header|Attribute)|session\.setAttribute\s*\(.*request\.",
    ),
    (
        "file_upload_filename",
        "Tainted Filename from File Upload",
        "CWE-22, CWE-434",
        "getOriginalFilename/getSubmittedFileName used directly in file operations - path traversal, web shell upload",
        r"getOriginalFilename\s*\(|getSubmittedFileName\s*\(",
    ),
]

_CATEGORY_IDS = {cat[0] for cat in _CATEGORIES}


class DangerousFunctionsJavaTool(DangerousFunctionsBase):
    """Scan Java source files for dangerous function patterns."""

    @tool_method(catch=True)
    async def scan_dangerous_functions_java(
        self,
        path: str | None = None,
        categories: list[str] | None = None,
    ) -> str:
        """
        Scan Java source files for dangerous function patterns grouped by
        vulnerability category. Each category targets specific CWEs.

        Available categories: sql_injection, deserialization, xxe,
        command_injection, path_traversal, ldap_injection, weak_crypto,
        insecure_random, log_injection, xss, el_injection, jndi_injection,
        ssrf, tls_insecure, jackson_deserialization,
        script_engine_injection, template_injection, xpath_injection,
        unsafe_reflection, open_redirect, http_response_splitting,
        nosql_injection, yaml_deserialization, zip_slip,
        csrf_disabled, smtp_header_injection, hql_injection,
        xml_injection, mass_assignment, unsafe_tls_protocol,
        redos, spring_actuator_exposed, trust_boundary_violation,
        file_upload_filename.
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
            language="Java",
        )
