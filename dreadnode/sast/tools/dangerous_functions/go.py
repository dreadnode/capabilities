"""Go dangerous function scanner."""

from dreadnode.agents.tools import tool_method

from . import CategoryList, DangerousFunctionsBase

_FILE_GLOB = "*.go"

_CATEGORIES: CategoryList = [
    (
        "sql_injection",
        "SQL Injection",
        "CWE-89",
        "fmt.Sprintf building SQL or Query/Exec with string concatenation (gosec G201/G202)",
        r'fmt\.Sprintf\s*\(.*"(SELECT|INSERT|UPDATE|DELETE)\b|\.(Query|QueryRow|Exec)\s*\(.*\+',
    ),
    (
        "command_injection",
        "Command Injection via Shell",
        "CWE-78",
        "exec.Command invoking a shell interpreter - arguments are shell-evaluated (gosec G204)",
        r'exec\.Command\s*\(\s*"(sh|bash|/bin/sh|/bin/bash|cmd)"',
    ),
    (
        "path_traversal",
        "Path Traversal",
        "CWE-22",
        "File or path operation with string concatenation - check for ../ sanitization (gosec G304)",
        r"os\.(Open|ReadFile|ReadDir)\s*\(.*\+|filepath\.Join\s*\(.*\+",
    ),
    (
        "xss_template",
        "XSS / Unsafe Template Usage",
        "CWE-79",
        "text/template has no auto-escaping; template.HTML/JS/URL bypass html/template escaping (gosec G203)",
        r'"text/template"|template\.HTML\s*\(|template\.JS\s*\(|template\.URL\s*\(',
    ),
    (
        "weak_crypto",
        "Weak Cryptography Import",
        "CWE-327",
        "Importing broken crypto packages - MD5, SHA-1, DES, RC4 (gosec G401/G501-G505)",
        r'"crypto/md5"|"crypto/sha1"|"crypto/des"|"crypto/rc4"',
    ),
    (
        "insecure_random",
        "Insecure Random Number Generation",
        "CWE-338",
        "math/rand is predictable - use crypto/rand for security-sensitive values (gosec G404)",
        r'"math/rand"',
    ),
    (
        "unsafe_usage",
        "Unsafe Package Usage",
        "CWE-242",
        "unsafe bypasses Go type safety and can cause memory corruption (gosec G103)",
        r'"unsafe"|unsafe\.Pointer|unsafe\.Sizeof|unsafe\.Offsetof',
    ),
    (
        "tls_insecure",
        "Insecure TLS / SSH Configuration",
        "CWE-295",
        "TLS certificate verification or SSH host key checking disabled (gosec G402/G106)",
        r"InsecureSkipVerify\s*:\s*true|InsecureIgnoreHostKey",
    ),
    (
        "file_permissions",
        "Overly Permissive File Permissions",
        "CWE-276",
        "World-writable file or directory creation (gosec G301/G302/G306)",
        r"os\.(Mkdir|MkdirAll|WriteFile|OpenFile|Chmod)\s*\(.*0[o]?(777|776|766|667|666)",
    ),
    (
        "http_no_timeout",
        "HTTP Server Without Timeouts",
        "CWE-400",
        "http.ListenAndServe without configured timeouts - vulnerable to Slowloris DoS (gosec G112/G114)",
        r"http\.ListenAndServe\s*\(|http\.ListenAndServeTLS\s*\(",
    ),
    (
        "ssrf",
        "Server-Side Request Forgery (SSRF)",
        "CWE-918",
        "HTTP GET/POST with variable URL - verify URL is not user-controlled (gosec G107)",
        r"http\.(Get|Post|Head|PostForm)\s*\(\s*[a-zA-Z_]\w*",
    ),
    (
        "pprof_exposed",
        "Exposed pprof Endpoint",
        "CWE-200",
        "net/http/pprof import exposes debug endpoints in production (gosec G108)",
        r'"net/http/pprof"',
    ),
    (
        "decompression_bomb",
        "Decompression Bomb",
        "CWE-409",
        "io.Copy from compressed reader without size limit - zip/gzip bomb risk (gosec G110)",
        r"io\.Copy\s*\(.*gzip\.|io\.Copy\s*\(.*zlib\.|io\.Copy\s*\(.*flate\.",
    ),
    (
        "bind_all_interfaces",
        "Bind to All Interfaces",
        "CWE-200",
        "Listening on 0.0.0.0 - exposes service on all network interfaces (gosec G102)",
        r'net\.Listen\s*\(.*"0\.0\.0\.0|":0\.0\.0\.0',
    ),
    (
        "embedded_credentials",
        "Hardcoded Credentials",
        "CWE-798",
        "Potential hardcoded passwords or API keys in variable assignments (gosec G101)",
        r'(?i)(password|passwd|secret|apikey|api_key|token)\s*[:=]\s*"[^"]{8,}"',
    ),
    (
        "zip_slip_archive",
        "Zip Slip Archive Extraction",
        "CWE-22",
        "Archive extraction without path validation - ../ in member names writes outside target dir (gosec G305)",
        r'"archive/zip"|"archive/tar"|tar\.NewReader',
    ),
    (
        "integer_overflow",
        "Integer Overflow on Type Conversion",
        "CWE-190",
        "strconv.Atoi result cast to smaller int type - silent truncation (gosec G109/G115)",
        r"int(8|16|32)\s*\(\s*(strconv\.Atoi|strconv\.ParseInt|strconv\.ParseUint)|uint(8|16|32)\s*\(",
    ),
    (
        "directory_listing",
        "HTTP Directory Listing Exposure",
        "CWE-548",
        "http.FileServer(http.Dir(...)) serves all files including .git/.env (gosec G111)",
        r"http\.FileServer\s*\(\s*http\.Dir\s*\(",
    ),
    (
        "weak_tls_version",
        "Weak TLS Version Configuration",
        "CWE-327",
        "TLS 1.0/1.1 explicitly set - deprecated by IETF RFC 8996, vulnerable to BEAST/POODLE",
        r"VersionTLS10|VersionTLS11|MinVersion\s*:\s*0x030[01]",
    ),
    (
        "weak_rsa_key",
        "Weak RSA Key Size",
        "CWE-326",
        "rsa.GenerateKey with key size < 2048 bits - practically breakable (gosec G403)",
        r"rsa\.GenerateKey\s*\([^,]+,\s*(512|768|1024)\b",
    ),
    (
        "gob_decode_untrusted",
        "Unsafe Gob/XML Deserialization",
        "CWE-502",
        "gob.NewDecoder can cause stack exhaustion (CVE-2024-34156); xml/yaml unmarshalling has parser differential issues",
        r"gob\.NewDecoder|gob\.Decode|xml\.NewDecoder|xml\.Unmarshal|yaml\.Unmarshal|yaml\.NewDecoder",
    ),
    (
        "predictable_temp_file",
        "Predictable Temporary File Creation",
        "CWE-377",
        "os.Create in TempDir with predictable name instead of os.CreateTemp - symlink race (gosec G303)",
        r'os\.Create\s*\(\s*(os\.TempDir|"/tmp/"|"/var/tmp/")',
    ),
    (
        "open_redirect",
        "Open Redirect",
        "CWE-601",
        "http.Redirect using URL from user input without validation - phishing/token theft",
        r"http\.Redirect\s*\(.*r\.(URL|Form|PostForm)|http\.Redirect\s*\(.*r\.Header",
    ),
    (
        "cgi_import",
        "Dangerous CGI Import",
        "CWE-94",
        "net/http/cgi and net/http/fcgi have multiple CVEs - on gosec import blocklist (G504)",
        r'"net/http/cgi"|"net/http/fcgi"',
    ),
    (
        "error_not_checked",
        "Unchecked Error on Close/Write",
        "CWE-391",
        "defer Close() without checking error - data loss or incomplete crypto operations (gosec G104/G307)",
        r"defer\s+\w+\.Close\s*\(\)|defer\s+\w+\.Flush\s*\(\)",
    ),
    (
        "struct_tag_misconfiguration",
        "Struct Tag Misconfiguration",
        "CWE-913",
        'json:"-," creates field named "-" instead of excluding; json:"omitempty" names field "omitempty"',
        r'json:"-,|json:"omitempty"|yaml:"-,|yaml:"omitempty"',
    ),
    (
        "cors_wildcard",
        "CORS Wildcard or Reflected Origin",
        "CWE-942",
        "Access-Control-Allow-Origin: * or AllowAllOrigins enables cross-origin data theft",
        r'Access-Control-Allow-Origin.*"\*"|AllowAllOrigins\s*:\s*true|AllowOrigins.*"\*"',
    ),
    (
        "http_header_injection",
        "HTTP Header Injection",
        "CWE-113",
        "Setting response headers from user-controlled values without CRLF sanitization",
        r"w\.Header\(\)\.Set\s*\(.*r\.(URL|Form|PostForm|Header)|http\.SetCookie\s*\(.*r\.(URL|Form)",
    ),
    (
        "lookpath_injection",
        "PATH Injection via exec.LookPath",
        "CWE-426",
        "exec.LookPath resolves commands from untrusted PATH locations - 7 related CVEs",
        r"exec\.LookPath\s*\(",
    ),
    (
        "weak_cipher_suite",
        "Weak TLS Cipher Suite",
        "CWE-326",
        "Explicitly configuring deprecated cipher suites - RSA key exchange, 3DES, RC4, CBC mode",
        r"tls\.TLS_RSA_|tls\.TLS_ECDHE_.*_CBC_|TLS_RSA_WITH_3DES|TLS_RSA_WITH_RC4",
    ),
    (
        "missing_disallow_unknown_fields",
        "JSON Decoder Accepts Unknown Fields",
        "CWE-20",
        "json.NewDecoder without DisallowUnknownFields - mass assignment via extra fields (CVE-2020-16250)",
        r"json\.NewDecoder\s*\(|json\.Unmarshal\s*\(",
    ),
]

_CATEGORY_IDS = {cat[0] for cat in _CATEGORIES}


class DangerousFunctionsGoTool(DangerousFunctionsBase):
    """Scan Go source files for dangerous function patterns."""

    @tool_method(catch=True)
    async def scan_dangerous_functions_go(
        self,
        path: str | None = None,
        categories: list[str] | None = None,
    ) -> str:
        """
        Scan Go source files for dangerous function patterns grouped by
        vulnerability category. Each category targets specific CWEs and
        maps to gosec rules where applicable.

        Available categories: sql_injection, command_injection, path_traversal,
        xss_template, weak_crypto, insecure_random, unsafe_usage, tls_insecure,
        file_permissions, http_no_timeout, ssrf, pprof_exposed,
        decompression_bomb, bind_all_interfaces, embedded_credentials,
        zip_slip_archive, integer_overflow, directory_listing,
        weak_tls_version, weak_rsa_key, gob_decode_untrusted,
        predictable_temp_file, open_redirect, cgi_import,
        error_not_checked, struct_tag_misconfiguration,
        cors_wildcard, http_header_injection, lookpath_injection,
        weak_cipher_suite, missing_disallow_unknown_fields.
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
            language="Go",
        )
