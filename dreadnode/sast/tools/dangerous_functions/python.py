"""Python dangerous function scanner."""

from dreadnode.agents.tools import tool_method

from . import CategoryList, DangerousFunctionsBase

_FILE_GLOB = "*.py"

_CATEGORIES: CategoryList = [
    (
        "code_injection",
        "Code Injection (eval/exec)",
        "CWE-94",
        "eval, exec, or compile with potentially untrusted input - arbitrary code execution (Bandit B102/B307)",
        r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(",
    ),
    (
        "sql_injection",
        "SQL Injection",
        "CWE-89",
        "SQL query built with string concatenation, %-formatting, or f-strings (Bandit B608)",
        r"\.execute\s*\(.*[+%]|f[\"'](SELECT|INSERT|UPDATE|DELETE)",
    ),
    (
        "command_injection",
        "Command Injection",
        "CWE-78",
        "os.system, os.popen, or subprocess with shell=True (Bandit B602/B605)",
        r"os\.system\s*\(|os\.popen\s*\(|subprocess.*shell\s*=\s*True",
    ),
    (
        "deserialization",
        "Insecure Deserialization (pickle/marshal)",
        "CWE-502",
        "pickle, cPickle, marshal, or shelve deserializing potentially untrusted data (Bandit B301/B302)",
        r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(|marshal\.loads?\s*\(|shelve\.open\s*\(",
    ),
    (
        "yaml_deserialization",
        "Unsafe YAML Loading",
        "CWE-502",
        "yaml.load without SafeLoader or yaml.unsafe_load - can execute arbitrary Python (Bandit B506)",
        r"yaml\.load\s*\(|yaml\.unsafe_load\s*\(|yaml\.full_load\s*\(",
    ),
    (
        "ssti",
        "Server-Side Template Injection",
        "CWE-1336",
        "render_template_string, Jinja2 autoescape disabled, or template built from user input (Bandit B701)",
        r"render_template_string\s*\(|autoescape\s*=\s*False|\.from_string\s*\(",
    ),
    (
        "weak_crypto",
        "Weak Cryptographic Hash",
        "CWE-327",
        "MD5 or SHA-1 usage - broken for security purposes (Bandit B303/B324)",
        r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(",
    ),
    (
        "insecure_random",
        "Insecure Random Number Generation",
        "CWE-330",
        "random module is predictable - use secrets or os.urandom for security-sensitive values (Bandit B311)",
        r"\brandom\.(random|randint|choice|choices|sample|uniform)\s*\(",
    ),
    (
        "tls_insecure",
        "Insecure TLS / Certificate Verification Disabled",
        "CWE-295",
        "Certificate verification disabled or weak SSL context (Bandit B501/B502)",
        r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False",
    ),
    (
        "xxe",
        "XML External Entity (XXE)",
        "CWE-611",
        "Stdlib or lxml XML parsers without defusedxml - may process external entities (Bandit B313-B320)",
        r"xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax\b|lxml\.etree",
    ),
    (
        "extended_deserialization",
        "Insecure Deserialization (Extended)",
        "CWE-502",
        "torch.load, joblib.load, dill.load, jsonpickle - arbitrary code execution via crafted payloads",
        r"torch\.load\s*\(|joblib\.load\s*\(|dill\.loads?\s*\(|jsonpickle\.decode\s*\(",
    ),
    (
        "tarfile_path_traversal",
        "Tarfile Path Traversal",
        "CWE-22",
        "tarfile.extractall or tarfile.extract without filtering - path traversal via ../ in archive (Bandit B202)",
        r"\.extractall\s*\(|\.extract\s*\(",
    ),
    (
        "django_sql_injection",
        "Django Raw SQL / extra()",
        "CWE-89",
        "Django ORM .raw() or .extra() with string interpolation - SQL injection bypass (Bandit B610/B611)",
        r"\.raw\s*\(|\.extra\s*\(",
    ),
    (
        "ssh_no_host_key",
        "SSH No Host Key Verification",
        "CWE-295",
        "Paramiko AutoAddPolicy or RejectPolicy bypassed - MITM risk (Bandit B507)",
        r"AutoAddPolicy\s*\(|set_missing_host_key_policy\s*\(",
    ),
    (
        "weak_cipher",
        "Weak Symmetric Cipher",
        "CWE-327",
        "DES, RC4, Blowfish, or other broken ciphers via PyCrypto/PyCryptodome/cryptography (Bandit B304/B305)",
        r"DES\.new\s*\(|ARC4\.new\s*\(|Blowfish\.new\s*\(|algorithms\.TripleDES\b|algorithms\.ARC4\b",
    ),
    (
        "zipfile_path_traversal",
        "Zipfile Path Traversal (Zip Slip)",
        "CWE-22",
        "ZipFile.extractall/shutil.unpack_archive can write outside target dir via ../ in member names",
        r"ZipFile\s*\(.*\.extractall\s*\(|shutil\.unpack_archive\s*\(",
    ),
    (
        "flask_debug",
        "Flask Debug Mode in Production",
        "CWE-94",
        "Flask debug=True enables Werkzeug interactive debugger - arbitrary code execution (Bandit B201)",
        r"\.run\s*\(.*debug\s*=\s*True|FLASK_DEBUG\s*=\s*[\"']?1",
    ),
    (
        "mako_template_xss",
        "Mako Template XSS",
        "CWE-79",
        "Mako templates have no auto-escaping - all input must be manually escaped with |h (Bandit B702)",
        r"from\s+mako\b|import\s+mako\b|MakoTemplates\s*\(",
    ),
    (
        "django_xss_mark_safe",
        "Django/MarkupSafe XSS via mark_safe",
        "CWE-79, CWE-80",
        "mark_safe()/Markup() bypasses Django/Jinja2 auto-escaping - XSS if user input is marked safe (Bandit B703/B308)",
        r"mark_safe\s*\(|markupsafe\.Markup\s*\(|Markup\s*\(\s*f[\"']",
    ),
    (
        "insecure_tempfile",
        "Insecure Temporary File Creation",
        "CWE-377",
        "tempfile.mktemp/os.tempnam create predictable names - TOCTOU race with symlink attacks (Bandit B306/B325)",
        r"tempfile\.mktemp\s*\(|os\.tempnam\s*\(|os\.tmpnam\s*\(",
    ),
    (
        "logging_config_rce",
        "Logging Config Code Execution",
        "CWE-94",
        "logging.config.listen() accepts configs over socket with eval() - local code execution (Bandit B612)",
        r"logging\.config\.listen\s*\(",
    ),
    (
        "ssl_bad_protocol",
        "Insecure SSL/TLS Protocol Version",
        "CWE-327",
        "Deprecated SSL/TLS versions (SSLv2/SSLv3/TLSv1/TLSv1.1) - POODLE/BEAST attacks (Bandit B502/B503)",
        r"PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1\b|SSLv2_METHOD|SSLv3_METHOD|SSLv23_METHOD|TLSv1_METHOD",
    ),
    (
        "weak_key_size",
        "Weak Cryptographic Key Size",
        "CWE-326",
        "RSA/DSA key < 2048 bits is practically breakable (Bandit B505)",
        r"generate_private_key\s*\(.*key_size\s*=\s*(512|768|1024)|RSA\.generate\s*\(\s*(512|768|1024)|DSA\.generate\s*\(\s*(512|768|1024)",
    ),
    (
        "ecb_cipher_mode",
        "ECB Cipher Mode",
        "CWE-327",
        "ECB mode leaks plaintext patterns - identical blocks produce identical ciphertext (Bandit B305)",
        r"modes\.ECB\s*\(|AES\.MODE_ECB|mode\s*=\s*AES\.MODE_ECB|DES3\.MODE_ECB",
    ),
    (
        "insecure_file_permissions",
        "Insecure File Permissions",
        "CWE-732",
        "World-writable/executable file creation via os.chmod/os.makedirs (Bandit B103)",
        r"os\.chmod\s*\(.*0o?7[67][67]|os\.fchmod\s*\(.*0o?7[67][67]|os\.makedirs\s*\(.*0o?777",
    ),
    (
        "telnetlib_ftp",
        "Unencrypted Protocol Usage (Telnet/FTP)",
        "CWE-319",
        "telnetlib/ftplib transmit credentials in cleartext - trivially interceptable (Bandit B312/B321/B401/B402)",
        r"import\s+telnetlib|from\s+telnetlib|import\s+ftplib|from\s+ftplib",
    ),
    (
        "xpath_injection",
        "XPath Injection",
        "CWE-643",
        "XPath query built with string concatenation - can bypass auth or extract XML data (CVSS 9.8)",
        r"\.xpath\s*\(.*[+%]|\.xpath\s*\(\s*f[\"']|\.find\s*\(.*[+%].*\)|\.findall\s*\(.*[+%]",
    ),
    (
        "format_string_vuln",
        "User-Controlled Format String",
        "CWE-134",
        "str.format() allows accessing __globals__/__init__/__class__ - leaks secrets from namespace",
        r"\.format\s*\(.*request|\.format_map\s*\(",
    ),
    (
        "paramiko_injection",
        "Paramiko Shell Injection",
        "CWE-78",
        "exec_command/invoke_shell executes commands on remote host via SSH - lateral movement (Bandit B601)",
        r"\.exec_command\s*\(|\.invoke_shell\s*\(",
    ),
    (
        "xmlrpc_usage",
        "XML-RPC Usage (Deserialization/XXE Risk)",
        "CWE-502, CWE-611",
        "xmlrpc module is vulnerable to XXE and exposes internal functions remotely (Bandit B411)",
        r"import\s+xmlrpc|from\s+xmlrpc|SimpleXMLRPCServer",
    ),
    (
        "request_without_timeout",
        "HTTP Request Without Timeout",
        "CWE-400",
        "requests.get/post without timeout can hang indefinitely - resource exhaustion DoS (Bandit B113)",
        r"requests\.(get|post|put|delete|patch|head|options)\s*\([^)]*\)(?!.*timeout)",
    ),
    (
        "mass_assignment_setattr",
        "Mass Assignment via setattr",
        "CWE-915",
        "setattr() with user-controlled attribute names allows modifying __class__/__dict__/methods",
        r"setattr\s*\(.*request\.|setattr\s*\(.*\bdata\b",
    ),
    (
        "huggingface_unsafe_load",
        "Unsafe ML Model Download/Loading",
        "CWE-502",
        "Downloading/loading ML models without integrity checks - supply chain RCE via pickled weights (Bandit B614/B615)",
        r"from_pretrained\s*\(|snapshot_download\s*\(|hf_hub_download\s*\(",
    ),
    (
        "cors_misconfiguration",
        "Permissive CORS Configuration",
        "CWE-942",
        "CORS_ALLOW_ALL_ORIGINS=True or allow_origins=['*'] enables cross-origin data theft",
        r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[.*\*.*\]",
    ),
]

_CATEGORY_IDS = {cat[0] for cat in _CATEGORIES}


class DangerousFunctionsPythonTool(DangerousFunctionsBase):
    """Scan Python source files for dangerous function patterns."""

    @tool_method(catch=True)
    async def scan_dangerous_functions_python(
        self,
        path: str | None = None,
        categories: list[str] | None = None,
    ) -> str:
        """
        Scan Python source files for dangerous function patterns grouped by
        vulnerability category. Each category targets specific CWEs and
        maps to Bandit rules where applicable.

        Available categories: code_injection, sql_injection, command_injection,
        deserialization, yaml_deserialization, ssti, weak_crypto,
        insecure_random, tls_insecure, xxe, extended_deserialization,
        tarfile_path_traversal, django_sql_injection, ssh_no_host_key,
        weak_cipher, zipfile_path_traversal, flask_debug,
        mako_template_xss, django_xss_mark_safe, insecure_tempfile,
        logging_config_rce, ssl_bad_protocol, weak_key_size,
        ecb_cipher_mode, insecure_file_permissions, telnetlib_ftp,
        xpath_injection, format_string_vuln, paramiko_injection,
        xmlrpc_usage, request_without_timeout, mass_assignment_setattr,
        huggingface_unsafe_load, cors_misconfiguration.
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
            language="Python",
        )
