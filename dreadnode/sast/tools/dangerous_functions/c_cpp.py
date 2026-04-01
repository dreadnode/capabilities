"""C/C++ dangerous function scanner."""

from dreadnode.agents.tools import tool_method

from . import CategoryList, DangerousFunctionsBase

_FILE_GLOB = "*.{c,cpp,h,hpp,cc,cxx,hxx}"

_CATEGORIES: CategoryList = [
    (
        "string_manipulation",
        "No Bounds Checking String Functions",
        "CWE-120, CWE-676",
        "Banned string functions with no destination size check - strcpy, strcat, sprintf, vsprintf, gets, strncpy, strncat",
        r"\b(strcpy|strcat|sprintf|vsprintf|gets|strncpy|strncat)\s*\(",
    ),
    (
        "format_string",
        "Format String Vulnerability",
        "CWE-134",
        "printf-family call with a variable (not string literal) as format argument",
        r"\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*[a-zA-Z_]\w*\s*[,)]",
    ),
    (
        "memory_management",
        "Unsafe realloc Self-Assignment",
        "CWE-416, CWE-415",
        "realloc result assigned back to the same pointer - leaks original on failure",
        r"\b(\w+)\s*=\s*realloc\s*\(\s*\1\s*,",
    ),
    (
        "unsafe_int_conversion",
        "Unsafe Integer Conversion",
        "CWE-190, CWE-676",
        "ato* functions with no error detection or overflow check",
        r"\b(atoi|atol|atoll|atof)\s*\(",
    ),
    (
        "command_injection",
        "Command Injection Sink",
        "CWE-78",
        "Shell command execution functions - system, popen, execlp, execvp",
        r"\b(system|popen|_popen|execlp|execvp)\s*\(",
    ),
    (
        "file_operations",
        "TOCTOU / Insecure Temp Files",
        "CWE-367, CWE-22",
        "access() check-before-use, insecure temp file creation",
        r"\b(access|mktemp|tmpnam|tempnam)\s*\(",
    ),
    (
        "thread_unsafe",
        "Thread-Unsafe Functions",
        "CWE-362, CWE-676",
        "Functions returning static buffers or using static state - banned by Git",
        r"\b(gmtime|localtime|ctime|asctime|strtok)\s*\(",
    ),
    (
        "weak_rng",
        "Weak Random Number Generation",
        "CWE-330",
        "Predictable PRNG - rand/srand are not cryptographically secure",
        r"\b(rand|srand)\s*\(",
    ),
    (
        "scanf_unbounded",
        "Unbounded scanf %s",
        "CWE-120",
        "scanf with %s and no field width - unbounded string read into buffer",
        r'\bscanf\s*\([^)]*"%[^"]*[^0-9]s"',
    ),
    (
        "cpp_new_delete",
        "Potential new[]/delete Mismatch",
        "CWE-762",
        "new[] allocation that may be freed with scalar delete (or vice versa)",
        r"\bnew\s+\w+\s*\[|delete\s+[a-zA-Z_]\w*\s*;",
    ),
    (
        "unsafe_memops",
        "Unchecked Memory Operations",
        "CWE-120, CWE-805",
        "memcpy/memmove with potentially unchecked size - verify length is validated",
        r"\b(memcpy|memmove|wmemcpy|wmemmove)\s*\(",
    ),
    (
        "weak_crypto",
        "Weak Cryptography",
        "CWE-327, CWE-328",
        "Deprecated crypto algorithms - DES, RC4, MD5, SHA-1 via OpenSSL or similar",
        r"\b(EVP_des_|EVP_rc4|EVP_md5|EVP_sha1|MD5_Init|SHA1_Init|DES_set_key)\b",
    ),
    (
        "env_trust",
        "Untrusted Environment Variable",
        "CWE-426, CWE-78",
        "getenv() value used without validation - may be attacker-controlled",
        r"\bgetenv\s*\(",
    ),
    (
        "unsafe_library_load",
        "Dynamic Library Loading",
        "CWE-426",
        "dlopen/LoadLibrary with potentially attacker-controlled path - DLL/SO hijacking risk",
        r"\b(dlopen|LoadLibrary|LoadLibraryEx)\s*\(",
    ),
    (
        "signal_handler",
        "Non-Trivial Signal Handler",
        "CWE-479",
        "signal() with custom handler - only async-signal-safe functions allowed inside handlers",
        r"\bsignal\s*\(\s*SIG\w+\s*,\s*(?!SIG_IGN|SIG_DFL)\w+\s*\)",
    ),
    (
        "stack_alloc",
        "Stack-Based Dynamic Allocation",
        "CWE-121, CWE-770",
        "alloca() allocates on stack with no bounds checking - stack overflow if size is attacker-controlled (banned by MS SDL)",
        r"\b(alloca|_alloca)\s*\(",
    ),
    (
        "toctou_file_perm",
        "TOCTOU Race on File Metadata",
        "CWE-362, CWE-367",
        "chown/chmod/chgrp operate on pathnames - vulnerable to symlink TOCTOU attacks in setuid programs",
        r"\b(chown|chmod|chgrp|readlink)\s*\(",
    ),
    (
        "unsafe_path_ops",
        "Unsafe Path Construction",
        "CWE-120, CWE-785",
        "realpath/getwd can overflow buffers - multiple CVEs (CVE-2003-0466, CVE-2018-1000001)",
        r"\b(realpath|getwd|_splitpath|_makepath)\s*\(",
    ),
    (
        "unsafe_crypt",
        "Obsolete Password Hashing",
        "CWE-327, CWE-916",
        "crypt() uses DES by default (8-char limit, trivially brute-forced)",
        r"\b(crypt|crypt_r)\s*\(",
    ),
    (
        "unsafe_user_identity",
        "Spoofable User Identity Functions",
        "CWE-807, CWE-676",
        "getlogin() is spoofable (relies on utmp), cuserid() has buffer overflow risk",
        r"\b(getlogin|cuserid|getpw)\s*\(",
    ),
    (
        "win_command_exec",
        "Windows Shell Execution",
        "CWE-78",
        "Windows command execution - CreateProcess has unquoted path vulnerability (CWE-428)",
        r"\b(WinExec|ShellExecute|ShellExecuteEx|CreateProcess|CreateProcessAsUser|CreateProcessWithLogon)\s*\(",
    ),
    (
        "win_acl_miscfg",
        "Windows ACL Misconfiguration",
        "CWE-732",
        "SetSecurityDescriptorDacl with NULL DACL grants Everyone full access",
        r"\b(SetSecurityDescriptorDacl|AddAccessAllowedAce)\s*\(",
    ),
    (
        "unsafe_str_ext",
        "Extended Buffer Overflow String Functions",
        "CWE-120, CWE-676",
        "streadd/strecpy/strtrns have no buffer overflow protection",
        r"\b(streadd|strecpy|strtrns)\s*\(",
    ),
    (
        "setjmp_longjmp",
        "Unsafe Non-Local Jump",
        "CWE-676, CWE-362",
        "setjmp/longjmp bypass C++ destructors and can be exploited via corrupted jmp_buf (CERT ERR52-CPP)",
        r"\b(setjmp|longjmp|sigsetjmp|siglongjmp|_setjmp|_longjmp)\s*\(",
    ),
    (
        "multibyte_conversion",
        "Multibyte/Wide Character Conversion Overflow",
        "CWE-120, CWE-805",
        "Byte/character size confusion in wctomb/wcstombs/MultiByteToWideChar leads to undersized buffers",
        r"\b(wctomb|wcrtomb|wcstombs|wcsrtombs|MultiByteToWideChar|WideCharToMultiByte)\s*\(",
    ),
    (
        "unsafe_getpass",
        "Obsolete Password Input",
        "CWE-676, CWE-120",
        "getpass() has fixed buffer size and leaves plaintext password in static memory",
        r"\bgetpass\s*\(",
    ),
    (
        "privilege_management",
        "Unsafe Privilege Drop/Escalation",
        "CWE-269, CWE-273",
        "seteuid/setreuid/setresuid - wrong order or unchecked return causes failed privilege drop (CERT POS36-C/POS37-C)",
        r"\b(seteuid|setreuid|setresuid|setegid|setregid|setresgid)\s*\(",
    ),
    (
        "unsafe_chroot",
        "Insecure chroot Jail",
        "CWE-243, CWE-22",
        "chroot() without chdir, privilege drop, or proper setup allows jail escape",
        r"\bchroot\s*\(",
    ),
    (
        "unsafe_cast_cpp",
        "Dangerous C++ Type Cast",
        "CWE-843, CWE-704",
        "reinterpret_cast bypasses type safety (type confusion); const_cast can cause UB on truly const objects",
        r"\b(reinterpret_cast|const_cast)\s*<",
    ),
    (
        "isbad_ptr",
        "Deprecated Pointer Validation (Windows)",
        "CWE-676",
        "IsBadReadPtr/IsBadWritePtr consume guard pages and mask real memory bugs - banned by MS SDL",
        r"\b(IsBadWritePtr|IsBadReadPtr|IsBadCodePtr|IsBadStringPtr)\s*\(",
    ),
    (
        "numeric_itoa",
        "Unsafe Integer-to-String Conversion",
        "CWE-120, CWE-676",
        "_itoa/_ltoa family do not check output buffer length - banned by MS SDL",
        r"\b(_itoa|_itow|_i64toa|_i64tow|_ui64toa|_ui64tow|_ultoa|_ultow|_ltoa|_ltow)\s*\(",
    ),
    (
        "win_temp_file",
        "Windows Insecure Temp File",
        "CWE-377, CWE-362",
        "GetTempFileName creates predictable temp file name - race condition with symlink attacks",
        r"\bGetTempFileName\s*\(",
    ),
    (
        "null_dacl_security",
        "NULL Security Descriptor Initialization",
        "CWE-732",
        "InitializeSecurityDescriptor may be configured with NULL DACL - world-accessible permissions",
        r"\bInitializeSecurityDescriptor\s*\(",
    ),
    (
        "unsafe_input_funcs",
        "Unchecked External Input in Loop",
        "CWE-20, CWE-120",
        "getchar/fgetc in while loop filling buffer without bounds check",
        r"\b(getchar|fgetc|getc)\s*\(\s*\).*while\b|while\b.*\b(getchar|fgetc|getc)\s*\(\s*\)",
    ),
]

_CATEGORY_IDS = {cat[0] for cat in _CATEGORIES}


class DangerousFunctionsCCppTool(DangerousFunctionsBase):
    """Scan C/C++ source files for dangerous function patterns."""

    @tool_method(catch=True)
    async def scan_dangerous_functions_c_cplusplus(
        self,
        path: str | None = None,
        categories: list[str] | None = None,
    ) -> str:
        """
        Scan C/C++ source files for dangerous function patterns grouped by
        vulnerability category. Each category targets specific CWEs.

        Available categories: string_manipulation, format_string,
        memory_management, unsafe_int_conversion, command_injection,
        file_operations, thread_unsafe, weak_rng, scanf_unbounded,
        cpp_new_delete, unsafe_memops, weak_crypto, env_trust,
        unsafe_library_load, signal_handler, stack_alloc,
        toctou_file_perm, unsafe_path_ops, unsafe_crypt,
        unsafe_user_identity, win_command_exec, win_acl_miscfg,
        unsafe_str_ext, setjmp_longjmp, multibyte_conversion,
        unsafe_getpass, privilege_management, unsafe_chroot,
        unsafe_cast_cpp, isbad_ptr, numeric_itoa, win_temp_file,
        null_dacl_security, unsafe_input_funcs.
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
            language="C/C++",
        )
