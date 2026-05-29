---
name: config-file-parsing-bugs
description: "Exploit config file parser vulnerabilities: line length truncation, duplicate section overwrites, encoding differentials, and fgets()-based C parser bugs. Use when target processes INI/YAML/TOML/properties files, PAM configs, syslog, or any fgets()-based config parser."
---

# Config File Parsing Bugs

Config file parsers silently truncate, silently drop, and silently overwrite. When a security decision depends on parsed config, parser quirks become security bugs.

## Attack Surface

Config file parsers are vulnerable when:
1. **Attacker can inject content** into a config file (admin panel, API, SSRF, file write)
2. **Parser has quirks** that differ from what the consumer expects
3. **Security decisions** depend on parsed values

## Techniques

### 1. Line Length Truncation

C-based parsers using `fgets()` read a fixed number of bytes per line. Excess bytes remain in the input buffer and are read by the NEXT `fgets()` call as a new line.

**inih (C INI parser):** Default `INI_MAX_LINE = 200` bytes.

```ini
[section]
key = AAAA...(195 bytes padding)...\nadmin = true

; Parser sees:
; Line 1 (200 bytes): "key = AAAA...(truncated)"
; Line 2 (remainder): "admin = true"   <-- parsed as legitimate entry
```

**PAM pam_group:** `PAM_GROUP_BUFLEN = 1000` bytes, same pattern.

**BSD syslog (RFC 3164):** 1024-byte message limit. Pad to 1024, inject newline + fake log entry.

**Detection in source code:**
```c
// VULNERABLE: fixed-size fgets with no overflow check
char line[200];
while (fgets(line, sizeof(line), fp) != NULL) {
    parse_line(line);
}
```

### 2. Duplicate Section/Key Overwrite

| Parser | Behavior |
|--------|----------|
| Python `configparser` | Last section wins, last key wins |
| PHP `parse_ini_file()` | Last key wins within section |
| inih (C) | Last key wins |
| Java `Properties.load()` | Last key wins |
| TOML spec | Duplicate keys are errors (but some parsers silently accept) |
| YAML spec | Last key wins (undefined behavior per spec) |

```ini
; Original:
[database]
host = secure-db.internal

; Attacker appends:
[database]
host = attacker-db.evil.com
; Result: app connects to attacker-db.evil.com
```

### 3. PHP parse_ini_file() Quirks

```ini
; INI_SCANNER_NORMAL treats unquoted ; as comment start
password = s3cret;drop_this
; Parsed value: "s3cret"  (everything after ; silently dropped)
```

`INI_SCANNER_NORMAL` interprets `true/false/null/none` as types -- potential type juggling if app uses loose comparison.

### 4. Whitespace and Encoding Differentials

**Line endings:** `\r\n` vs `\n` -- Linux parser may include `\r` in the value.

**Unicode whitespace:** U+00A0 (non-breaking space), U+200B (zero-width space) -- some parsers treat as part of the value, others as whitespace.

**YAML tabs:** YAML forbids tabs for indentation but some parsers accept them. Tab width differences can change nesting level.

### 5. Environment Variable Interpolation

```ini
; systemd: Environment="SECRET=%H-secret"  ; %H expands to hostname
; Docker .env: DB_URL=postgres://${DB_HOST}:5432/app
; Shell: source /etc/default/myapp
```

If you can set an environment variable (via SSRF to cloud metadata, another injection), the expanded value in config may differ from what was validated.

## Detection Checklist

1. Identify all config file parsers in the codebase
2. Determine buffer sizes for C-based parsers (`grep -r 'fgets\|MAX_LINE\|BUF.*LEN'`)
3. Check if overlong line errors are handled or silently ignored
4. Test duplicate section/key behavior empirically
5. Identify injection vectors: can attacker influence config file content?
6. Verify: does a security decision depend on a parsed config value?

## Related Skills

- **parser-differential-bypass** -- Parsing differentials between processing layers
- **insecure-defaults** -- When config defaults are insecure
- **write-path-to-rce** -- When config injection enables arbitrary file write
- **apache-confusion-attacks** -- Apache httpd config parsing ambiguities
