# Mirrored Reference Sources

Snapshots of external reference material the skill cites. Cached locally so the agent can `grep` instead of pulling 30k words per session. **Each mirror is a point-in-time snapshot** — the upstream is authoritative; refresh with `firecrawl scrape` when needed.

Snapshot date for all entries below: **2026-05-12**.

## Mirroring policy

Mirrored in-tree only when **(a)** the upstream license permits redistribution (Microsoft Learn, Apple ABI, Linux man-pages, Corkami CC-BY) or **(b)** the upstream explicitly invites attribution-with-backlink reuse (Unprotect Project). Index-only mirrors are kept for personal blogs with no declared license (Hasherezade, Objective-See, OALabs) — full posts are cited by URL and fetched on demand. Sources without an explicit redistribution license (Check Point Anti-Debug Encyclopedia, ired.team, al-khaser source) are cited by URL only.

## Refresh recipe

```bash
firecrawl scrape "<url>" --only-main-content -o references/external/<source>/<slug>.md
```

The original scrape script lived in the working tree at the time of the first snapshot. Re-run per-source as content drifts.

---

## Mirrored in-tree

### unprotect/

- **Name:** Unprotect Project
- **URL:** https://unprotect.it/
- **Authors:** Thomas Roccia and Unprotect Project contributors
- **License posture:** Community-maintained malware-evasion catalog. Per-technique snippets carry attribution to their original authors; the catalog itself is openly published with backlinks expected. Each mirrored file preserves the upstream's Technique Identifier and links back to the canonical URL.
- **Files:** 70 (anti-debug, packer, anti-VM techniques)
- **Volume:** 3,775 lines

### formats/

- **ms-pe-format.md** — Microsoft PE/COFF specification (https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). Microsoft Learn content — permissive technical reference. 2,512 lines.
- **apple-macho.md** — Mach-O ABI reference, aidansteele's mirror of Apple's historical doc (https://github.com/aidansteele/osx-abi-macho-file-format-reference). Public Apple reference. 2,319 lines.
- **corkami-binary-readme.md** — Corkami binary-format poster index by Ange Albertini (https://github.com/corkami/pics/blob/master/binary/README.md). CC-BY. 575 lines.
- **elf-man5.md** — Linux `elf(5)` man page (https://man7.org/linux/man-pages/man5/elf.5.html). Linux man-pages, GFDL-1.3+ / BSD-3-Clause. 1,504 lines.
- **elf-gabi-toc.md** — Linux Foundation ELF gABI table of contents (https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html). Index only; deep linking expected. 60 lines.

### objective-see/

- **Name:** Objective-See blog (Patrick Wardle's macOS security research)
- **URL:** https://objective-see.org/blog.html
- **Author:** Patrick Wardle
- **License posture:** Personal research blog, no explicit license. Mirror is the post index (titles + summaries) only. For deep content, the agent follows the linked post URLs.
- **Files:** 1 (blog index)
- **Volume:** 2,358 lines

### hasherezade/

- **Name:** Hasherezade's blog (PE-bear, pe-sieve, libpeconv author)
- **URL:** https://hshrzd.wordpress.com/
- **Author:** Aleksandra "hasherezade" Doniec
- **License posture:** Personal research blog. Index mirrored; full posts fetched on demand.
- **Files:** 1 (blog index)
- **Volume:** 4,293 lines

### oalabs/

- **Name:** OALabs (Open Analysis) research
- **URL:** https://research.openanalysis.net/
- **Author:** Sergei Frankoff, Sean Wilson
- **License posture:** Personal research site. Index only; per-post fetch on demand.
- **Files:** 1 (research index)
- **Volume:** 116 lines

---

## Cited by URL — fetch on demand

These sources are referenced by the skill but **not mirrored** because they lack an explicit redistribution license or carry a copyleft license incompatible with this capability's MIT licence. The skill / agent fetches the relevant page on demand when a technique is searched.

- **Check Point Anti-Debug Encyclopedia** — https://anti-debug.checkpoint.com/. Per-category canonical reference (debug-flags, object-handles, exceptions, timing, process-memory, assembly, interactive, misc). Research publication, no explicit redistribution license. Authoritative for Windows anti-debug technique detail; the local short-form `windows-anti-debug.md` distils the common cases and the Unprotect mirror covers the cross-platform catalog.
- **al-khaser** — https://github.com/ayoubfaouzi/al-khaser. Reference C++ implementations of every anti-debug + anti-VM technique. **GPL-3.0** copyleft, incompatible with MIT redistribution; `git clone` the repo locally to read the source when a specific implementation is needed.
- **ired.team** — https://www.ired.team/. Mantvydas Baranauskas's reversing & offensive-security KB. Personal knowledge base, no explicit license. Key pages cited by URL in `pe-format-quick-ref.md`, `shellcode-patterns.md`, `SKILL.md`: exploring-the-peb, pe-file-header-parser-in-c++, reversing-a-password-protected-application.
- **Intezer ELF Malware Anti-Analysis Techniques** — original URL https://www.intezer.com/blog/research/elf-malware-anti-analysis-techniques/ returned 404 on 2026-05-12. May have been deleted or moved. Substitute: `external/unprotect/` (cross-platform anti-debug + anti-VM catalog) + al-khaser Linux portions.
- **HackTricks Reversing** — https://book.hacktricks.wiki/. Index page didn't surface a stable reversing section in current site layout. Fetch specific topic pages directly.
- **MITRE ATT&CK / MBC** — https://attack.mitre.org/, https://github.com/MBCProject/mbc-markdown. Linked from techniques; not mirrored.
- **TAOMM** (The Art of Mac Malware) — https://taomm.org/. Book site, citation only.
- **Mandiant Threat Intelligence** — https://cloud.google.com/blog/topics/threat-intelligence. Too large/dynamic; fetch specific posts.
- **ScyllaHide** — https://github.com/x64dbg/ScyllaHide. Source repository; clone if needed.
- **Detect It Easy (DIE)** — https://github.com/horsicq/Detect-It-Easy. Tool repository; clone if needed.

---

## License & attribution policy for this capability

This capability is **MIT-licensed**. The mirrored content above is either permissively licensed (Microsoft, Apple, Linux Foundation, Corkami CC-BY), attribution-required with per-file backlinks preserved (Unprotect), or index-only excerpts of personal blogs (post bodies fetched from the upstream URL). Sources without an explicit redistribution license are cited by URL and not embedded.
