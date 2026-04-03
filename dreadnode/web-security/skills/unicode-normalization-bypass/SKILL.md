---
name: unicode-normalization-bypass
description: Bypass WAFs and input filters using Unicode normalization equivalents (NFKC/NFKD). Use when WAF blocks payloads but application normalizes Unicode before processing.
---

# Unicode Normalization Bypass

## Pattern
- WAF blocking standard payloads but backend normalizes Unicode post-filter
- Application accepts internationalized/multi-script input
- Fullwidth, mathematical, or decorative Unicode characters accepted
- Length-based restrictions with case mapping (Turkish locale edge cases)

## Probe
**Substitutions** (WAF sees Unicode, app normalizes to ASCII):
- `<` → `\uff1c` (fullwidth `<`) | `>` → `\uff1e` (fullwidth `>`)
- `'` → `\uff07` (fullwidth) or `\u02bc` (modifier letter)
- `/` → `\u2215` (division slash) or `\u2044` (fraction slash)
- `"` → `\uff02` (fullwidth) | `.` → `\uff0e` (fullwidth)
- `0-9` → `\uff10-\uff19` (fullwidth digits)
- Script variants: `\U0001d4e2` (mathematical bold `s`), circled letters

**Detection test**: submit `\U0001d543\u2147\U0001d664\U0001d4c3\u2148\U0001d530\U0001d525\U0001d4b6\U0001d65f` — if response reflects "Leonishan", normalization is active.

**NFKC normalization** is most common (Kubernetes, Python `.casefold()`, Java `Normalizer`).

**Unicode surrogates → wildcard injection** (Solr/Elasticsearch):
- Lone surrogates like `\udc2a` are invalid UTF-8 and cannot be displayed
- Systems convert them to U+FFFD replacement character (`�`)
- Some backends further simplify `�` to ASCII `?`
- `?` is a single-char wildcard in Solr, Elasticsearch, and SQL LIKE
- Result: inject surrogate → bypass character filter → wildcard query execution → data leak
```
Input:     admin\udc2a      (filter allows it — not a blocked char)
Backend:   admin�           (replacement char)
Simplified: admin?          (wildcard — matches admin1, admin2, adminX, ...)
```
Test on search/filter endpoints backed by Solr/Elasticsearch: submit `\udc2a` and check if results broaden.

## Indicators
- Response reflects normalized (ASCII) version of Unicode input
- Payload bypasses WAF but executes on backend (XSS, SSTI, SQLi, path traversal)
- Character count changes after normalization (compatibility decomposition)

## Double Encoding + Unicode
Stack URL encoding with Unicode for multi-layer bypass:
```
# Filter decodes URL once, then checks for <script> — but Unicode survives
%ef%bc%9c%ef%bd%93%ef%bd%83%ef%bd%92%ef%bd%89%ef%bd%90%ef%bd%94%ef%bc%9e
# Double-encode the Unicode bytes — filter decodes to UTF-8 bytes, backend decodes to fullwidth chars
%25ef%25bc%259c  →  decode once: %ef%bc%9c  →  decode again: ＜ (fullwidth <)
# Triple for two-decode-layer stacks
%2525ef%2525bc%25259c
```
Test when WAF decodes URL encoding before Unicode normalization — each layer peels one encoding level.

## Chain With
- ssti-error-based-detection (bypass WAF to reach template engine)
- apache-confusion-attacks (combine encodings with path confusion)
- orm-filter-data-leak (surrogate wildcard injection on search/filter endpoints)

## Reference
- https://i.blackhat.com/BH-USA-25/Presentations/USA-25-Barnett-Lost-In-Translation-Exploiting-Unicode-compressed.pdf
- https://lab.ctbb.show/research/unicode-surrogates-conversion (surrogates → wildcard)
