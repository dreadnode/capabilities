# Common Anti-Patterns by Language

| Language | Anti-Pattern | Why It Fails |
|----------|-------------|--------------|
| PHP | `str_replace()` without recursive loop | Nesting bypass |
| PHP | `preg_replace()` with `/e` flag | Code execution in replacement |
| PHP | `strip_tags()` then `urldecode()` | Ordering bypass |
| JS | `.replace()` without `/g` flag | First-match-only |
| JS | `$&`, `$'` in `.replace()` replacement string | User-controlled replacement reinjection |
| Python | `re.sub()` with user-controlled pattern | ReDoS, injection |
| Ruby | `gsub` with string (not regex) first arg | Literal match only, no anchoring |
| Java | `String.replace()` (literal, global) vs `replaceFirst()` | Method confusion |
| Go | `strings.Replace()` with `n=1` | First-match-only |
| All | Blocklist instead of allowlist | Completeness failure by design |

## Rationalizations to Reject

- **"The WAF will catch it"** -- WAF and app may parse differently (see parser-differential-bypass)
- **"Nobody would think to try that"** -- Automated tools test every permutation
- **"We only use this internally"** -- Internal tools become external via SSRF, compromised credentials
- **"It's just an extra layer of defense"** -- If it's the ONLY layer between source and sink, it's the entire defense

## Examples

**Example 1: PHP SQL filter bypass via nesting + case**
```
Sanitizer: str_replace(['SELECT','INSERT','DELETE'], '', $input)
Payload:   sElSELECTeCt * FROM users
Result:    sEleCt * FROM users  (inner SELECT removed, outer reconstructs with mixed case)
```

**Example 2: JS XSS filter bypass via ordering**
```
Sanitizer: input.replace(/<script>/gi, '') applied BEFORE urldecode
Payload:   %3Cscript%3Ealert(1)%3C/script%3E
Flow:      filter sees encoded (no match) → urldecode → <script>alert(1)</script>
```

**Example 3: Path traversal via non-recursive replace**
```
Sanitizer: path.replace('../', '')
Payload:   ....//....//etc/passwd
Flow:      first ../ removed from each group → ../../etc/passwd
```
