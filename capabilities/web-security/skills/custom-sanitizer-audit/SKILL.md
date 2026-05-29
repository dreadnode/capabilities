---
name: custom-sanitizer-audit
description: "Audit custom sanitization functions for bypass vulnerabilities using the Five-Point Checklist and ordering analysis. Use when encountering homegrown sanitize/filter/clean/escape functions, reviewing input validation, or testing custom security wrappers."
---

# Custom Sanitizer Audit

Every homegrown security function is a bypass waiting to be found. Framework-provided sanitizers have years of adversarial testing; custom ones have the developer's imagination as their ceiling.

## The Five-Point Checklist

Every custom sanitizer MUST be evaluated against all five points. A failure on ANY single point is a bypass.

### 1. Case-Insensitive?

```php
// BYPASSABLE: strpos() not stripos()
if (strpos($input, 'SELECT') !== false) { block(); }
// Bypass: select, SeLeCt

// SECURE: stripos()
if (stripos($input, 'SELECT') !== false) { block(); }
```

### 2. Global Replacement?

```javascript
// BYPASSABLE: first match only
input.replace("../", "")
// Input: "....//etc/passwd" → "../etc/passwd"

// SECURE: global flag
input.replace(/\.\.\//g, "")
```

### 3. Recursive?

After one pass of removal, does the remaining string reconstitute the blocked pattern?

```
Input:    <scrip<script>t>alert(1)</scrip</script>t>
Pass 1:   inner <script> removed → <script>alert(1)</script>  ← XSS
```

**Test:** Nest the blocked string inside itself. If the sanitizer runs once, the outer halves collapse into the blocked string.

### 4. Complete?

Does the blocklist cover all dangerous variants?

```javascript
// BYPASSABLE: blocks <script> but not event handlers
input.replace(/<script[^>]*>.*?<\/script>/gi, "");
// Bypass: <img onerror=alert(1) src=x>, <svg onload=alert(1)>
```

### 5. Consistent Across All Routes?

Is the sanitizer applied uniformly to every entry point?

```bash
# Find the sanitizer definition, search all call sites,
# find all routes handling the same input type,
# diff the two lists — missing routes are bypasses
```

## Ordering Bugs: Validate-Then-Transform

The sanitizer may be correct in isolation but applied in the wrong order relative to data transformations. See [references/ordering-bugs.md](references/ordering-bugs.md) for patterns.

**General Rule:** decode/normalize/transform FIRST, sanitize LAST, use IMMEDIATELY. Any operation between sanitization and use is a potential bypass.

## The Sixth Check: Security Gate with No Bailout

```php
// VULNERABLE: check exists but doesn't stop execution
if (!is_valid_input($data)) {
    $error = true;  // flag set, never checked before dangerous op
}
execute_query($data);  // runs regardless
```

For every security check, verify the NEXT line is `return`, `exit`, `throw`, `die()`, or `abort()`.

## Detection Workflow

### Step 1: Find All Custom Security Functions

```bash
grep -rn "function.*sanitiz\|function.*filter\|function.*clean\|function.*escap\|function.*valid" \
  --include="*.php" --include="*.js" --include="*.py" --include="*.rb" --include="*.java" --include="*.go"

grep -rn "blocked\|blacklist\|blocklist\|forbidden\|banned\|disallowed" \
  --include="*.php" --include="*.js" --include="*.py" --include="*.rb"
```

### Step 2: Audit Each Function

```
Function: sanitize_input() at src/utils/security.php:42
| Check              | Result | Evidence                          |
|--------------------|--------|-----------------------------------|
| Case-insensitive?  | FAIL   | Uses strpos() not stripos()       |
| Global replacement?| PASS   | Uses str_replace() (global in PHP)|
| Recursive?         | FAIL   | Single pass, nesting bypasses     |
| Complete?          | FAIL   | Missing UNION, HAVING keywords    |
| Consistent?        | FAIL   | Not called in /api/v2/export      |
```

### Step 3: Check Ordering

Trace data flow backward AND forward from each sanitizer call site. See [references/ordering-bugs.md](references/ordering-bugs.md).

### Step 4: Test Bypasses

For every FAIL, craft a specific bypass payload and test.

## Anti-Patterns by Language

See [references/anti-patterns.md](references/anti-patterns.md) for the full table of common anti-patterns across PHP, JS, Python, Ruby, Java, and Go.

## Related Skills

- **parser-differential-bypass** -- sanitizer and consumer parse input differently
- **unicode-normalization-bypass** -- Unicode NFKC/NFKD undoes sanitization
- **dompurify-mxss-bypass** -- DOMPurify sanitizer bypass
- **insecure-defaults** -- sanitizer has fail-open behavior on error
