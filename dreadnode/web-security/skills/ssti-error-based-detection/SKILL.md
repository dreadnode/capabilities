---
name: ssti-error-based-detection
description: Error-based blind SSTI detection using polyglot payloads and error message differentials. Use when template engine suspected but injection appears blind.
---

# SSTI Error-Based Detection

## Pattern
- Template injection suspected but no reflected output observed
- Application renders verbose error messages on invalid input
- Need to identify template engine before escalation
- Time-based blind SSTI too slow or unreliable

## Probe
**Polyglot detector** (triggers distinct errors per engine):
```
${{<%[%'"}}%\.
```
**Engine-specific error probes** — observe error type to fingerprint:
- Jinja2: `{{7*'7'}}` → `7777777` or `UndefinedError`
- Twig: `{{7*7}}` → `49` or `Twig_Error_Syntax`
- Freemarker: `${7*7}` → `49` or `ParseException`
- Velocity: `#set($x=7*7)$x` → `49` or `MethodInvocationException`
- ERB: `<%= 7*7 %>` → `49` or `SyntaxError`
- Pebble: `{{7*7}}` → `49` or `PebbleException`
- Smarty: `{7*7}` → `49` or `SmartyCompilerException`

Key insight: **error class names and stack traces reveal the engine** even when output is blind. `AttributeError` = Python (Jinja2/Mako). `NumberFormatException` = Java (Freemarker/Pebble).

## Indicators
- Different error types on different payloads → engine fingerprinted
- Stack trace contains engine class names (e.g. `jinja2.exceptions`, `freemarker.core`)
- Error message includes partial evaluation result

## Chain With
- ssrf-redirect-loop (reach internal template services via SSRF)

## Reference
https://portswigger.net/research/server-side-template-injection
