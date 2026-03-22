---
name: libmagic-type-confusion
description: Bypass file type detection using libmagic's JSON nesting depth limit to force type confusion. Upload files that evade MIME checks by exploiting recursion guards in file or libmagic. Use when file uploads validate type via libmagic or the file command and you need to smuggle executable content.
---

# libmagic Type Confusion via Deep JSON Nesting

## Pattern
- The application validates upload type using `file` or libmagic bindings
- Dangerous formats such as HTML, SVG, or script-capable content are blocked
- A later processing stage handles the uploaded file based on the detected type

## Root Cause
libmagic's JSON detector includes a recursion guard:

```c
if (lvl > 500) {
    return 0;
}
```

Once nesting exceeds the guard, libmagic stops treating the file as JSON. If another recognizable signature is embedded, classification may fall through to that type instead.

## Version Differences

| Version | JSON depth limit | Notes |
|---------|------------------|-------|
| libmagic 5.41 | about 10 levels | easier to exploit |
| libmagic 5.46+ | about 500 levels | requires deeper nesting |

## Exploitation

### Step 1: Generate nested JSON with an embedded signature
```python
#!/usr/bin/env python3
import json

def make_payload(depth=510, target_sig="%PDF-1.4"):
    obj = "terminal"
    for i in range(depth):
        obj = {f"l{i}": obj}
    obj["_sig"] = target_sig + "\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n%%EOF"
    return json.dumps(obj)
```

### Step 2: Verify confusion locally
```bash
file confused.json
```

### Step 3: Upload and trigger the downstream handler
The goal is not just misclassification. Confirm the file reaches a parser, renderer, or execution path that trusts the reported type.

## Practical Payloads

### PDF smuggling
Embed a PDF header and minimal PDF structure so the target routes it into a PDF pipeline.

### HTML smuggling
On older libmagic versions, shallow nesting may be enough to hide HTML or SVG content from JSON detection.

## Language and Library Coverage

Affected when they inherit libmagic behavior:
- C and C++
- Perl
- Ruby
- PHP `finfo`
- Python `python-magic`
- Go wrappers around libmagic

Usually not affected by this exact bug class:
- Node.js-only MIME implementations
- Java systems using Apache Tika
- .NET-native MIME detection
- Rust-native detection libraries

## Testing Steps
1. Determine whether the target uses libmagic or `file`.
2. Identify the version if possible.
3. Generate a nested JSON payload matching the target depth threshold.
4. Embed the target type signature.
5. Confirm both type confusion and downstream processing.

## Chain With
- `dom-vulnerability-detection`
- `write-path-to-rce`
- `parser-differential-bypass`

## References
- https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion
- https://github.com/file/file/blob/master/src/is_json.c
