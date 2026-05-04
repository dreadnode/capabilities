---
name: jxscout-repeater
description: Send and iterate on raw HTTP requests using jxscout's repeater. Use when the user asks to analyze, test, try out, send, resend, or replay an HTTP request; when testing an endpoint or API call for security issues; when modifying parameters/headers/body to test for vulnerabilities; or when the user mentions repeater, .req/.res, or raw HTTP testing.
license: proprietary
metadata:
  source: jxscout-pro-v2
  author: francisconeves97
  origin: ported from jxscout-pro-v2 agent skills
---

# jxscout Repeater

The repeater sends raw HTTP requests from `.req` files and saves timestamped request/response pairs for each attempt. It's your tool for hands-on testing: modify a request, send it, check the response, iterate.

## Command

```bash
jxscout-pro-v2 -c repeater <req_file> [options]
```

**Required:**
- `<req_file>` -- path to a file containing a raw HTTP request

**Options:**
- `--url <url>` -- override connection target (e.g. `https://host:443`). When set, overrides host/port/TLS derived from the request file.
- `--proxy-host <host>` -- send through a proxy (use with `--proxy-port`)
- `--proxy-port <port>` -- proxy port

## Request file format

Plain HTTP -- the exact bytes to send. Method, path, headers, blank line, optional body:

```
POST /api/v2/users HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbG...
Content-Type: application/json

{"user_id": 123, "role": "admin"}
```

**Content-Length** is updated automatically from the actual body before sending -- do not manually adjust it when editing the body.

## Output

- **stdout**: the raw HTTP response (status line, headers, body). Compressed responses are automatically decompressed.
- **Files**: for each send, two files are created next to the input file:
  - `<basename>_<YYYYMMDDHHMMSS>_<status>.req` -- the request that was sent
  - `<basename>_<YYYYMMDDHHMMSS>_<status>.res` -- the response received

Example: sending `repeater/idor_test/original.req` that gets a 200 creates `original_20260208155236_200.req` and `original_20260208155236_200.res`.

## Workflow

### Setting up

If the `.req` file is **not** already in the `repeater/` folder:

1. Create a directory structure under `repeater/` that identifies both the **endpoint** and the **specific test**. Use the endpoint as the top-level folder and a subfolder for each test scenario. The folder names should make it obvious what's being tested at a glance.
   - Good: `repeater/api_v2_users_profile/idor_other_user/`, `repeater/graphql_updateRole_mutation/privilege_escalation/`, `repeater/checkout_apply_coupon/negative_amount/`, `repeater/POST_auth_login/bruteforce_lockout/`
   - Also fine for a single test: `repeater/api_v2_users_profile/` (no subfolder needed when there's only one test for the endpoint)
   - Bad: `repeater/idor_testing/`, `repeater/xss_test/` (too generic -- says what you're testing for but not which endpoint)
2. Copy the `.req` file there as `original.req`
3. Use `repeater/<endpoint>/<test>/original.req` for all subsequent work

### Iterating

1. Run: `jxscout-pro-v2 -c repeater repeater/<test_name>/original.req`
2. Check stdout and/or the `.res` file for status, headers, and body
3. Edit `original.req` -- change the parameter, header, or body you're testing
4. Run the same command again
5. Compare with previous responses (the timestamped `.res` files are your history)
6. Repeat until you've confirmed or ruled out the issue

Always edit the **same** `original.req` file. Each send creates a timestamped copy, so your full history of attempts is preserved automatically.

### Comparing responses

- Check status codes across attempts (e.g. 200 vs 403 vs 500)
- Diff response bodies to spot behavioral changes
- Look for error messages, stack traces, or debug output that leak information
- Compare response sizes -- significant size differences often indicate different behavior

## Practical examples

### Testing for IDOR
Edit the user ID in the request body or URL path. Send with your session token to access another user's data:
- Original: `{"user_id": 123}` (your ID)
- Modified: `{"user_id": 456}` (victim ID)
- Compare: does the response return different user's data?

### Testing for auth bypass
Remove or modify the auth header:
- Remove `Authorization` header entirely
- Replace token with expired/invalid value
- Try a different user's token
- Compare: does the endpoint still return data?

### Testing for injection
Modify parameter values with payloads:
- Add SQL metacharacters: `' OR 1=1--`
- Add template injection: `{{7*7}}`
- Add path traversal: `../../etc/passwd`
- Check: error messages, different response codes, unexpected output

### Testing header-based behavior
Modify or add headers to test server behavior:
- Add `X-Forwarded-For: 127.0.0.1` for IP-based access control bypass
- Change `Origin` header for CORS testing
- Modify `Content-Type` to test parser confusion

## Using captured HTTP requests

If `http_requests/` exists in the project working directory, jxscout has captured real HTTP traffic from the target. These `.req` files are ready-made starting points for the repeater:

1. Browse `http_requests/` to find an interesting request (e.g. an API call, auth endpoint, file upload)
2. Copy it to `repeater/<test_name>/original.req`
3. Start iterating from a real request instead of crafting one from scratch

This is especially useful when you find an interesting endpoint through static analysis and want to test it with actual headers, cookies, and auth tokens from a real session.

## Important

- Never create new request files for iterations -- always edit `original.req` so history accumulates in the timestamped pairs.
- The repeater handles TLS automatically based on the scheme in the request or `--url`.
- Use `--proxy-host` and `--proxy-port` to route through Burp or Caido for additional inspection.

## Troubleshooting slow or hanging requests

If a repeater request takes too long to respond or appears to hang, the `.req` file likely has formatting issues. Re-read the file carefully and check for:

1. **Extra spaces in the request line** -- there must be exactly one space between the method, path, and HTTP version (e.g. `GET /path HTTP/1.1`, not `GET  /path  HTTP/1.1`)
2. **Trailing whitespace on header lines** -- spaces or tabs after header values can cause parsing issues on the server side
3. **Extra blank lines between headers** -- there must be zero blank lines between headers; only one blank line separating headers from the body
4. **Spaces before or after header names/values** -- `Authorization: Bearer token` is correct, ` Authorization : Bearer token ` is not
5. **Extra newlines or whitespace after the body** -- trailing blank lines at the end of the file can be interpreted as part of the body
6. **Host header mismatch** -- verify the `Host` header matches the actual target server

When a request hangs, fix any formatting issues found and retry before investigating other causes.
