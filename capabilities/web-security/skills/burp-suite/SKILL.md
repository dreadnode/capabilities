---
name: burp-suite
description: Queries Burp proxy history, sends requests via Repeater, configures Intruder attacks, retrieves scanner findings, and performs OOB testing with Collaborator. Use when working with Burp proxy history, sending requests through Burp, using Repeater/Intruder, checking scanner issues, or performing OOB testing with Collaborator.
---

# Burp Suite MCP Tools

Burp Suite Professional exposes 24 tools via its native MCP server. These connect directly to the running Burp instance — no wrapper or SDK needed.

## HTTP Requests

```
send_http1_request(content, targetHostname, targetPort, usesHttps)
send_http2_request(headers, pseudoHeaders, requestBody, targetHostname, targetPort, usesHttps)
```

`content` is the full raw HTTP/1.1 request including request line and headers. Use `\r\n` line endings.

```
send_http1_request(
  content="GET /api/users HTTP/1.1\r\nHost: target.com\r\nCookie: session=abc\r\n\r\n",
  targetHostname="target.com",
  targetPort=443,
  usesHttps=true
)
```

All requests appear in Burp's proxy history automatically. **Verify:** After sending, confirm the request appears with `get_proxy_http_history(count=1, offset=0)`.

## Proxy History

```
get_proxy_http_history(count, offset)
get_proxy_http_history_regex(count, offset, regex)
get_proxy_websocket_history(count, offset)
get_proxy_websocket_history_regex(count, offset, regex)
```

`offset=0, count=10` gets the 10 most recent items. Use regex to filter by URL, header, or body content.

## Repeater & Intruder

```
create_repeater_tab(content, targetHostname, targetPort, usesHttps, tabName?)
send_to_intruder(content, targetHostname, targetPort, usesHttps, tabName?)
```

Send a request to Repeater for manual iteration or to Intruder for automated fuzzing. Always name tabs descriptively (e.g. "IDOR /api/users").

## Scanner

```
get_scanner_issues(count, offset)
```

Returns vulnerabilities found by Burp's active and passive scanner with severity, confidence, and affected URLs.

## Collaborator (OOB Testing)

```
generate_collaborator_payload(customData?)
get_collaborator_interactions(payloadId?)
```

Workflow:
1. `generate_collaborator_payload` → get a unique `*.burpcollaborator.net` URL + `payloadId`
2. Inject the URL into a request (SSRF, blind XSS, XXE, email header injection)
3. `get_collaborator_interactions(payloadId)` → check for DNS/HTTP/SMTP callbacks

This is the primary tool for confirming blind vulnerabilities where no in-band response is visible.

## Intercept & Engine Control

```
set_proxy_intercept_state(intercepting: bool)
set_task_execution_engine_state(running: bool)
```

## Editor

```
get_active_editor_contents()
set_active_editor_contents(text)
```

Read or set the content of the user's active Burp message editor tab.

## Encoding Helpers

```
url_encode(content)    url_decode(content)
base64_encode(content) base64_decode(content)
generate_random_string(length, characterSet)
```

## Configuration

```
output_project_options()   set_project_options(json)
output_user_options()      set_user_options(json)
```

Export config first to understand the schema before setting options.

## Common Workflows

1. **SSRF confirmation via Collaborator**: `generate_collaborator_payload` → inject URL into SSRF parameter via `send_http1_request` → `get_collaborator_interactions` to confirm callback
2. **IDOR testing via Repeater**: `create_repeater_tab` with request for resource A → modify ID to resource B → compare responses
3. **Scanner triage**: `get_scanner_issues(count=20, offset=0)` → review severity/confidence → replay high-confidence findings with `send_http1_request` to confirm
