---
name: te0-request-smuggling
description: TE.0 request smuggling where front-end processes Transfer-Encoding chunked but back-end ignores it entirely. Use when reverse proxy + backend detected and standard CL.TE/TE.CL fails.
---

# TE.0 Request Smuggling

## Pattern
- Reverse proxy + backend architecture (common in cloud deployments)
- Standard CL.TE and TE.CL smuggling attempts failed
- Backend ignores Transfer-Encoding header entirely (treats body as length 0)
- Front-end processes chunked encoding and forwards full body
- Google Cloud, AWS ALB, nginx + misconfigured backends common targets

## Probe
```http
OPTIONS / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 0

50
GET /admin HTTP/1.1
Host: target.com
X-Ignore: x

0

```
**Key details:**
- OPTIONS method specifically — GET/POST may be handled differently
- Front-end sees chunked body, forwards it. Backend sees CL:0, ignores body.
- Smuggled request (`GET /admin`) poisons the next legitimate request's response.
- Vary the smuggled path to confirm: `/admin`, `/logout`, redirect to attacker domain.

## Indicators
- Next legitimate request returns response for smuggled path (response poisoning)
- Unexpected 3xx redirect to attacker-controlled domain
- Session data from other users appears in your response
- Timing: second request arrives faster than expected (already queued)

## Chain With
- web-cache-deception-path (poison cache via smuggled request)

## Reference
https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/
