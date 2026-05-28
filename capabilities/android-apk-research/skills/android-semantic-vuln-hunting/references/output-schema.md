# Output schemas

## Finding hypothesis JSONL

Each line is one finding object. `class` is the canonical bug-class slug; the
normalizer (`normalize_semantic_findings` MCP tool) uses it to default
MASVS/CWE/MASWE tags when the record omits them.

```json
{
  "title": "Deep link redirects authenticated WebView to attacker-controlled host",
  "risk": "high",
  "confidence": "medium",
  "apk": "corpus/app.apk",
  "package": "com.example",
  "class": "deep_link_to_authenticated_webview",
  "masvs": ["MASVS-PLATFORM", "MASVS-NETWORK"],
  "cwe": ["CWE-939", "CWE-749"],
  "maswe": ["MASWE-0058"],
  "entrypoint": "com.example.DeepLinkActivity exported BROWSABLE myapp://open",
  "source": "Intent.getData().getQueryParameter('next')",
  "trust_boundary": "browser/other app controls next; app treats string prefix as first-party URL validation",
  "sink": "WebView.loadUrl(next) with authenticated cookies",
  "impact": "token theft or account takeover if auth context is sent to attacker-controlled URL",
  "evidence": ["DeepLinkActivity.java:42", "WebRouter.java:88"],
  "validation_plan": ["Use test device to launch myapp://open?next=https://trusted.com.attacker.tld/", "Observe WebView request host and cookies with authorized proxy"],
  "scanner_gap": "generic warning only",
  "needs_backend_validation": false
}
```

### Tag fields

- **`masvs`** — OWASP MASVS control category (`MASVS-PLATFORM`,
  `MASVS-NETWORK`, `MASVS-AUTH`, `MASVS-STORAGE`, `MASVS-CRYPTO`,
  `MASVS-CODE`, `MASVS-RESILIENCE`, `MASVS-PRIVACY`).
  Reference: <https://mas.owasp.org/MASVS/>.
- **`cwe`** — Common Weakness Enumeration IDs (e.g. `CWE-749`, `CWE-926`).
  Reference: <https://cwe.mitre.org/>.
- **`maswe`** — OWASP Mobile Application Security Weakness Enumeration IDs.
  MAS's weakness catalog tied to MASTG tests; currently in beta.
  Reference: <https://mas.owasp.org/MASWE/>. **Where no MASWE cleanly maps
  the bug class** (Dirty Stream, client-side trust, backend API abuse,
  request-signing replay, leaked-host feature-flag gates) the field stays
  empty rather than asserting an unrelated ID; CWE + MASVS carry the
  grounding instead.

All three are arrays, all three are optional in the source record — the
normalizer fills defaults from the `class` value if the record omits them.

## Bug-class taxonomy

Use these stable `class` slugs so corpus-level reports can compare patterns
across runs. Each class maps to a default MASVS / CWE / MASWE tag tuple in
`scripts/normalize_findings.py:CLASS_TAXONOMY` — when adding a new class,
update both this table and the dict in the same change.

MASWE anchors used below:
- **MASWE-0058** — Insecure Deep Links (MASVS-PLATFORM)
- **MASWE-0064** — Insecure Content Providers (MASVS-PLATFORM)
- **MASWE-0066** — Insecure Intents (MASVS-PLATFORM)
- **MASWE-0068** — JavaScript Bridges in WebViews (MASVS-PLATFORM)

| `class` | MASVS | CWE | MASWE |
|---|---|---|---|
| `deep_link_to_authenticated_webview` | PLATFORM, NETWORK | CWE-939, CWE-749 | MASWE-0058 |
| `deep_link_to_js_bridge` | PLATFORM | CWE-749, CWE-829 | MASWE-0058, 0068 |
| `custom_scheme_arbitrary_webview` | PLATFORM | CWE-939, CWE-079 | MASWE-0058 |
| `intent_redirection_private_component` | PLATFORM | CWE-926, CWE-940 | MASWE-0066 |
| `intent_redirection_uri_grant_leak` | PLATFORM | CWE-926, CWE-200 | MASWE-0066 |
| `dirty_stream_file_overwrite` | PLATFORM, STORAGE | CWE-22, CWE-73 | — |
| `share_target_path_traversal` | PLATFORM, STORAGE | CWE-22 | — |
| `exported_provider_sqli` | PLATFORM | CWE-89, CWE-926 | MASWE-0064 |
| `exported_provider_private_file_read` | PLATFORM, STORAGE | CWE-200, CWE-926 | MASWE-0064 |
| `provider_uri_grant_confusion` | PLATFORM | CWE-441, CWE-926 | MASWE-0064, 0066 |
| `deep_link_auto_account_state_change` | AUTH, PLATFORM | CWE-352, CWE-862 | MASWE-0058 |
| `client_state_auth_bypass` | AUTH | CWE-602, CWE-287 | — |
| `apk_discovered_backend_bola` | AUTH, NETWORK | CWE-639 | — *(OWASP API1)* |
| `apk_discovered_backend_workflow_bypass` | AUTH, NETWORK | CWE-841, CWE-863 | — *(OWASP API5)* |
| `apk_discovered_backend_mass_assignment` | NETWORK | CWE-915 | — *(OWASP API6)* |
| `apk_discovered_backend_ssrf_or_open_redirect` | NETWORK | CWE-918, CWE-601 | — *(OWASP API7)* |
| `apk_discovered_graphql_operation_abuse` | NETWORK | CWE-639, CWE-863 | — *(OWASP API1/API3)* |
| `apk_discovered_grpc_operation_abuse` | NETWORK | CWE-639, CWE-863 | — *(OWASP API1/API3)* |
| `webview_bridge_to_mobile_api_action` | PLATFORM | CWE-749, CWE-829 | MASWE-0068 |
| `mobile_request_signing_replay_or_confusion` | NETWORK, CRYPTO | CWE-345, CWE-294 | — |
| `leaked_host_feature_flag_gated` | NETWORK, CODE | CWE-1188 | — |
| `leaked_host_intent_extra_gated` | NETWORK, PLATFORM | CWE-1188, CWE-926 | MASWE-0066 |

Tags are starting points, not contracts — override per-finding when the
specific chain warrants different categorization. The OWASP API Top 10
annotations on `apk_discovered_backend_*` rows are aide-memoires for the
backend-side framework; they aren't yet emitted by the normalizer.

## Corpus manifest JSONL

```json
{
  "package": "com.example",
  "version": "1.2.3",
  "source": "androzoo|device|fdroid|user|mirror",
  "sha256": "...",
  "path": "corpus/com.example/base.apk",
  "downloaded_at": "2026-05-15T16:00:00Z",
  "provenance_url": "https://...",
  "authorization_notes": "..."
}
```

## Report sections

A good Markdown report has:

1. Scope and corpus provenance.
2. Method summary and tool versions.
3. Top findings by impact/confidence.
4. Scanner-gap summary.
5. Validation queue grouped by required authorization tier.
6. Appendix with all normalized hypotheses.
