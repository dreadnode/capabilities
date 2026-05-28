# Request signing and attestation review

Use when an APK contains custom API signing, encrypted bodies, device binding, Play Integrity/SafetyNet, certificate pinning, or backend endpoints that trust mobile-only headers. The goal is not to steal secrets; it is to understand what the backend thinks the mobile client proves.

## Search terms

```bash
rg -n \
  -e 'Hmac|Mac\.getInstance|SHA256|SHA-256|MessageDigest|Signature|getInstance\("Hmac' \
  -e 'signRequest|signature|x-signature|X-Signature|canonical|canonicalize|stringToSign' \
  -e 'nonce|timestamp|expires|ttl|replay|clockSkew|serverTime' \
  -e 'deviceId|installationId|androidId|Settings\.Secure|Build\.SERIAL|fingerprint' \
  -e 'SafetyNet|PlayIntegrity|IntegrityManager|IntegrityTokenRequest|attestation|attest' \
  -e 'CertificatePinner|TrustManager|HostnameVerifier|pinning|pinset' \
  -e 'encryptBody|encryptedPayload|Cipher\.getInstance|AES/GCM|RSA/ECB|publicKey' \
  "$SRC" > findings/<pkg>/rg-signing-attestation.txt
```

## Questions to answer

### Signature coverage

- Is the HTTP method signed?
- Is the path signed?
- Are query parameters signed after canonical sorting?
- Is the whole body signed, or only selected fields?
- Are object IDs (`accountId`, `tenantId`, `deviceId`, `orderId`) included?
- Are auth headers and tenant headers signed?
- Are file uploads/multipart parts signed consistently?

### Replay controls

- Is there a nonce?
- Is the timestamp server-validated?
- Does the server issue the nonce or does the client generate it?
- Is the nonce bound to account/device/session/path/body?
- What happens on retry/offline sync?

### Device and attestation binding

- Is Play Integrity/SafetyNet required or best-effort?
- Is there fallback for devices without Play Services?
- Are attestation failures logged but allowed?
- Is device ID client generated or server enrolled?
- Can a signed request be replayed from another device/account?

### Pinning / transport

- Is certificate pinning present only in release builds?
- Are debug/staging hosts unpinned?
- Do WebView/custom tabs share cookies or tokens with API clients?

## High-value bug shapes

- Signature excludes privilege-bearing fields (`tenantId`, `role`, `price`, `status`, `deviceId`).
- Signature is computed before later mutation of request body/map.
- Retry/offline queue reuses old signatures after object/account state changes.
- Nonce/timestamp is client-only and not server-enforced.
- Attestation fallback allows sensitive endpoints with only device ID.
- WebView/JS bridge can call native signing helper for attacker-controlled path/body.
- Mixed signed and unsigned endpoints share the same authorization token.

## Evidence standard

Static code can prove signing design and potential coverage gaps. It cannot prove backend acceptance. Use `mobile_request_signing_replay_or_confusion` with `needs_backend_validation` until authorized backend tests show replay, cross-device use, or field tampering works.
