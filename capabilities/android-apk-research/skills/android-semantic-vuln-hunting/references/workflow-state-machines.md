# Workflow state-machine reconstruction

Use when an APK reveals multi-step backend actions. The goal is to reconstruct the intended order, object ownership checks, and confirmation gates before planning backend validation.

## Good candidate workflows

- account recovery / password reset / magic link consume
- device registration / trusted device / device migration
- family/child/guardian invite and location sharing
- team/org/tenant invite and role assignment
- KYC / identity verification / document upload
- checkout / payment / refund / wallet transfer
- coupon / points / gift-card / subscription activation
- booking / ticket / trip modification
- password vault item sharing / emergency access
- IoT device bind/share/transfer-owner/command
- moderation/report/block/unblock/private media

## Extraction steps

1. Identify endpoint family and request DTOs from `api_map.jsonl`.
2. Find ViewModel/Presenter/UseCase/Repository methods that call the endpoints.
3. Order calls by UI state, coroutine chain, Rx chain, callback chain, or navigation route.
4. Record confirmation gates: unlock, OTP, biometric, KYC, user click, modal text, server challenge.
5. Record client-controlled object IDs and role/status fields at each step.
6. Record server-provided tokens/challenges and whether later steps bind to them.
7. Identify side-effecting endpoints that appear callable from code without earlier steps.

## Grep

```bash
rg -n \
  -e 'start|initiate|request|verify|confirm|approve|accept|complete|finalize|activate|claim|redeem|recover|reset|bind|pair|transfer|cancel|refund' \
  -e 'viewModelScope\.launch|lifecycleScope\.launch|LaunchedEffect|flatMap|switchMap|andThen|enqueue|suspend fun' \
  -e 'Otp|OTP|mfa|MFA|biometric|BiometricPrompt|challenge|nonce|token|verificationCode' \
  -e 'userId|accountId|tenantId|orgId|familyId|deviceId|inviteId|paymentId|orderId|subscriptionId' \
  -e 'status|state|role|verified|approved|completed|pending|expired' \
  "$SRC" > findings/<pkg>/rg-workflows.txt
```

## Output template

```text
workflow: <name>
entrypoints:
  - deep link / screen / notification / API method
steps:
  1. <method> -> <endpoint> fields=[...]
  2. <method> -> <endpoint> fields=[...]
  3. <method> -> <endpoint> fields=[...]
client_controlled_fields:
  - ...
server_tokens_or_challenges:
  - ...
confirmation_gates:
  - ...
possible_bypass:
  - complete endpoint appears callable with client-supplied deviceId and recoveryToken
impact_if_backend_accepts:
  - ...
validation_plan:
  - tier2/tier3 steps, starting with non-destructive negative checks
```

## Common mistakes

- Do not equate a callable API client method with exploitability. Many methods are protected server-side.
- Do not ignore confirmation UI. A user click/modal can be a meaningful gate.
- Do not ignore server-issued challenge binding. If later steps require a server challenge bound to account/device, the hypothesis may be hardening-only.
- Do not probe destructive production flows without explicit scope.
