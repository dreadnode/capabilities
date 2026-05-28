# Backend-rich APK workflows

Use this after the normal component/deep-link triage identifies an app whose real value is the backend it exposes: finance, health, travel, IoT, enterprise, retail/loyalty, messaging, family/education, workforce, cloud files, password managers, or any app with rich generated API clients.

The APK is treated as a protocol/workflow oracle. The output should be an API/workflow map and a validation queue, not unscoped backend probing.

## Mode selection

### Mode 1 — lightweight backend richness ranking

Use before deep decompile or when ranking a corpus. Goal: identify APKs likely to contain a rich backend map.

Inputs:

- JADX source tree when available, or extracted strings/resources when not.
- Optional JS/Hermes/Dart analysis directories for hybrid apps.

Outputs:

- `api_map.jsonl` from `scripts/extract_api_map.py`
- `backend_richness.json` summary

### Mode 2 — API map extraction

Use after decompile for a target APK. Goal: inventory endpoints, clients, object IDs, workflow verbs, auth/signing, and URL-fetch surfaces.

```bash
python3 scripts/extract_api_map.py \
  --src findings/decompiled/<pkg>/sources \
  --out findings/<pkg>/api_map.jsonl \
  --summary findings/<pkg>/backend_richness.json
```

For React Native / Flutter / hybrid apps, run additional maps over JS/Dart artifacts:

```bash
python3 scripts/extract_api_map.py \
  --src findings/<pkg>/js-analysis \
  --out findings/<pkg>/api_map_js.jsonl \
  --summary findings/<pkg>/backend_richness_js.json
```

Then read top rows by category:

```bash
jq -r 'select(.category=="endpoint" or .category=="graphql" or .category=="grpc") | [.file,.line,.kind,.value] | @tsv' findings/<pkg>/api_map.jsonl | head -100
jq '.scores, .top_terms' findings/<pkg>/backend_richness.json
```

### Mode 3 — workflow/state-machine reconstruction

Use when an endpoint family includes side-effecting verbs:

- `accept`, `approve`, `complete`, `activate`, `claim`, `redeem`, `recover`, `reset`, `verify`, `bind`, `pair`, `link`, `migrate`, `transfer`, `cancel`, `refund`, `share`, `invite`

Read the API client, request DTOs, ViewModel/Presenter, and confirmation UI around those verbs. Build a sequence:

```text
workflow: device_recovery
steps:
  1. POST /recovery/start
  2. POST /recovery/verify
  3. POST /recovery/complete
client_controlled_fields:
  userId, deviceId, recoveryToken, trustedDevice
server_authorization_unknown:
  token bound to initiating account/device? final device already approved?
validation_tier:
  tier2_test_account_or_qa_backend
```

### Mode 4 — bridge-to-backend trace

Use for WebView/RN/Flutter/Capacitor/Cordova apps.

Trace:

```text
external route / WebView origin / JS message
  -> native bridge or MethodChannel
  -> API client / request signer
  -> backend side-effect
```

Risk increases when the bridge exposes:

- auth/session tokens or cookies
- device IDs / installation IDs
- request signing helpers
- payment/order/booking APIs
- file upload/import APIs
- recovery/device pairing APIs
- tenant/account switching APIs

### Mode 5 — version-diff API archaeology

Use when multiple APK versions are available.

```bash
python3 scripts/extract_api_map.py --src findings/v1/sources --out findings/v1/api_map.jsonl --summary findings/v1/backend_richness.json
python3 scripts/extract_api_map.py --src findings/v2/sources --out findings/v2/api_map.jsonl --summary findings/v2/backend_richness.json
comm -13 \
  <(jq -r '.category+"\t"+.value' findings/v1/api_map.jsonl | sort -u) \
  <(jq -r '.category+"\t"+.value' findings/v2/api_map.jsonl | sort -u)
```

Prioritize newly added:

- feature flags
- endpoint families
- workflow verbs
- request-signing code
- GraphQL operations / persisted hashes
- protobuf services / methods
- WebView bridge methods

## Backend-richness scoring intuition

High-priority APKs tend to have several of these:

- many API hosts and endpoint constants
- Retrofit/Apollo/gRPC/WebSocket/Firebase clients
- request signing or device attestation
- many DTO classes with object IDs
- tenant/account/org/family/vault/device/payment/order concepts
- workflow verbs around recovery, invite, approval, transfer, redemption, checkout, pairing
- URL-fetch or callback parameters submitted to backend
- feature flag / remote config systems
- WebView/native bridge connected to API clients
- offline sync and conflict-resolution code

## Validation boundaries

Static APK-to-backend work produces excellent hypotheses, but most backend vulnerability claims need authorized dynamic evidence.

Default labels:

- `confidence_tier=needs_backend_validation`
- `validation_tier=tier2_test_account_or_qa_backend` for two-account or QA validation
- `validation_tier=tier3_explicit_production_authorization` for production account/tenant/payment/device state changes

Safe first probes, when authorized:

- non-destructive metadata reads
- invalid-token / wrong-device negative checks
- endpoint existence checks against QA
- URL preview checks with owned canary domains
- GraphQL query shape checks on non-sensitive objects

Do not perform without explicit scope:

- payment, refund, transfer, coupon/gift-card redemption
- account recovery / device pair completion
- cross-account object access in production
- invite/ownership changes
- destructive mutations
- probing real users, tenants, devices, health records, children/family data, or private messages
