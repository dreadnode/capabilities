# APK-to-backend API vulnerability paths

Use this when the likely impact is not contained inside the APK. Many high-value Android apps are thin clients for rich API backends whose real authorization, workflow, object lifecycle, payment, identity, and moderation logic is only discoverable by starting from the APK. The APK gives you routes, auth mechanics, request signing, feature flags, protobuf schemas, GraphQL documents, WebSocket events, and hidden endpoint families that a normal web crawl will not reach.

Default posture: static discovery and local reconstruction first. Only send requests to live backends with explicit authorization and the right validation tier. Treat production API probing, account-to-account tests, payment actions, invite abuse, and tenant boundary checks as `tier2_test_account_or_qa_backend` or `tier3_explicit_production_authorization`.

## What makes an APK valuable as a backend map

Prioritize apps where the APK suggests a complex backend that is hard to enumerate from the public web UI:

- many API base URLs, versioned paths, or endpoint constants (`/v1/`, `/api/`, `/graphql`, `/rpc`, `/gateway`, `/mobile/`)
- generated clients: Retrofit, Apollo GraphQL, gRPC/protobuf, OpenAPI, Swagger, Moshi/Gson DTO forests, Kotlin serialization, Room-to-network sync layers
- request signing or anti-abuse layers: HMAC, nonce, timestamp, canonical request, device attestation, certificate pinning, encrypted bodies, custom headers
- rich object models: account, user, tenant, org, family, child, vault, device, payment, order, booking, ride, ticket, chat, room, group, invite, membership, subscription
- workflow verbs: create, accept, approve, transfer, redeem, claim, activate, enroll, recover, reset, verify, bind, pair, link, migrate, escalate, impersonate, delegate
- realtime/event transports: WebSocket, MQTT, SSE, SignalR, Socket.IO, Firebase RTDB/Firestore, push-driven command handlers
- web content bridged to API actions: in-app browser, WebView JS bridge, deep link to WebView, web checkout, OAuth, support/chat widgets

## Bug classes to hunt from APK-derived API maps

### 1. BOLA / IDOR in mobile-only object APIs

Shape:

```text
APK DTO / endpoint reveals object ID parameter
  -> object belongs to account/tenant/family/vault/chat/order/payment/device
  -> client passes ID in path/query/body/header
  -> app gates UI locally or derives allowed IDs locally
  -> backend authorization for substituted ID is unknown or missing
```

High-value sinks:

- `/users/{id}`, `/accounts/{accountId}`, `/tenants/{tenantId}`, `/orgs/{orgId}`
- `/families/{familyId}/children/{childId}`
- `/vaults/{vaultId}/items/{itemId}`
- `/orders/{orderId}`, `/trips/{tripId}`, `/tickets/{ticketId}`
- `/rooms/{roomId}`, `/messages/{messageId}`, `/attachments/{attachmentId}`
- `/devices/{deviceId}`, `/sessions/{sessionId}`, `/subscriptions/{subscriptionId}`

Evidence standard: static endpoint + object model + auth context is a hypothesis. Claiming BOLA needs authorized dynamic validation with two test accounts/tenants or explicit backend evidence.

### 2. Server-side workflow confusion / state machine bypass

Shape:

```text
APK exposes multi-step flow
  -> client tracks step/state/role locally or in request fields
  -> API has verbs like approve/accept/complete/activate/recover/transfer
  -> hidden or out-of-order request may skip confirmation, KYC, payment, 2FA, invite ownership, or admin approval
```

Hunt examples:

- call `complete` without `start` / `verify`
- accept invite with a different account than the intended recipient
- approve device pairing after only local unlock
- redeem/claim/activate with reused or cross-account token
- change email/phone/payment instrument before verification completes
- replay an old signed request if nonce/timestamp is weak

### 3. Mobile API mass assignment / client-trusted fields

Shape:

```text
DTO contains fields the UI never exposes or marks read-only
  -> request serializer sends whole object or mutable map
  -> fields look privilege-bearing: role, isAdmin, premium, verified, ownerId, tenantId, price, discount, status, scope
  -> backend may accept client-supplied field
```

Static signals:

- request classes with both user-controlled and server-controlled fields
- `copy(...)`, `toMap()`, `HashMap`, `JSONObject.put`, `@SerializedName`, `@JsonClass`, Kotlin data classes sent wholesale
- fields named `role`, `admin`, `owner`, `verified`, `status`, `state`, `plan`, `price`, `amount`, `discount`, `scope`, `permissions`, `entitlements`

### 4. SSRF / open redirect / URL fetch through backend APIs

Shape:

```text
APK passes URL/domain/callback/image/avatar/webhook/preview/import parameter
  -> backend fetches, previews, redirects, imports, or stores the remote resource
  -> URL validation is unknown or weak in client
```

High-value endpoints:

- link preview / unfurl / OpenGraph fetch
- avatar/profile import by URL
- file import from URL / cloud sync
- webhook callback / redirect URL / return URL
- OAuth `redirect_uri`, SSO metadata, support/chat upload
- QR/barcode scanned URL submitted to backend

Static evidence is a lead. Backend SSRF/open redirect claims require authorized dynamic validation and safe canary endpoints.

### 5. GraphQL / gRPC / protobuf hidden operations

Shape:

```text
APK ships query documents, operation names, persisted query hashes, proto descriptors, or generated stubs
  -> operations reveal mobile-only admin/support/payment/device flows
  -> object IDs and role/state fields map to BOLA, mass assignment, or workflow bypass probes
```

Search for:

- GraphQL: `.graphql`, `ApolloClient`, `operationName`, `query`, `mutation`, `persistedQuery`, `sha256Hash`, `__typename`
- gRPC/protobuf: `.proto`, `MethodDescriptor`, `io.grpc`, `GeneratedMessageLite`, `parseFrom`, `toByteArray`, `service`, `rpc`
- custom RPC: `/rpc/`, `/gateway/`, `method`, `params`, `jsonrpc`, `procedure`

Do not assume introspection is enabled. The APK itself is the schema fragment.

### 6. WebView-to-backend bridge paths

Shape:

```text
WebView/deep link loads web content
  -> JS bridge or URL handler calls native API client with mobile auth/session/device context
  -> web-origin controls method/args or route params
  -> backend action executes as mobile user/device
```

This is the APK-to-web-vuln crossover: a web bug becomes higher impact because the web content can reach mobile-only native API methods, auth headers, device identifiers, or signed request helpers.

## Grep profile: backend API map

Run this after first-party source narrowing. For React Native / Flutter / hybrid apps, run equivalent searches over JS bundle strings / Hermes strings / Dart `pp.txt` too.

```bash
rg -n \
  -e 'https?://|/api/|/v[0-9]+/|/graphql|/grpc|/rpc|/gateway|/mobile|/internal' \
  -e 'Retrofit|OkHttpClient|Request\.Builder|HttpUrl|Volley|Ktor|ktor|ApolloClient|GraphQL|operationName|persistedQuery' \
  -e 'io\.grpc|ManagedChannel|MethodDescriptor|GeneratedMessageLite|parseFrom|toByteArray|protobuf|proto3' \
  -e 'WebSocket|Socket\.IO|SignalR|EventSource|SSE|MQTT|FirebaseFirestore|FirebaseDatabase' \
  -e 'Authorization|Bearer|X-Api-Key|apiKey|x-device|deviceId|installationId|sessionId|refreshToken' \
  -e 'Hmac|Mac\.getInstance|SHA256|signature|signRequest|nonce|timestamp|canonical|attestation|SafetyNet|PlayIntegrity' \
  -e 'tenantId|orgId|accountId|userId|ownerId|familyId|childId|vaultId|deviceId|orderId|paymentId|roomId|messageId' \
  -e 'role|isAdmin|verified|entitlement|premium|subscription|scope|permissions|status|state|price|amount|discount' \
  -e 'accept|approve|complete|activate|claim|redeem|recover|reset|verify|bind|pair|link|migrate|transfer' \
  -e 'callback|redirect_uri|returnUrl|webhook|avatarUrl|imageUrl|preview|unfurl|importUrl|sourceUrl' \
  "$SRC" > findings/<pkg>/rg-api-backend.txt
```

## Extraction checklist

1. **Base URLs and environments** — prod/stage/dev hosts, API gateways, regional domains, CDN hosts, WebView origins.
2. **Auth material and headers** — bearer token source, refresh flow, device/session IDs, tenant/account headers, request-signature inputs. Do not extract real user secrets from production accounts.
3. **Endpoint inventory** — method, path, operation name, request DTO, response DTO, required auth state, feature flag.
4. **Object graph** — IDs and ownership boundaries: user/account/org/family/device/vault/order/chat/payment.
5. **Workflow graph** — allowed step order from app code; side-effecting verbs; confirmation/2FA/KYC gates.
6. **Client-only controls** — local booleans, feature flags, read-only DTO fields, disabled UI buttons, client-side amount/price/status calculations.
7. **Backend probe plan** — what must be tested with test accounts, what can be checked offline, and which actions are destructive.

## Hypothesis wording

Use `needs_backend_validation` unless the backend was tested under scope. A strong static hypothesis should say:

```text
APK reveals endpoint /v2/families/{familyId}/children/{childId}/location and DTO ChildLocationRequest(childId, familyId, deviceId). The UI obtains childId from the locally cached family list, but the request builder accepts arbitrary IDs and no server-side authorization evidence is available in static code. Hypothesis: possible BOLA across family/child IDs. Validation requires two authorized test family accounts and read-only location endpoint checks.
```

Do **not** write:

```text
The API is vulnerable to IDOR.
```

unless dynamic validation proves cross-account access.

## Suggested class names

- `apk_discovered_backend_bola`
- `apk_discovered_backend_workflow_bypass`
- `apk_discovered_backend_mass_assignment`
- `apk_discovered_backend_ssrf_or_open_redirect`
- `apk_discovered_graphql_operation_abuse`
- `apk_discovered_grpc_operation_abuse`
- `webview_bridge_to_mobile_api_action`
- `mobile_request_signing_replay_or_confusion`
