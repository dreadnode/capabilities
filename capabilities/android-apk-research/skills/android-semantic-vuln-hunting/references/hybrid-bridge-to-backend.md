# Hybrid bridge to backend tracing

Use for React Native, Flutter, Capacitor, Cordova, and WebView-heavy apps where external web/JS/Dart input may reach native API clients. This is the main APK -> web -> backend crossover path.

## Trace shape

```text
external input
  -> deep link / WebView URL / postMessage / JS route / Dart route
  -> native bridge / MethodChannel / EventChannel / Cordova plugin / Capacitor plugin
  -> API client / request signer / token store
  -> backend side effect
```

## Bridge inventory

Java/Kotlin:

```bash
rg -n \
  -e 'addJavascriptInterface|@JavascriptInterface|postWebMessage|WebMessagePort|onPostMessage' \
  -e 'MethodChannel|EventChannel|BasicMessageChannel|setMethodCallHandler|invokeMethod' \
  -e 'PluginMethod|CapacitorPlugin|CordovaPlugin|execute\(' \
  -e 'ReactContextBaseJavaModule|@ReactMethod|NativeModule|RCTDeviceEventEmitter' \
  "$SRC" > findings/<pkg>/rg-bridges.txt
```

JS/Hermes strings:

```bash
rg -nN \
  -e 'postMessage|addEventListener|Linking|NativeModules|TurboModuleRegistry|bridge|invoke|emit' \
  -e 'fetch\(|axios|graphql|mutation|query|WebSocket|socket\.emit' \
  -e 'token|Authorization|deviceId|sessionId|accountId|tenantId' \
  "$JSDIR" > findings/<pkg>/rg-js-bridge-backend.txt
```

Dart/Flutter strings:

```bash
rg -nN \
  -e 'MethodChannel|EventChannel|invokeMethod|setMethodCallHandler' \
  -e 'http\.|Dio\(|GraphQLClient|WebSocketChannel|FirebaseFirestore' \
  -e 'token|Authorization|deviceId|sessionId|accountId|tenantId' \
  findings/<pkg>/dart-analysis/pp.txt > findings/<pkg>/rg-dart-bridge-backend.txt
```

## High-risk bridge methods

- token/session access: `getToken`, `refreshToken`, `getCookies`, `setCookie`
- signed requests: `sign`, `signedFetch`, `request`, `apiCall`, `hmac`
- account state: `acceptInvite`, `completeRecovery`, `verifyDevice`, `switchAccount`
- payments/orders: `checkout`, `pay`, `refund`, `redeem`, `applyCoupon`
- file APIs: `upload`, `import`, `share`, `openFile`, `download`
- device/IoT: `pair`, `bind`, `unlock`, `command`, `provision`

## Promote when

- web/JS/Dart-controlled data reaches a native method that performs an authenticated/signed API call, and
- origin/route/argument validation is absent, partial, or performed before an attacker-controllable redirect/frame/message boundary, and
- the backend action has account, payment, device, file, tenant, or privacy impact.

Most findings are `webview_bridge_to_mobile_api_action` or `deep_link_to_js_bridge` and require route-map plus backend validation.
