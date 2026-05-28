# Per-impact-class focused-rg profiles

Use these as the starting `rg` pattern set after JADX decompile. They extend, not replace, the universal source/sink set in `android-semantic-vuln-hunting`. The point is to spend the first minute reading the lines a given app *class* is most likely to ship a bug in, rather than the universal set that's right for every app.

Each profile assumes you have:

```bash
SRC=findings/<pkg>/jadx/sources/<first-party-root>
```

and want one file of hits per APK.

## A_ingress — QR / barcode / docscan / NFC

The bug pattern: scanned data is rendered or executed without origin/sanity checks. Look for:

- decoder output flowing into `Uri.parse` → `loadUrl`, `startActivity`, `Intent.parseUri`
- vCard / WiFi-config / contact / calendar URI parsing
- ML Kit / ZXing result callbacks pasted into the deep-link dispatcher
- camera-side intent filters that re-fire intents based on scanned content

```bash
rg -n \
  -e 'decodeQrCode|parseQrPayload|decodeBarcode|onBarcodeDetected|onQrCodeDetected' \
  -e 'BarcodeFormat|BarcodeReader|MultiFormatReader|Result\.getText\(' \
  -e 'ZXing|com\.google\.mlkit\.vision\.barcode|BarcodeAnalyzer' \
  -e 'Uri\.parse\([^)]*(?:result|barcode|qr|payload|scanned)' \
  -e 'WifiConfig|MeCard|vCard|VCard|geo:|tel:|mailto:|sms:' \
  -e 'Intent\(.*Uri\.parse\(' -e 'startActivity\(.*Uri\.parse\(' \
  -e 'loadUrl\([^)]*(?:result|scanned|payload)' \
  -e 'getExtras\(\).get\(.*(?:result|payload|qr|barcode)' \
  -e 'onActivityResult.*(?:RequestCode.*QR|Scan|Barcode)' \
  "$SRC" > findings/<pkg>/rg-class-A.txt
```

## B_remote — TeamViewer / AnyDesk / AirDroid / RDP

The bug pattern: pairing or session establishment trusts a token / code / URI from an attacker-influenced channel. Also exported services that handle pairing requests. Backend angle: remote-control/session APIs often expose device IDs, partner IDs, pairing workflows, relay endpoints, and websocket commands that need cross-account and replay review.

```bash
rg -n \
  -e 'AccessibilityService|onAccessibilityEvent|performGlobalAction' \
  -e 'MediaProjection|VirtualDisplay|ScreenCapture|createScreenCaptureIntent' \
  -e 'pairingCode|partnerId|sessionToken|sessionId|connectionId|deviceId|accountId|tenantId' \
  -e 'startSession|joinSession|acceptInvite|inviteCode|approve|complete|bind|pair|link' \
  -e 'Retrofit|OkHttpClient|WebSocket|Socket|MQTT|grpc|protobuf|Authorization|Bearer|signature|nonce|timestamp' \
  -e 'getQueryParameter\(.*(?:code|token|session|partner|invite|pairing)' \
  -e 'startActivity\(.*FLAG_ACTIVITY_NEW_TASK' \
  -e 'addJavascriptInterface|loadUrl' \
  -e 'Permission\.SYSTEM_ALERT_WINDOW|TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT' \
  -e 'Settings\.canDrawOverlays|requestPermission.*overlay' \
  "$SRC" > findings/<pkg>/rg-class-B.txt
```

## C_wallet — crypto wallets, exchanges, DEX

The bug pattern: dapp link → transaction signing without explicit per-call origin/contract gating; WalletConnect session hijack; weak chain/RPC validation; in-app browser WebView with JS bridge that exposes wallet state. Backend angle: exchange/wallet APIs often expose order, quote, KYC, device, subscription, webhook/callback, and request-signing mechanics that are difficult to map without the APK.

```bash
rg -n \
  -e 'wc:|walletconnect|WalletConnect|WCSession|WCClient|RelayClient' \
  -e 'reown\.|Reown|com\.reown\.|dispatchEnvelope' \
  -e 'signTransaction|signMessage|signTypedData|personal_sign|eth_send|eth_sign' \
  -e 'sendTransaction|sendRawTransaction|broadcastTransaction' \
  -e 'getActiveSession|approveSession|rejectSession' \
  -e 'dappUrl|originUrl|requestUrl|metadata\.url|peerMetadata' \
  -e 'Web3|Web3Modal|RPC|provider\.send' \
  -e 'mnemonic|seed_phrase|seedPhrase|privateKey|keystore' \
  -e 'BiometricPrompt|FingerprintManager|KeyguardManager' \
  -e 'addJavascriptInterface|setJavaScriptEnabled' \
  -e 'QuestBrowser|DappBrowser|InAppBrowser|WebViewActivity' \
  -e 'shareData|getCurrentAppState|updateFingerprint' \
  -e 'Adjust\.processDeeplink|AdjustDeeplink|Branch\.initSession|RNBranchModule' \
  -e 'flutter_webview_plugin|MethodChannel.*[Ww]eb' \
  -e 'getQueryParameter\(.*(?:address|amount|chain|callback|tx)' \
  -e 'orderId|quoteId|paymentId|accountId|userId|kyc|tier|limit|price|amount|fee|discount' \
  -e 'Hmac|Mac\.getInstance|signature|nonce|timestamp|canonical|attestation|PlayIntegrity' \
  -e 'Retrofit|OkHttpClient|ApolloClient|GraphQL|/graphql|/api/|/v[0-9]+/|WebSocket' \
  "$SRC" > findings/<pkg>/rg-class-C.txt
```

Pattern recurrence across C_wallet targets (MetaMask, Trust Wallet, SafePal): every one hit on `addJavascriptInterface` + `WalletConnect`/`Reown` + one of {`RNBranchModule`, `Adjust.processDeeplink`, `flutter_webview_plugin`}. **The third-party deep-link consumer (Branch/Adjust) is consistently called *before* the app's own host allowlist runs** — worth a dedicated read on every C_wallet APK.

## D_secret — password managers, 2FA, authenticators

The bug pattern: autofill or accessibility service trusts the foreground app id without strict matching; clipboard exposure; URI handler dumps secrets into the wrong window. Backend angle: vault/password-manager APIs expose device registration, recovery, sharing, family/team membership, and item IDs that are prime BOLA/workflow-bypass candidates once mapped from the APK.

```bash
rg -n \
  -e 'AutofillService|onFillRequest|FillResponse|AutofillId|AssistStructure' \
  -e 'AccessibilityService|onAccessibilityEvent|AccessibilityNodeInfo' \
  -e 'getInstalledApplications|getPackagesForUid|getApplicationInfo' \
  -e 'getRunningAppProcesses|getRunningTasks|UsageStatsManager' \
  -e 'ClipboardManager|setPrimaryClip|getPrimaryClip' \
  -e 'BiometricPrompt|BiometricManager|KeyGenParameterSpec' \
  -e 'KeyStore|MasterKey|EncryptedSharedPreferences|Cipher\.getInstance' \
  -e 'addJavascriptInterface|JavaScriptInterface|@JavascriptInterface' \
  -e 'getQueryParameter\(.*(?:totp|otp|secret|seed|token|code)' \
  -e 'Authenticator|TOTP|HOTP|generateOTP' \
  -e 'vaultId|itemId|secretId|familyId|orgId|teamId|deviceId|recovery|shareId|inviteId' \
  -e 'accept|approve|complete|activate|recover|reset|verify|bind|pair|migrate|transfer' \
  -e 'Retrofit|OkHttpClient|ApolloClient|GraphQL|/graphql|/api/|/v[0-9]+/|Hmac|signature|nonce' \
  "$SRC" > findings/<pkg>/rg-class-D.txt
```

## E_file_cloud — file managers, cloud sync

The bug pattern: ContentProvider exports a too-broad `<paths>`, FileProvider grants flow into wrong intents, share-target accepts arbitrary `content://` URIs and re-broadcasts them with grants. Recent historical signal adds **Dirty Stream**: import/share targets trust attacker-controlled provider filenames (`OpenableColumns.DISPLAY_NAME`, `EXTRA_TITLE`) and overwrite app-private files.

```bash
rg -n \
  -e 'ContentProvider|getContentResolver|openInputStream|openOutputStream|openFileDescriptor' \
  -e 'FileProvider|getUriForFile|FLAG_GRANT_READ_URI_PERMISSION|FLAG_GRANT_WRITE_URI_PERMISSION' \
  -e 'grantUriPermission|revokeUriPermission|takePersistableUriPermission' \
  -e 'ACTION_SEND|ACTION_SEND_MULTIPLE|ACTION_GET_CONTENT|ACTION_OPEN_DOCUMENT|EXTRA_STREAM|EXTRA_TEXT|EXTRA_TITLE|ClipData' \
  -e 'OpenableColumns\.DISPLAY_NAME|MediaStore\.MediaColumns\.DISPLAY_NAME|getColumnIndex.*display|DocumentsContract|DocumentFile\.fromSingleUri' \
  -e 'FileOutputStream|Files\.copy|copyTo|writeBytes|openFileOutput|new File\(' \
  -e 'getCacheDir|getFilesDir|cacheDir|filesDir|StorageVolume|Environment\.getExternalStorage' \
  -e 'canonicalPath|getCanonicalPath|normalize|createTempFile|sanitize|replace\("\.\."' \
  -e 'rawQuery|execSQL|SQLiteQueryBuilder|selection|projection|sortOrder|setStrict|setProjectionMap' \
  -e 'webdav|WebDAV|nextcloud|owncloud' \
  -e 'getQueryParameter\(.*(?:path|file|url|src|download)' \
  -e 'startActivity\(.*VIEW.*Uri' \
  -e '"\.\./|"\.\.\\\\\\\\' \
  "$SRC" > findings/<pkg>/rg-class-E.txt
```

## F_family — parental control, location tracking

The bug pattern: exported services accept pairing codes that bind the device to a remote account; location streams have no origin check; admin commands can be triggered via deep link.

```bash
rg -n \
  -e 'DeviceAdminReceiver|DevicePolicyManager|onPasswordChanged|onPasswordExpiring' \
  -e 'FusedLocationProvider|LocationManager|requestLocationUpdates' \
  -e 'AccessibilityService|onAccessibilityEvent' \
  -e 'pairingCode|invitationCode|familyCode|joinCode' \
  -e 'getQueryParameter\(.*(?:code|invite|family|child|parent|pair)' \
  -e 'AdminPin|adminPin|PARENT_PIN|parentPin' \
  -e 'Geofence|addGeofences|GeofencingClient' \
  -e 'BackgroundService|JobScheduler|WorkManager.*Periodic' \
  -e 'sendTextMessage|SmsManager' \
  "$SRC" > findings/<pkg>/rg-class-F.txt
```

## G_messenger

The bug pattern: rich-link preview fetcher follows attacker-controlled URLs without scope; chat-protocol deep links populate auth context; file-attach view chain leaks grants; share/import handlers trust attachment filenames or nested intents. Backend angle: messaging APIs expose room/message/attachment/member IDs, invite workflows, link preview fetchers, and realtime event methods that map directly to BOLA/SSRF/workflow probes.

```bash
rg -n \
  -e 'LinkPreview|OpenGraph|ogImage|ogDescription|fetchPreview' \
  -e 'addJavascriptInterface|setJavaScriptEnabled|shouldOverrideUrlLoading' \
  -e 'CookieManager|setCookie' \
  -e 'invitationLink|inviteLink|joinLink|tg:|sgnl:|threema:|line:|wickr:' \
  -e 'StickerProvider|stickers\.android' \
  -e 'getParcelableExtra\(.*EXTRA_STREAM|EXTRA_INTENT|Intent\.parseUri' \
  -e 'ACTION_SEND|ACTION_SEND_MULTIPLE|EXTRA_STREAM|EXTRA_TITLE|ClipData|OpenableColumns\.DISPLAY_NAME' \
  -e 'openInputStream|FileOutputStream|Files\.copy|new File\(|getCacheDir|getFilesDir' \
  -e 'startActivity\(.*Intent.*data' \
  -e 'getQueryParameter\(.*(?:invite|token|chat|user|room|server)' \
  -e 'roomId|messageId|attachmentId|memberId|userId|serverId|inviteId|groupId|channelId' \
  -e 'GraphQL|ApolloClient|/graphql|WebSocket|Socket\.IO|SignalR|EventSource|FirebaseFirestore|FirebaseDatabase' \
  -e 'preview|unfurl|OpenGraph|webhook|callback|redirect_uri|returnUrl|avatarUrl|imageUrl' \
  -e 'Notification.*setContentIntent|PendingIntent\.getActivity' \
  -e 'Linkify|spannable|URLSpan' \
  "$SRC" > findings/<pkg>/rg-class-G.txt
```

## H_email

The bug pattern: HTML body rendering with insufficient sanitization; MIME parsing tricks; attachment open chains; mailto: handlers redirected to attacker WebViews; attachment import/export trusts caller-supplied filenames.

```bash
rg -n \
  -e 'MimeMessage|MimeMultipart|MimeBodyPart|MimeUtility|MimeType' \
  -e 'WebView.*loadDataWithBaseURL|loadData|loadUrl' \
  -e 'setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface' \
  -e 'MailTo|mailto:|message/rfc822' \
  -e 'CalendarContract|Events\.CONTENT_URI' \
  -e 'X-Originating-IP|Received: from|Return-Path' \
  -e 'S/MIME|PGP|PgpKey|Mailvelope' \
  -e 'getParcelableExtra\(.*EXTRA_STREAM|EXTRA_EMAIL|Intent\.parseUri' \
  -e 'ACTION_SEND|ACTION_SEND_MULTIPLE|EXTRA_STREAM|EXTRA_TITLE|ClipData|OpenableColumns\.DISPLAY_NAME' \
  -e 'FileProvider|getUriForFile|openInputStream|FileOutputStream|Files\.copy|new File\(' \
  -e 'getQueryParameter\(.*(?:subject|body|cc|bcc|to|attach)' \
  "$SRC" > findings/<pkg>/rg-class-H.txt
```

## I_browser

The bug pattern: custom-tab intent forwarding hands out cookies/origins; URI-scheme dispatch loops; built-in settings pages with implicit JS bridges.

```bash
rg -n \
  -e 'CustomTabsIntent|CustomTabsClient|CustomTabsSession|CustomTabsCallback' \
  -e 'addJavascriptInterface|@JavascriptInterface|setJavaScriptEnabled' \
  -e 'shouldOverrideUrlLoading|WebViewClient|WebChromeClient' \
  -e 'intent://|intent:.*S\.browser_fallback_url' \
  -e 'Intent\.parseUri|parseUri' \
  -e 'getCookie|setCookie|CookieManager' \
  -e 'getQueryParameter\(.*(?:url|src|next|return|redirect)' \
  -e 'TrustedWebActivity|TWA|setNavigationBarColor' \
  -e 'about:|chrome:|file:|content:|javascript:' \
  -e 'PWA|service-worker|manifest\.webmanifest' \
  "$SRC" > findings/<pkg>/rg-class-I.txt
```

## J_iot — smart home companion apps

The bug pattern: LAN discovery + JSON-over-HTTP control with weak origin checks; OAuth-via-WebView; push tokens binding accounts to devices. Backend angle: IoT companion apps often reveal device ownership APIs, MQTT/WebSocket command channels, provisioning tokens, and cloud-to-LAN bridge methods that need tenant/device authorization review.

```bash
rg -n \
  -e 'mDNS|NsdManager|MulticastSocket|SSDP|UPnP|Bonjour' \
  -e 'WifiManager|WifiNetworkSpecifier|WifiConfiguration|connectToWifi' \
  -e 'BluetoothGatt|BluetoothLeScanner|ScanCallback|scanResult' \
  -e 'addJavascriptInterface|setJavaScriptEnabled' \
  -e 'OAuth|oauth_token|authorize|redirect_uri' \
  -e 'mqtt|Mqtt|MqttClient|MqttAndroidClient|paho\.client\.mqttv3' \
  -e 'PushToken|FCM_TOKEN|registrationToken|onTokenRefresh' \
  -e 'deviceId|deviceUuid|deviceSecret|pairingToken|provisioningToken|homeId|tenantId|accountId|ownerId' \
  -e 'getQueryParameter\(.*(?:device|token|home|account|server)' \
  -e 'command|setState|unlock|arm|disarm|invite|shareDevice|transferOwner|bind|pair|provision' \
  -e 'Retrofit|OkHttpClient|WebSocket|MQTT|FirebaseFirestore|grpc|protobuf|Hmac|signature|nonce|timestamp' \
  -e 'http://(192|10|172)\.' \
  "$SRC" > findings/<pkg>/rg-class-J.txt
```

## How to use these

```bash
# Read the per-APK class from the triage manifest
CLASS=$(jq -r --arg p "<package>" 'select(.package==$p) | .impact_class' findings/<run>/triage/manifest.jsonl)

# Then run the matching profile
case "$CLASS" in
  A_ingress)   bash scripts/run_class_rg.sh A "$SRC" findings/<pkg>/ ;;
  B_remote)    bash scripts/run_class_rg.sh B "$SRC" findings/<pkg>/ ;;
  C_wallet)    bash scripts/run_class_rg.sh C "$SRC" findings/<pkg>/ ;;
  D_secret)    bash scripts/run_class_rg.sh D "$SRC" findings/<pkg>/ ;;
  E_file_cloud) bash scripts/run_class_rg.sh E "$SRC" findings/<pkg>/ ;;
  F_family)    bash scripts/run_class_rg.sh F "$SRC" findings/<pkg>/ ;;
  G_messenger) bash scripts/run_class_rg.sh G "$SRC" findings/<pkg>/ ;;
  H_email)     bash scripts/run_class_rg.sh H "$SRC" findings/<pkg>/ ;;
  I_browser)   bash scripts/run_class_rg.sh I "$SRC" findings/<pkg>/ ;;
  J_iot)       bash scripts/run_class_rg.sh J "$SRC" findings/<pkg>/ ;;
esac
```

Or just paste the right block above into the shell. The profiles are deliberately small enough to read.

## Notes on what's missing

- These are **starting points**, not exhaustive. Add patterns as you find them in real APKs.
- Cross-class patterns (deep-link routers, JS bridges, FileProvider grants) still belong in the universal source/sink set in `android-semantic-vuln-hunting`. The per-class sets capture **what's unique to the class**, not what's common across all Android apps.
- For React Native / Capacitor / Cordova shells, complement with **Step 7.5** in `android-semantic-vuln-hunting`: pretty-print `assets/index.bundle` and grep the JS-side bridge surface.
