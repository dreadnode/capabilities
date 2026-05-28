#!/usr/bin/env bash
# Run the focused-rg profile for one impact class against a JADX source tree.
# Patterns mirror references/android-semantic-vuln-hunting/impact-class-rg-profiles.md.
#
# Usage:
#   run_class_rg.sh A_ingress  /path/to/jadx/sources/<pkg>  /path/to/out_dir
#
# Writes:
#   <out_dir>/rg-class-<short>.txt   one line per hit
#   <out_dir>/rg-class-<short>.summary.txt   per-file hit counts, descending
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <class> <src_dir> <out_dir>" >&2
  echo "  <class> = A_ingress|B_remote|C_wallet|D_secret|E_file_cloud|F_family|G_messenger|H_email|I_browser|J_iot" >&2
  exit 64
fi
CLASS="$1"
SRC="$2"
OUT="$3"
mkdir -p "$OUT"

declare -a PATTERNS=()

case "$CLASS" in
  A_ingress|A)
    SHORT=A
    PATTERNS+=(
      'decodeQrCode|parseQrPayload|decodeBarcode|onBarcodeDetected|onQrCodeDetected'
      'BarcodeFormat|BarcodeReader|MultiFormatReader|Result\.getText\('
      'ZXing|com\.google\.mlkit\.vision\.barcode|BarcodeAnalyzer'
      'Uri\.parse\([^)]*(result|barcode|qr|payload|scanned)'
      'WifiConfig|MeCard|vCard|VCard|geo:|tel:|mailto:|sms:'
      'Intent\(.*Uri\.parse\(|startActivity\(.*Uri\.parse\('
      'loadUrl\([^)]*(result|scanned|payload)'
      'onActivityResult.*(RequestCode.*QR|Scan|Barcode)'
    )
    ;;
  B_remote|B)
    SHORT=B
    PATTERNS+=(
      'AccessibilityService|onAccessibilityEvent|performGlobalAction'
      'MediaProjection|VirtualDisplay|ScreenCapture|createScreenCaptureIntent'
      'pairingCode|partnerId|sessionToken|sessionId|connectionId'
      'startSession|joinSession|acceptInvite|inviteCode'
      'getQueryParameter\(.*(code|token|session|partner|invite|pairing)'
      'addJavascriptInterface|loadUrl'
      'TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|SYSTEM_ALERT_WINDOW'
      'Settings\.canDrawOverlays|requestPermission.*overlay'
    )
    ;;
  C_wallet|C)
    SHORT=C
    PATTERNS+=(
      'wc:|walletconnect|WalletConnect|WCSession|WCClient|RelayClient'
      'signTransaction|signMessage|signTypedData|personal_sign|eth_send|eth_sign'
      'sendTransaction|sendRawTransaction|broadcastTransaction'
      'getActiveSession|approveSession|rejectSession'
      'dappUrl|originUrl|requestUrl|metadata\.url|peerMetadata'
      'Web3|Web3Modal|RPC|provider\.send'
      'mnemonic|seed_phrase|seedPhrase|privateKey|keystore'
      'BiometricPrompt|FingerprintManager|KeyguardManager'
      'addJavascriptInterface|setJavaScriptEnabled'
      'getQueryParameter\(.*(address|amount|chain|callback|tx)'
    )
    ;;
  D_secret|D)
    SHORT=D
    PATTERNS+=(
      'AutofillService|onFillRequest|FillResponse|AutofillId|AssistStructure'
      'AccessibilityService|onAccessibilityEvent|AccessibilityNodeInfo'
      'getInstalledApplications|getPackagesForUid|getApplicationInfo'
      'getRunningAppProcesses|getRunningTasks|UsageStatsManager'
      'ClipboardManager|setPrimaryClip|getPrimaryClip'
      'BiometricPrompt|BiometricManager|KeyGenParameterSpec'
      'KeyStore|MasterKey|EncryptedSharedPreferences|Cipher\.getInstance'
      'addJavascriptInterface|@JavascriptInterface'
      'getQueryParameter\(.*(totp|otp|secret|seed|token|code)'
      'TOTP|HOTP|generateOTP'
    )
    ;;
  E_file_cloud|E)
    SHORT=E
    PATTERNS+=(
      'ContentProvider|getContentResolver|openInputStream|openOutputStream'
      'FileProvider|getUriForFile|FLAG_GRANT_READ_URI_PERMISSION|FLAG_GRANT_WRITE_URI_PERMISSION'
      'grantUriPermission|revokeUriPermission'
      'ACTION_SEND|ACTION_SEND_MULTIPLE|EXTRA_STREAM|EXTRA_TEXT'
      'OpenableColumns|MediaStore|DocumentsContract'
      'StorageVolume|Environment\.getExternalStorage'
      'webdav|WebDAV|nextcloud|owncloud'
      'getQueryParameter\(.*(path|file|url|src|download)'
      'startActivity\(.*VIEW.*Uri'
    )
    ;;
  F_family|F)
    SHORT=F
    PATTERNS+=(
      'DeviceAdminReceiver|DevicePolicyManager|onPasswordChanged'
      'FusedLocationProvider|LocationManager|requestLocationUpdates'
      'AccessibilityService|onAccessibilityEvent'
      'pairingCode|invitationCode|familyCode|joinCode'
      'getQueryParameter\(.*(code|invite|family|child|parent|pair)'
      'AdminPin|adminPin|PARENT_PIN|parentPin'
      'Geofence|addGeofences|GeofencingClient'
      'BackgroundService|JobScheduler|WorkManager.*Periodic'
      'sendTextMessage|SmsManager'
    )
    ;;
  G_messenger|G)
    SHORT=G
    PATTERNS+=(
      'LinkPreview|OpenGraph|ogImage|ogDescription|fetchPreview'
      'addJavascriptInterface|setJavaScriptEnabled|shouldOverrideUrlLoading'
      'CookieManager|setCookie'
      'invitationLink|inviteLink|joinLink|tg:|sgnl:|threema:|line:|wickr:'
      'getParcelableExtra\(.*(EXTRA_STREAM|EXTRA_INTENT)'
      'startActivity\(.*Intent.*data'
      'getQueryParameter\(.*(invite|token|chat|user|room|server)'
      'Notification.*setContentIntent|PendingIntent\.getActivity'
      'Linkify|spannable|URLSpan'
    )
    ;;
  H_email|H)
    SHORT=H
    PATTERNS+=(
      'MimeMessage|MimeMultipart|MimeBodyPart|MimeUtility|MimeType'
      'WebView.*loadDataWithBaseURL|loadData|loadUrl'
      'setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface'
      'MailTo|mailto:|message/rfc822'
      'CalendarContract|Events\.CONTENT_URI'
      'X-Originating-IP|Received: from|Return-Path'
      'S/MIME|PGP|PgpKey|Mailvelope'
      'getParcelableExtra\(.*(EXTRA_STREAM|EXTRA_EMAIL)'
      'FileProvider|getUriForFile'
      'getQueryParameter\(.*(subject|body|cc|bcc|to|attach)'
    )
    ;;
  I_browser|I)
    SHORT=I
    PATTERNS+=(
      'CustomTabsIntent|CustomTabsClient|CustomTabsSession|CustomTabsCallback'
      'addJavascriptInterface|@JavascriptInterface|setJavaScriptEnabled'
      'shouldOverrideUrlLoading|WebViewClient|WebChromeClient'
      'intent://|intent:.*S\.browser_fallback_url'
      'Intent\.parseUri|parseUri'
      'getCookie|setCookie|CookieManager'
      'getQueryParameter\(.*(url|src|next|return|redirect)'
      'TrustedWebActivity|TWA|setNavigationBarColor'
      'about:|chrome:|content:|javascript:'
      'PWA|service-worker|manifest\.webmanifest'
    )
    ;;
  J_iot|J)
    SHORT=J
    PATTERNS+=(
      'mDNS|NsdManager|MulticastSocket|SSDP|UPnP|Bonjour'
      'WifiManager|WifiNetworkSpecifier|WifiConfiguration|connectToWifi'
      'BluetoothGatt|BluetoothLeScanner|ScanCallback'
      'addJavascriptInterface|setJavaScriptEnabled'
      'OAuth|oauth_token|authorize|redirect_uri'
      'mqtt|Mqtt|MqttClient|MqttAndroidClient'
      'PushToken|FCM_TOKEN|registrationToken|onTokenRefresh'
      'deviceId|deviceUuid|deviceSecret|pairingToken|provisioningToken'
      'getQueryParameter\(.*(device|token|home|account|server)'
      'http://(192|10|172)\.'
    )
    ;;
  *)
    echo "unknown class: $CLASS" >&2
    exit 64
    ;;
esac

OUT_FILE="$OUT/rg-class-$SHORT.txt"
SUMMARY="$OUT/rg-class-$SHORT.summary.txt"

# Build the rg invocation: -n line numbers, -P PCRE2, multiple -e patterns
ARGS=( -n -P )
for pat in "${PATTERNS[@]}"; do
  ARGS+=( -e "$pat" )
done
ARGS+=( "$SRC" )

rg "${ARGS[@]}" > "$OUT_FILE" 2>/dev/null || true

# Summary: file -> hit count, descending. Helps prioritise files to read.
awk -F: '{print $1}' "$OUT_FILE" | sort | uniq -c | sort -rn > "$SUMMARY"

HITS=$(wc -l < "$OUT_FILE" | tr -d ' ')
FILES=$(wc -l < "$SUMMARY" | tr -d ' ')
echo "class=$CLASS short=$SHORT hits=$HITS files=$FILES out=$OUT_FILE summary=$SUMMARY"
