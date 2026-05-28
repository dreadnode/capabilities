# Historical Android APK vulnerability patterns (2023-2026)

Use this as a pattern catalogue, not as a prevalence study. The public record is biased toward vulnerabilities that received CVEs, vendor advisories, conference/blog writeups, or bug-bounty disclosure. Search terms used to build this reference also bias toward semantic APK issues that are easy to describe publicly: deep links, WebViews, intent redirection, providers, and share/import flows. Absence here does **not** mean a class is rare or low impact; it means it was less visible in the public sources sampled.

The point for corpus hunting is to copy the **shape** of repeatedly impactful findings into our ranking, grep profiles, and hypothesis taxonomy.

## Pattern index

| Pattern | Public signal | Entry/source/sink shape | Hunt bias |
|---|---|---|---|
| Deep link to authenticated WebView | Home Assistant Android `CVE-2023-41898`; Rakuten Ichiba Android `CVE-2024-41918`; bug-bounty reports against retail/travel/social apps | BROWSABLE/custom scheme receives URL-like param -> weak allowlist -> `WebView.loadUrl` with auth cookies/headers or phishing context | Search-heavy bias toward disclosed WebView bugs; still high ROI because scanners often flag only generic WebView APIs. |
| Intent redirection / private component reachability | Element Android `CVE-2024-26131` / `CVE-2024-26132`; Android Developers intent-redirection risk guidance; SDK-level wallet cases reported publicly after 2025 disclosure | Exported component accepts nested `Intent` / string `Intent.parseUri` -> launches it under victim app identity -> private component, grant, or privileged flow | Public examples overrepresent messaging/wallet apps, but the proxy pattern appears in many app classes. |
| Dirty Stream / untrusted ContentProvider filename | Microsoft Dirty Stream research in 2024; Xiaomi File Manager and WPS Office fixed; Android Developers ContentProvider filename guidance | Share/import target accepts attacker `content://` -> trusts `_display_name` / title / path -> writes under app-private storage -> overwrite config/token/code/cache | Very actionable statically; public signal is high because Microsoft/Google amplified it. Treat as first-class in file/cloud/email/messenger/office apps. |
| Provider SQL injection / overbroad exported provider | ownCloud Android `CVE-2023-24804`, `CVE-2023-23948`; older Nextcloud class remains relevant | Exported provider with no signature permission -> caller controls `selection`, `projection`, URI path, or table routing -> internal DB rows leak/modify | CVEs skew to open-source apps where provider code is reviewable; closed-source APKs still expose the same API shapes. |
| Share-target path traversal | ownCloud ReceiveExternalFilesActivity issues; Basecamp bug-bounty reports; recurring Nextcloud/Talk-style reports | `ACTION_SEND` / `EXTRA_STREAM` / `EXTRA_TEXT` / `EXTRA_TITLE` -> filename/path from caller -> `File(cacheDir, name)` / upload path / temp path -> read/write outside intended directory | Often bounty-disclosed rather than CVE-assigned; grep for it explicitly because manifest-only ranking undercounts it. |
| WebView native bridge origin confusion | TikTok-style JS interface takeover reports; Android Developers native bridge guidance updated 2024 | Attacker-controlled page/frame -> `addJavascriptInterface` / `postWebMessage` / `WebMessagePort` -> native methods expose account/token/file/SDK actions | Public examples skew toward social/super-apps; in corpora, RN/Flutter/hybrid shells need JS/Dart route-map validation before grading. |
| Deep link to account-state change without WebView | Publicly less CVE-rich but recurring in bounty writeups and internal corpus work | BROWSABLE route args -> navigation/ViewModel init/`LaunchedEffect` -> `accept` / `register` / `complete` / `recover` / `pair` API call before explicit confirmation | Easy to miss if the review stops at “opens a screen.” Requires reading destination side effects. |

## Pattern recipes

### 1. Deep link to authenticated WebView

Grounding:

- Android unsafe deep links: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks
- Android unsafe WebView URI loading: https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading
- Home Assistant Android arbitrary WebView URL: https://securitylab.github.com/advisories/GHSL-2023-142_Home_Assistant_Companion_for_Android/
- Rakuten Ichiba custom URL scheme issue: https://jvn.jp/en/jp/JVN56648919/

Grep:

```bash
rg -n \
  -e 'getIntent\(\)\.getData|getDataString|getQueryParameter' \
  -e 'url|redirect|next|returnUrl|callback|continue|target|deeplink' \
  -e 'loadUrl|postUrl|loadDataWithBaseURL' \
  -e 'setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface|postWebMessage|WebMessagePort' \
  -e 'CookieManager|Authorization|Bearer|getAuthHeaders|setCookie' \
  "$SRC"
```

Promote only when the chain has URL control, weak/missing scheme+host validation, and authenticated context or a sensitive bridge/action. URL control alone is `hardening_only` or `needs_route_map_validation`.

### 2. Intent redirection / private component reachability

Grounding:

- Android intent redirection: https://developer.android.com/privacy-and-security/risks/intent-redirection
- Element Android writeup: https://www.shielder.com/blog/2024/04/element-android-cve-2024-26131-cve-2024-26132-never-take-intents-from-strangers/

Grep:

```bash
rg -n \
  -e 'getParcelableExtra.*Intent|getSerializableExtra.*Intent|Bundle\.getParcelable|Intent\.parseUri' \
  -e 'startActivity|startService|bindService|sendBroadcast' \
  -e 'FLAG_GRANT_READ_URI_PERMISSION|FLAG_GRANT_WRITE_URI_PERMISSION|ClipData' \
  -e 'resolveActivity|IntentSanitizer|setPackage|setComponent' \
  "$SRC"
```

Promote only when an exported/no-permission component launches attacker-controlled nested intents without a strict component/package/data/flag allowlist. Distinguish “screen open” from a privileged action or grant leak.

### 3. Dirty Stream / untrusted ContentProvider filename

Grounding:

- Microsoft Dirty Stream: https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/
- Android ContentProvider filename guidance: https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename

Grep:

```bash
rg -n \
  -e 'ACTION_SEND|ACTION_SEND_MULTIPLE|EXTRA_STREAM|EXTRA_TEXT|EXTRA_TITLE|ClipData' \
  -e 'OpenableColumns\.DISPLAY_NAME|MediaStore\.MediaColumns\.DISPLAY_NAME|getColumnIndex.*display' \
  -e 'openInputStream|openFileDescriptor|ContentResolver\.query' \
  -e 'FileOutputStream|Files\.copy|copyTo|new File\(|openFileOutput|writeBytes' \
  -e 'getCacheDir|getFilesDir|cacheDir|filesDir' \
  -e 'canonicalPath|getCanonicalPath|normalize|createTempFile|sanitize' \
  "$SRC"
```

Promote only when attacker-controlled filename/title/display name reaches a private-storage write without temp-file generation, basename sanitization, and canonical path enforcement. Impact requires a trusted later read/use of the overwritten file.

### 4. Provider SQL injection / overbroad provider

Grounding:

- ownCloud Android provider issues: https://securitylab.github.com/advisories/GHSL-2022-059_GHSL-2022-060_Owncloud_Android_app/

Grep:

```bash
rg -n \
  -e 'class .*ContentProvider|extends ContentProvider' \
  -e 'query\(|insert\(|update\(|delete\(|openFile\(' \
  -e 'rawQuery|execSQL|SQLiteQueryBuilder|selection|projection|sortOrder' \
  -e 'setStrict|setProjectionMap|appendWhere|UriMatcher' \
  "$SRC"
```

Promote only when a provider is exported or reachable with grants, lacks signature permission, and caller-controlled SQL/path inputs can reach sensitive rows/files.

### 5. Deep link to account-state change without WebView

Grep:

```bash
rg -n \
  -e 'getQueryParameter\(.*(?:id|key|token|code|invite|pair|device|account)' \
  -e 'LaunchedEffect|init\s*\{|viewModelScope\.launch|lifecycleScope\.launch|onCreate' \
  -e 'accept|complete|register|recover|pair|join|claim|activate|verify|transfer' \
  -e 'Retrofit|OkHttp|enqueue|suspend fun|execute\(' \
  "$SRC"
```

Promote only when the route fires a server/account-state mutation before explicit user confirmation and backend authorization is absent or needs validation.

## Capability implications

- Component ranking should boost exported share/import targets in addition to BROWSABLE routes.
- `E_file_cloud`, `G_messenger`, `H_email`, and office/retail classes should get Dirty Stream/path-traversal search terms by default.
- Report taxonomy should distinguish `dirty_stream_file_overwrite`, `share_target_path_traversal`, `exported_provider_sqli`, `intent_redirection_uri_grant_leak`, and `deep_link_to_js_bridge` instead of flattening everything into “WebView” or “provider exposure.”
- Because the source set is public-writeup biased, corpus reports should state whether a pattern was selected due to historical signal or due to local corpus frequency.
