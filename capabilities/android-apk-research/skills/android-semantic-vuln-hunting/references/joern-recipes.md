# Joern recipes for Android semantic review

Joern's role in this capability is **deep context on shortlisted methods**, not corpus scanning. By the time you reach Joern you have:

- a decompiled JADX source tree
- specific files/methods from `rg`/Semgrep that look like real chains
- an exported BROWSABLE component or WebView entrypoint to anchor on

Use Joern to answer: who calls this, where does this value come from, what does this bridge expose, does this validator actually run before that sink?

Reference docs:

- Joern overview and CPG concept: https://docs.joern.io/code-property-graph/
- Quickstart and query language: https://docs.joern.io/quickstart/
- Source repository and release notes: https://github.com/joernio/joern

## Importing a JADX source tree

JADX writes Java sources under `<out>/sources/`. Joern's `javasrc2cpg` frontend handles that path directly. Memory usage scales with corpus size — for one large bank/wallet APK, 8–16 GB of heap is comfortable.

Interactive shell:

```scala
joern> importCode(inputPath = "findings/decompiled/<pkg>/sources", projectName = "<pkg>")
joern> save
```

Headless script:

```bash
cat > /tmp/import.sc <<'EOF'
@main def main(src: String, name: String) = {
  importCode(inputPath = src, projectName = name)
  save
}
EOF
joern --script /tmp/import.sc --param src=findings/decompiled/<pkg>/sources --param name=<pkg>
```

Subsequent sessions open the saved project with `open("<pkg>")` and skip the import cost.

## Recipe 1 — exported activities reading attacker input

For each Activity that the manifest exports (you already have this list from `androguard.json`), check whether its lifecycle methods read attacker-controlled input.

```scala
val exported = Seq("com.target.LoginActivity", "com.target.DeepLinkActivity")  // from androguard.json

cpg.method
  .where(_.typeDecl.fullNameExact(exported: _*))
  .name("(onCreate|onNewIntent|onStart|onResume)")
  .where(_.callee.name("getIntent|getData|getStringExtra|getParcelableExtra|getQueryParameter"))
  .map(m => (m.typeDecl.fullName.head, m.name, m.filename, m.lineNumber.getOrElse(0)))
  .l
```

For each hit, follow the value with `cpg.call.name("loadUrl|startActivity|startService").where(_.argument.code(".*intent.*"))` to find sinks.

## Recipe 2 — deep link source → WebView sink

This is the canonical chain. The Android Developers page describes the unsafe-deep-link pattern: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks.

```scala
def webviewSinks = cpg.call.name("loadUrl|postUrl|loadDataWithBaseURL")
def intentSources = cpg.call.name("getIntent|getData|getStringExtra|getQueryParameter")

webviewSinks
  .reachableByFlows(intentSources)
  .take(25)
  .map(_.elements.map(n => s"${n.method.fullName}:${n.lineNumber.getOrElse(0)}").l)
  .l
```

If `reachableByFlows` returns too many false positives on obfuscated trees, pin the entrypoint:

```scala
def entry = cpg.typeDecl.fullNameExact("com.target.DeepLinkActivity").method.l
webviewSinks
  .reachableByFlows(intentSources.where(_.method.in(entry)))
  .take(25)
  .l
```

## Recipe 3 — what does the JavaScript bridge expose?

CodeQL's unsafe-WebView-fetch query treats `addJavascriptInterface` as a high-trust boundary: https://codeql.github.com/codeql-query-help/java/java-android-unsafe-android-webview-fetch/.

```scala
// Enumerate every class registered as a JavaScript interface.
cpg.call.name("addJavascriptInterface")
  .argument
  .isCall
  .typeFullName
  .l

// For each bridge class, list its @JavascriptInterface-annotated public methods.
val bridgeTypes = Seq("com.target.bridge.NativeBridge")
cpg.typeDecl.fullNameExact(bridgeTypes: _*).method
  .where(_.annotation.name("JavascriptInterface"))
  .map(m => (m.fullName, m.parameter.l.map(_.code).mkString(", ")))
  .l
```

Bridges that expose tokens, account state, file access, intent launch, or arbitrary URL navigation are the actual finding.

## Recipe 4 — intent redirection / private component reachability

CodeQL pattern: https://codeql.github.com/codeql-query-help/java/java-android-intent-redirection/.

```scala
// Exported components forwarding a nested Intent obtained from getParcelableExtra/getSerializableExtra.
val nestedIntentSources = cpg.call.name("getParcelableExtra|getSerializableExtra|parseUri")
val componentLaunches = cpg.call.name("startActivity|startActivityForResult|startService|bindService|sendBroadcast")

componentLaunches
  .reachableByFlows(nestedIntentSources)
  .take(25)
  .l
```

Pair with `androguard.json` to confirm the containing class is `exported=true` and lacks a meaningful `permission`.

## Recipe 5 — client-side auth/session decisions

```scala
val localState = cpg.call.name("getSharedPreferences|getBoolean|getString|getInt")
val authDecisions = cpg.call.name("isLoggedIn|hasValidSession|checkAuth|canAccess|isPremium|isAdmin")

authDecisions
  .reachableByFlows(localState)
  .take(25)
  .l

// Hardcoded keys that participate in token/account logic.
cpg.literal.code("\".{32,}\"")
  .where(_.method.name(".*(token|reset|sign|verify|encrypt|decrypt|password).*"))
  .map(l => (l.method.fullName, l.lineNumber.getOrElse(0), l.code))
  .l
```

## Recipe 6 — weak deep-link host validation

```scala
// Calls to host validators on strings derived from intent data.
val hostsFromIntent = cpg.call.name("getHost|getQueryParameter").argument
val weakChecks = cpg.call.name("contains|startsWith|endsWith|matches")
weakChecks
  .where(_.argument.reachableBy(hostsFromIntent))
  .map(c => (c.method.fullName, c.lineNumber.getOrElse(0), c.code))
  .take(50)
  .l
```

Each hit is a candidate for host-confusion payloads such as `https://trusted.com.attacker.tld/` or `https://trusted.com@attacker.tld/`.

## Operational notes

- Increase Joern's heap when importing large APKs: `export JAVA_OPTS='-Xmx12g'` before launching.
- Save projects (`save`) and reopen (`open("<pkg>")`) to avoid re-paying import cost.
- Joern is the *escalation* tier. If `rg` + `androguard.json` already proves the chain, skip Joern and write the finding.
- Capture useful query output to a file with `>` redirection inside Joern (`cpg.method.l #> "out.txt"`), then attach the file path to the finding's `evidence` array.
